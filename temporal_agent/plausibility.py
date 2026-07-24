"""
Camada de plausibilidade via Groq (token-limitada).

O SQL determinístico monta as cadeias candidatas a 0 tokens; aqui o LLM só JULGA se
uma cadeia é uma trilha de ataque coordenada plausível e rotula as táticas ATT&CK
prováveis. Input compacto (uma linha por passo, nº de passos limitado), `max_tokens`
de saída travado — mesmos princípios de economia do agente 1.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

DEFAULT_MODEL = "llama-3.3-70b-versatile"
DEFAULT_MAX_OUTPUT_TOKENS = 500
MAX_STEPS_PER_CHAIN = 30          # teto de passos enviados (limita input)
MAX_ARTIFACT_CHARS = 80

SYSTEM_PROMPT = (
    "Você é um analista de SOC. Recebe uma SEQUÊNCIA de eventos de telemetria Windows "
    "já ordenada no tempo (uma linha por passo: HH:MM:SS host/usuario categoria imagem | "
    "artefato). Julgue se a sequência é uma TRILHA DE ATAQUE coordenada e plausível ou "
    "atividade benigna do sistema.\n"
    "Responda APENAS um objeto JSON com as chaves:\n"
    '  "verdict": "attack" | "suspicious" | "benign",\n'
    '  "plausibility": número 0.0-1.0 (confiança de que é uma trilha de ataque real),\n'
    '  "likely_tactics": lista curta de táticas MITRE ATT&CK (ex.: "Execution", '
    '"Command and Control", "Persistence", "Defense Evasion", "Discovery", '
    '"Lateral Movement", "Collection", "Exfiltration"),\n'
    '  "rationale": uma frase curta explicando o veredito.\n'
    "Não invente eventos que não estão na lista. Considere sinais como: binário com nome "
    "mascarado, execução seguida de conexão a IP externo (C2), spawn de cmd/powershell, "
    "persistência em registro, uso de utilitários de sistema (certutil, net, psexec)."
)


def estimate_tokens(text: str) -> int:
    return (len(text) + 3) // 4


@dataclass
class ChainVerdict:
    verdict: str = "unknown"
    plausibility: float = 0.0
    likely_tactics: list = None
    rationale: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    error: str | None = None

    def __post_init__(self):
        if self.likely_tactics is None:
            self.likely_tactics = []


def render_chain(chain, max_steps: int = MAX_STEPS_PER_CHAIN) -> str:
    """Renderiza a cadeia em texto compacto p/ o LLM (limita passos e tamanho)."""
    steps = chain.steps
    head_tail = steps
    truncated = False
    if len(steps) > max_steps:
        # mantém o começo e o fim (onde a narrativa de ataque costuma estar)
        head = steps[: max_steps * 2 // 3]
        tail = steps[-(max_steps // 3):]
        head_tail = head + tail
        truncated = True
    lines = []
    for st in head_tail:
        art = (st.artifact or "")[:MAX_ARTIFACT_CHARS]
        img = f" {st.image_name}" if st.image_name else ""
        lines.append(f"{st.time} {st.host}/{st.actor or '-'} {st.category}{img}"
                     + (f" | {art}" if art else ""))
    body = "\n".join(lines)
    if truncated:
        body += f"\n…[{len(steps) - len(head_tail)} passos intermediários omitidos]"
    return body


class GroqPlausibility:
    def __init__(self, model: str = DEFAULT_MODEL,
                 max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
                 api_key: str | None = None):
        self.model = model
        self.max_output_tokens = max_output_tokens
        self._api_key = api_key or os.environ.get("GROQ_API_KEY")
        self._client = None

    def _ensure(self):
        if self._client is not None:
            return
        if not self._api_key:
            raise RuntimeError("GROQ_API_KEY ausente (defina no .env ou no ambiente).")
        try:
            from groq import Groq
        except ImportError as e:
            raise RuntimeError("Lib 'groq' não instalada. Rode: pip install groq") from e
        self._client = Groq(api_key=self._api_key)

    def score(self, chain) -> ChainVerdict:
        self._ensure()
        user = (f"Entidade: {chain.entity} | passos: {len(chain.steps)} | "
                f"cross-dia: {chain.cross_day}\n{render_chain(chain)}")
        try:
            resp = self._client.chat.completions.create(
                model=self.model, temperature=0,
                max_tokens=self.max_output_tokens,
                response_format={"type": "json_object"},
                messages=[{"role": "system", "content": SYSTEM_PROMPT},
                          {"role": "user", "content": user}],
            )
        except Exception as e:  # noqa: BLE001
            return ChainVerdict(error=f"{type(e).__name__}: {e}")

        text = resp.choices[0].message.content or "{}"
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            data = {}
        u = resp.usage
        return ChainVerdict(
            verdict=str(data.get("verdict", "unknown")),
            plausibility=float(data.get("plausibility", 0.0) or 0.0),
            likely_tactics=data.get("likely_tactics", []) or [],
            rationale=str(data.get("rationale", "")),
            prompt_tokens=getattr(u, "prompt_tokens", 0),
            completion_tokens=getattr(u, "completion_tokens", 0),
            total_tokens=getattr(u, "total_tokens", 0),
        )

    def dry_run(self, chain) -> int:
        user = render_chain(chain)
        return estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(user)
