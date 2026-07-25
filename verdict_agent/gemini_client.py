"""
Cliente Gemini do Agente 4 — arbitragem estruturada da técnica por evento.

Diferente dos agentes 1/2 (Groq/Llama) e do agente 3 (retrieval local e5), o
veredito final usa **Gemini** (google-genai). O Gemini recebe a cadeia inteira de
uma vez — com os candidatos ATT&CK que o RAG recuperou para CADA evento — e devolve,
numa única chamada, um `ChainVerdictReport` já validado via `response_schema` Pydantic.

Princípios herdados do pipeline:
  - Saída ESTRUTURADA (Pydantic) → nada de parsing frágil de texto livre.
  - GROUNDING: a técnica atribuída tem de ser um dos candidatos do RAG (ou "NONE").
    O Gemini DECIDE entre candidatos usando o contexto temporal; não inventa T-IDs.
  - temperatura 0 → veredito determinístico e factual.
  - system prompt em inglês (evita "vazamento" de idioma), mas a `rationale`/resumo
    são pedidos explicitamente em português.
"""
from __future__ import annotations

import os
import time
from pathlib import Path

from .schema import ChainVerdictReport

# Retry de sobrecarga TRANSITÓRIA do servidor Gemini (503 UNAVAILABLE / "high demand",
# 429 rate-limit momentâneo, 500). NÃO mascara erro persistente: re-lança após esgotar.
_TRANSIENT_STATUS = {429, 500, 503}
_MAX_TRIES = 6
_BASE_BACKOFF = 4.0  # s; cresce exponencialmente (4, 8, 16, 32, 64)

DEFAULT_MODEL = "gemini-flash-latest"

SYSTEM_PROMPT = (
    "You are a senior SOC analyst producing a FINAL, structured verdict for an "
    "already time-ordered chain of Windows telemetry events (MITRE ATT&CK / APT29 "
    "adversary-emulation context).\n"
    "For EACH event you receive its description plus a short list of CANDIDATE ATT&CK "
    "techniques that a retrieval system proposed. Your job is to DECIDE, per event, "
    "which single candidate technique truly applies given the whole-chain narrative, "
    "and how confident you are.\n"
    "HARD RULES:\n"
    "  1. The assigned attack_id MUST be one of the candidate ids given for that event, "
    "     OR the literal string \"NONE\" if no candidate genuinely applies. Never invent "
    "     a technique id that was not offered.\n"
    "  2. Use the temporal context of the surrounding events to disambiguate (e.g. a "
    "     masqueraded binary executing, then connecting to an external IP, is C2 / "
    "     defense evasion — not benign).\n"
    "  3. confidence (0.0-1.0) and confidence_level must agree: high>=0.75, "
    "     medium 0.4-0.75, low<0.4, none=0.0 with attack_id \"NONE\".\n"
    "  4. Keep every 'rationale' to ONE short sentence, written in Brazilian "
    "     Portuguese. Write 'attack_summary' in Brazilian Portuguese too.\n"
    "  5. Return exactly one EventVerdict per input event, in the same order."
)


def load_env_file(start: Path | None = None) -> None:
    """Carrega o .env da raiz do projeto (sobe até encontrar), sem sobrescrever."""
    here = (start or Path(__file__)).resolve()
    for parent in [here, *here.parents]:
        env = parent / ".env"
        if env.exists():
            for line in env.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))
            return


class GeminiVerdict:
    """Carrega o cliente Gemini uma vez; reusa em cada judge()."""

    def __init__(self, model: str = DEFAULT_MODEL, api_key: str | None = None):
        self.model = model
        load_env_file()
        # GEMINI_API_KEY é a chave documentada no .env.example deste projeto.
        self._api_key = (api_key or os.environ.get("GEMINI_API_KEY")
                         or os.environ.get("GOOGLE_API_KEY"))
        self._client = None
        self.last_usage: dict = {}

    def _ensure(self):
        if self._client is not None:
            return
        if not self._api_key:
            raise RuntimeError(
                "GEMINI_API_KEY ausente (defina no .env da raiz ou no ambiente). "
                "Gere em https://aistudio.google.com/app/apikey")
        try:
            from google import genai
        except ImportError as e:  # pragma: no cover
            raise RuntimeError(
                "SDK ausente. Rode: .venv/bin/pip install google-genai") from e
        self._client = genai.Client(api_key=self._api_key)

    def judge(self, user_prompt: str) -> ChainVerdictReport:
        """Envia o prompt (cadeia + candidatos) e devolve o veredito estruturado."""
        self._ensure()
        from google.genai import types
        from google.genai import errors as genai_errors

        cfg = types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            temperature=0.0,
            response_mime_type="application/json",
            response_schema=ChainVerdictReport,
        )
        resp = None
        for attempt in range(1, _MAX_TRIES + 1):
            try:
                resp = self._client.models.generate_content(
                    model=self.model, contents=user_prompt, config=cfg)
                break
            except genai_errors.ServerError as e:  # 5xx / sobrecarga transitória
                code = getattr(e, "code", None) or getattr(e, "status_code", None)
                if code not in _TRANSIENT_STATUS or attempt == _MAX_TRIES:
                    raise
                wait = _BASE_BACKOFF * (2 ** (attempt - 1))
                print(f"    ⚠️  Gemini {code} transitório (tentativa {attempt}/{_MAX_TRIES}); "
                      f"aguardando {wait:.0f}s…", flush=True)
                time.sleep(wait)
            except genai_errors.ClientError as e:  # 4xx: 429 pode ser rate-limit momentâneo
                code = getattr(e, "code", None) or getattr(e, "status_code", None)
                if code not in _TRANSIENT_STATUS or attempt == _MAX_TRIES:
                    raise
                wait = _BASE_BACKOFF * (2 ** (attempt - 1))
                print(f"    ⚠️  Gemini {code} transitório (tentativa {attempt}/{_MAX_TRIES}); "
                      f"aguardando {wait:.0f}s…", flush=True)
                time.sleep(wait)
        u = getattr(resp, "usage_metadata", None)
        if u is not None:
            self.last_usage = {
                "prompt_tokens": getattr(u, "prompt_token_count", 0) or 0,
                "output_tokens": getattr(u, "candidates_token_count", 0) or 0,
                "total_tokens": getattr(u, "total_token_count", 0) or 0,
            }
        report = resp.parsed
        if not isinstance(report, ChainVerdictReport):
            # fallback: valida o JSON cru se o SDK não devolveu o objeto tipado
            report = ChainVerdictReport.model_validate_json(resp.text)
        return report
