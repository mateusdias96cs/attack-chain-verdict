"""
Cliente Groq com controle de tokens.

- Input mínimo: só o que o parser determinístico NÃO resolveu (Message +
  chaves não mapeadas + envelope), nunca a linha JSON inteira.
- Prompt de sistema compacto e reaproveitável.
- `max_tokens` de saída travado (teto por chamada).
- Guarda de orçamento: trunca campos gigantes (CallTrace, ScriptBlockText)
  antes de enviar, preservando o valor completo no registro Silver final.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import schema

DEFAULT_MODEL = "llama-3.3-70b-versatile"
DEFAULT_MAX_OUTPUT_TOKENS = 900
# teto de caracteres de input enviado ao LLM (~ input_token_budget * 4)
DEFAULT_INPUT_CHAR_BUDGET = 6000

SYSTEM_PROMPT = (
    "Você é um parser de logs do Windows (Sysmon/Security/PowerShell/WFP) que "
    "converte um evento bruto em UMA linha da camada Silver.\n"
    "Responda APENAS com um objeto JSON válido: chave = nome exato da coluna "
    "Silver, valor = valor extraído. NÃO invente valores; se não houver dado "
    "para uma coluna, OMITA a coluna. Preserve exatamente a escrita original "
    "(caminhos com \\\\, GUIDs com {}, hex com 0x). Regras de normalização:\n"
    "- process_id/target_process_id/parent_process_id: inteiro decimal.\n"
    "- raw_process_id: inteiro (converta hex 0x.. para decimal); "
    "raw_process_id_original = texto original.\n"
    "- Hashes 'SHA1=..,MD5=..,SHA256=..' -> hash_sha1/hash_md5/hash_sha256/hash_imphash.\n"
    "- network_protocol minúsculo 'tcp'/'udp' (6->tcp, 17->udp).\n"
    "- booleanos 'true'/'false' -> true/false.\n"
    "- timestamps no formato 'YYYY-MM-DD HH:MM:SS.mmm'.\n"
    "Colunas Silver válidas:\n" + ", ".join(schema.SILVER_COLUMNS)
)


@dataclass
class LLMResult:
    data: dict
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    raw_text: str = ""
    error: str | None = None


def estimate_tokens(text: str) -> int:
    """Estimativa barata (~4 chars/token) para checar orçamento sem tokenizer."""
    return (len(text) + 3) // 4


def build_user_prompt(rec_slice: dict, hint: str = "") -> str:
    body = json.dumps(rec_slice, ensure_ascii=False, indent=1)
    prefix = f"Correção necessária: {hint}\n" if hint else ""
    return f"{prefix}Evento bruto (campos ainda não resolvidos):\n{body}"


def clamp_input(rec_slice: dict, budget: int = DEFAULT_INPUT_CHAR_BUDGET) -> dict:
    """Trunca valores enormes para caber no orçamento de input (só p/ o LLM)."""
    out = {}
    for k, v in rec_slice.items():
        s = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
        if len(s) > 1500:
            s = s[:1500] + "…[truncado]"
        out[k] = s
    # se ainda estourar, corta o Message que costuma dominar
    while estimate_tokens(json.dumps(out, ensure_ascii=False)) * 4 > budget and "Message" in out:
        out["Message"] = out["Message"][: max(200, len(out["Message"]) // 2)] + "…[truncado]"
        if len(out["Message"]) <= 260:
            break
    return out


class GroqParser:
    def __init__(self, model: str = DEFAULT_MODEL,
                 max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS,
                 api_key: str | None = None):
        self.model = model
        self.max_output_tokens = max_output_tokens
        self._api_key = api_key or os.environ.get("GROQ_API_KEY")
        self._client = None

    def _ensure_client(self):
        if self._client is not None:
            return
        if not self._api_key:
            raise RuntimeError("GROQ_API_KEY ausente (defina no .env ou no ambiente).")
        try:
            from groq import Groq
        except ImportError as e:
            raise RuntimeError(
                "Lib 'groq' não instalada. Rode: pip install groq") from e
        self._client = Groq(api_key=self._api_key)

    def parse(self, rec_slice: dict, hint: str = "") -> LLMResult:
        self._ensure_client()
        user = build_user_prompt(clamp_input(rec_slice), hint)
        try:
            resp = self._client.chat.completions.create(
                model=self.model,
                temperature=0,
                max_tokens=self.max_output_tokens,
                response_format={"type": "json_object"},
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
            )
        except Exception as e:  # noqa: BLE001 — reporta erro sem derrubar o CLI
            return LLMResult(data={}, error=f"{type(e).__name__}: {e}")

        text = resp.choices[0].message.content or "{}"
        try:
            data = json.loads(text)
            if not isinstance(data, dict):
                data = {}
        except json.JSONDecodeError:
            data = {}
        u = resp.usage
        return LLMResult(
            data={k: v for k, v in data.items() if k in schema.SILVER_COLUMNS},
            prompt_tokens=getattr(u, "prompt_tokens", 0),
            completion_tokens=getattr(u, "completion_tokens", 0),
            total_tokens=getattr(u, "total_tokens", 0),
            raw_text=text,
        )
