"""
Agente híbrido Bronze -> Silver.

Fluxo (por log):
  1. Parser determinístico preenche o que sabe   -> 0 tokens
  2. Se houver lacunas / EventID desconhecido / Message não parseada,
     chama o Groq para completar SÓ as colunas faltantes
  3. Valida (DQ). Se falhar regra crítica, re-consulta o Groq com o erro
     como dica — loop limitado a MAX_LLM_CALLS (padrão 3) chamadas no total.
O determinístico sempre vence sobre o LLM em campos que ele já resolveu
(evita o LLM "reescrever" e quebrar a apresentação).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import validate
from .cache import MappingCache, derive_mapping
from .groq_client import GroqParser, LLMResult, estimate_tokens
from .parser import CoverageReport, deterministic_parse, load_raw

MAX_LLM_CALLS = 3  # teto de loop de busca solicitado

# colunas Silver de tipo inteiro — o LLM às vezes devolve string; coagimos aqui
_INT_COLS = {
    "record_number", "event_id", "collector_port", "source_port",
    "destination_port", "source_thread_id", "target_thread_id", "new_thread_id",
    "logon_type", "message_number", "message_total", "process_id",
    "target_process_id", "parent_process_id", "raw_process_id",
    "raw_parent_process_id",
}


def _coerce(col: str, val):
    if col in _INT_COLS and not isinstance(val, int):
        try:
            s = str(val).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None
    return val


@dataclass
class AgentResult:
    silver: dict
    coverage: CoverageReport
    used_llm: bool = False
    llm_calls: int = 0
    total_tokens: int = 0
    cache_hit: bool = False
    dq_failed: list[str] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)


def _merge_llm(silver: dict, llm_data: dict) -> list[str]:
    """Aplica valores do LLM só onde o determinístico deixou vazio."""
    filled = []
    for col, val in llm_data.items():
        if val in (None, "", "-"):
            continue
        if silver.get(col) in (None, "", "-"):
            coerced = _coerce(col, val)
            if coerced is None:
                continue
            silver[col] = coerced
            filled.append(col)
    return filled


def _llm_slice(raw: str, report: CoverageReport) -> dict:
    """Monta o input mínimo para o LLM: envelope + Message + chaves não mapeadas."""
    rec, _ = load_raw(raw)
    keep = {
        "EventID": rec.get("EventID"),
        "Channel": rec.get("Channel"),
        "Hostname": rec.get("Hostname"),
        "Message": rec.get("Message"),
    }
    keep.update(report.unmapped_keys)  # o que o determinístico não soube mapear
    return {k: v for k, v in keep.items() if v not in (None, "")}


def _unmapped_values(raw: str, report: CoverageReport) -> dict:
    """Valores brutos COMPLETOS das chaves não-mapeadas (não truncados)."""
    rec, _ = load_raw(raw)
    return {k: rec.get(k) for k in report.unmapped_keys}


def _apply_mapping(silver: dict, unmapped_values: dict, mapping: dict) -> list[str]:
    """Aplica um plano de mapeamento cacheado aos valores DESTE log (0 tokens)."""
    filled = []
    for src_key, col in mapping.items():
        val = unmapped_values.get(src_key)
        if val in (None, "", "-") or silver.get(col) not in (None, "", "-"):
            continue
        coerced = _coerce(col, val)
        if coerced is None:
            continue
        silver[col] = coerced
        filled.append(col)
    return filled


def parse_log(raw: str,
              source_file: str | None = None,
              use_llm: bool = True,
              force_llm: bool = False,
              groq: GroqParser | None = None,
              max_llm_calls: int = MAX_LLM_CALLS,
              dry_run: bool = False,
              cache: MappingCache | None = None) -> AgentResult:
    silver, report = deterministic_parse(raw, source_file=source_file)
    res = AgentResult(silver=silver, coverage=report)
    res.trace.append(
        f"determinístico: log_source={report.log_source} "
        f"event_id={report.event_id} "
        f"lacunas={report.missing_critical or '—'} "
        f"não-mapeadas={list(report.unmapped_keys) or '—'}")

    want_llm = use_llm and (force_llm or report.needs_llm)
    if not want_llm:
        res.trace.append("LLM não acionado (determinístico completo).")
        _finalize(res)
        return res

    if dry_run:
        rec_slice = _llm_slice(raw, report)
        from .groq_client import SYSTEM_PROMPT, build_user_prompt, clamp_input
        est_in = estimate_tokens(SYSTEM_PROMPT) + estimate_tokens(
            build_user_prompt(clamp_input(rec_slice)))
        res.trace.append(f"[dry-run] input estimado ≈ {est_in} tokens "
                         f"(sem output; máx {max_llm_calls} chamadas).")
        _finalize(res)
        return res

    # ---- Cache de mapeamento (tenta evitar o LLM) --------------------------
    shape = None
    if cache is not None:
        shape = MappingCache.shape_key(
            report.event_id, report.log_source, report.unmapped_keys)
        entry = cache.get(shape)
        if entry and entry.get("kind") == "map":
            unmapped_values = _unmapped_values(raw, report)
            filled = _apply_mapping(silver, unmapped_values, entry["map"])
            cache.bump(shape)
            res.cache_hit = True
            res.trace.append(
                f"cache HIT shape='{shape}' +{len(filled)} campos "
                f"(0 tokens) {filled or ''}")
            failed = validate.validate(silver)
            if not any(r in validate.CRITICAL_RULES for r in failed):
                _finalize(res)
                return res
            res.trace.append("cache hit não resolveu críticos → fallback LLM")
        elif entry and entry.get("kind") == "llm_always":
            res.trace.append(f"cache: shape '{shape}' marcado llm_always")

    # ---- LLM (com loop de auto-correção, teto de max_llm_calls) ------------
    groq = groq or GroqParser()
    hint = ""
    last_ok: LLMResult | None = None
    last_filled: list[str] = []
    for attempt in range(1, max_llm_calls + 1):
        rec_slice = _llm_slice(raw, report)
        out: LLMResult = groq.parse(rec_slice, hint=hint)
        res.used_llm = True
        res.llm_calls = attempt
        res.total_tokens += out.total_tokens
        if out.error:
            res.trace.append(f"LLM chamada {attempt}: ERRO {out.error}")
            break
        last_ok = out
        filled = _merge_llm(silver, out.data)
        last_filled = filled
        res.trace.append(
            f"LLM chamada {attempt}: +{len(filled)} campos "
            f"({out.total_tokens} tok) {filled or ''}")
        failed = validate.validate(silver)
        if not any(r in validate.CRITICAL_RULES for r in failed):
            break
        hint = "corrija estas colunas críticas ausentes/ inválidas: " + \
               ", ".join(r for r in failed if r in validate.CRITICAL_RULES)

    # ---- Aprende o plano para este shape (grava no cache) -----------------
    # Deriva o mapeamento SÓ sobre as colunas que o LLM contribuiu de fato
    # (ignora ecos de colunas que o determinístico já tinha preenchido).
    if cache is not None and shape is not None and last_ok is not None \
            and not cache.get(shape):
        contributed = {c: last_ok.data.get(c) for c in last_filled}
        mapping = derive_mapping(_unmapped_values(raw, report), contributed)
        if mapping is None:
            cache.put_llm_always(shape)
            res.trace.append(f"cache: shape '{shape}' -> llm_always (não rastreável)")
        else:
            cache.put_map(shape, mapping)
            res.trace.append(f"cache: shape '{shape}' aprendido map={mapping or '{}'}")
        cache.save()

    _finalize(res)
    return res


def _finalize(res: AgentResult):
    failed = validate.validate(res.silver)
    validate.apply_dq_status(res.silver, failed)
    res.dq_failed = failed
