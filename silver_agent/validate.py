"""Validação DQ do registro Silver (subconjunto crítico das regras §4.1).

Usada pelo loop de auto-correção do agente: se um registro falha uma regra
crítica, o agente re-consulta o Groq (até o teto de 3 chamadas).
"""
from __future__ import annotations

import re

from . import schema

_GUID_RE = re.compile(r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$")
_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def validate(silver: dict) -> list[str]:
    """Retorna lista de regras violadas (vazia = passou). Nomes espelham §4.1."""
    failed: list[str] = []

    if silver.get("event_id") is None:               # #1 crítico
        failed.append("event_id_not_null")
    if not silver.get("hostname_nk"):                # #3 crítico
        failed.append("hostname_not_null")
    if silver.get("record_number") is None:          # #5 crítico
        failed.append("record_number_not_null")
    if not silver.get("event_utc_time"):             # #7 crítico
        failed.append("event_utc_time_resolved")

    ch = silver.get("channel")                       # #9 warning
    if ch and ch not in schema.KNOWN_CHANNELS:
        failed.append("channel_in_known_set")

    if silver.get("unmapped_json"):                  # zero-perda: aviso, nunca descarte
        failed.append("unmapped_fields_present")

    pg = silver.get("process_guid")                  # #10 warning
    if pg and not _GUID_RE.match(str(pg)):
        failed.append("process_guid_format")

    for col, length in schema.HASH_LENGTHS.items():  # #14 info
        v = silver.get(col)
        if v and (len(str(v)) != length or not re.fullmatch(r"[0-9a-fA-F]+", str(v))):
            failed.append("hash_fields_well_formed")
            break

    for col in ("source_port", "destination_port"):  # #15 warning
        v = silver.get(col)
        if isinstance(v, int) and not (0 <= v <= 65535):
            failed.append("network_port_range")
            break

    return failed


CRITICAL_RULES = {
    "event_id_not_null", "hostname_not_null",
    "record_number_not_null", "event_utc_time_resolved",
}


def apply_dq_status(silver: dict, failed: list[str]) -> dict:
    """Grava dq_status / dq_failed_rules no registro (não descarta linhas)."""
    if any(r in CRITICAL_RULES for r in failed):
        silver["dq_status"] = "quarantined"
    elif failed:
        silver["dq_status"] = "passed_with_warnings"
    else:
        silver["dq_status"] = "passed"
    silver["dq_failed_rules"] = ",".join(failed) if failed else None
    return silver
