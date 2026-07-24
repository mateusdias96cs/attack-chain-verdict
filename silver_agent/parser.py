"""
Parser determinístico Bronze -> Silver (0 tokens).

Recebe um log bruto do Windows (linha NDJSON completa OU só o bloco Message de
texto) e preenche o máximo de colunas Silver possível aplicando as regras de
docs/medallion/medallion_architecture.md §5. O que não conseguir resolver é
reportado em `CoverageReport` para o agente Groq completar.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from . import schema

# Offset descoberto empiricamente neste dataset (UTC-4) — ver §5.2. Usado só
# como fallback quando UtcTime/@timestamp estão ausentes (não hardcode cego).
_CALIBRATED_OFFSET = timedelta(hours=4)
_TRUE = {"true", "1", "yes"}
_HASH_KEYS = {"SHA1": "hash_sha1", "MD5": "hash_md5",
              "SHA256": "hash_sha256", "IMPHASH": "hash_imphash"}


@dataclass
class CoverageReport:
    event_id: int | None
    log_source: str
    unknown_event_id: bool
    message_parsed: bool
    missing_critical: list[str] = field(default_factory=list)
    # chaves presentes no log bruto que o parser não mapeou p/ nenhuma coluna
    unmapped_keys: dict[str, str] = field(default_factory=dict)

    @property
    def needs_llm(self) -> bool:
        return bool(self.unknown_event_id or not self.message_parsed
                    or self.missing_critical or self.unmapped_keys)


# ---------------------------------------------------------------------------
# Parsing do bloco Message ("Process accessed:\r\nRuleName: -\r\nUtcTime: ...")
# ---------------------------------------------------------------------------
def parse_message_block(message: str) -> dict[str, str]:
    """Divide o bloco `Chave: Valor` do Message. Split no PRIMEIRO ': ' apenas,
    para não quebrar valores com ':' (caminhos C:\\, timestamps 02:55:23)."""
    out: dict[str, str] = {}
    if not message:
        return out
    for raw in message.replace("\r\n", "\n").split("\n"):
        line = raw.rstrip()
        # campos reais são "Chave: valor"; a 1ª linha é a descrição do evento
        # (ex.: "Process accessed:") e não tem ": " — é ignorada de propósito.
        if ": " not in line:
            continue
        key, val = line.split(": ", 1)
        key = key.strip()
        # nome de campo é uma única palavra alfanumérica (ProcessId, TargetImage…)
        if re.match(r"^[A-Za-z][A-Za-z0-9_]*$", key):
            out.setdefault(key, val)
    return out


# ---------------------------------------------------------------------------
# Normalizadores
# ---------------------------------------------------------------------------
def _to_int(v):
    if v in (None, "", "-"):
        return None
    try:
        s = str(v).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def _to_bool(v):
    if v in (None, ""):
        return None
    return str(v).strip().lower() in _TRUE


def _norm_protocol(v):
    if v in (None, ""):
        return None
    m = {"6": "tcp", "17": "udp", "tcp": "tcp", "udp": "udp"}
    return m.get(str(v).strip().lower(), str(v).strip().lower())


def _norm_direction(initiated, direction):
    if initiated not in (None, ""):
        return "outbound" if str(initiated).lower() in _TRUE else "inbound"
    if direction not in (None, ""):
        # WFP usa %%14592 (inbound) / %%14593 (outbound) — ref_windows_message_code
        d = str(direction)
        if "14593" in d:
            return "outbound"
        if "14592" in d:
            return "inbound"
    return None


def _parse_hashes(raw):
    """'SHA1=..,MD5=..,SHA256=..,IMPHASH=..' -> dict de colunas hash_*."""
    out = {}
    if not raw:
        return out
    for part in str(raw).split(","):
        if "=" in part:
            algo, val = part.split("=", 1)
            col = _HASH_KEYS.get(algo.strip().upper())
            if col:
                out[col] = val.strip()
    return out


def _parse_ts(v):
    """Aceita 'YYYY-MM-DD HH:MM:SS(.fff)' e ISO8601 Z. Retorna datetime UTC-aware
    quando possível, senão None."""
    if not v:
        return None
    s = str(v).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


def _reconcile_time(rec: dict, log_source: str):
    """event_utc_time canônico + time_source_flag + offset aplicado (§5.2)."""
    # UtcTime só é emitido por eventos Sysmon e é sempre UTC — se está presente,
    # é a fonte canônica (independe de já termos classificado o log_source, o que
    # importa para entradas de Message cru sem o envelope JSON).
    utc = rec.get("UtcTime")
    if utc:
        dt = _parse_ts(utc)
        if dt:
            return dt, "utc_time_native", 0
    # fallback UTC confiável: @timestamp (Logstash, já em UTC Z)
    at = _parse_ts(rec.get("@timestamp"))
    if at:
        return at, "utc_time_native", 0
    # último recurso: EventTime local + offset calibrado do dataset
    et = _parse_ts(rec.get("EventTime"))
    if et:
        return et + _CALIBRATED_OFFSET, "event_time_calibrated", int(_CALIBRATED_OFFSET.total_seconds())
    return None, "unresolved", None


# ---------------------------------------------------------------------------
# Entrada: aceita linha JSON completa OU só o texto do Message
# ---------------------------------------------------------------------------
def load_raw(raw: str) -> tuple[dict, bool]:
    """Retorna (dict_de_campos, message_parsed). Se a entrada for JSON, mescla
    top-level + Message parseado (top-level tem prioridade). Se for só texto
    Message, parseia o bloco."""
    raw = raw.strip()
    rec: dict = {}
    msg_parsed = True
    if raw.startswith("{"):
        try:
            rec = json.loads(raw)
        except json.JSONDecodeError:
            rec = {}
    if rec:
        block = parse_message_block(rec.get("Message", "") or "")
        # entrada JSON já traz estrutura nos campos top-level; o Message é bônus.
        # Só sinalizamos "não parseado" para entradas de texto Message cru (abaixo).
        msg_parsed = True
        for k, v in block.items():          # completa top-level sem sobrescrever
            rec.setdefault(k, v)
    else:  # entrada é o Message cru
        rec = parse_message_block(raw)
        msg_parsed = bool(rec)
        rec.setdefault("Message", raw)
    return rec, msg_parsed


def _coalesce(rec: dict, keys: list[str]):
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", "-"):
            return v
    return None


# Todas as chaves brutas que o parser consome (p/ calcular unmapped_keys)
_CONSUMED = set().union(*schema.COALESCE_MAP.values()) | {
    "EventID", "UtcTime", "EventTime", "@timestamp", "EventReceivedTime",
    "CreationUtcTime", "Message", "ProcessId", "SourceProcessId",
    "TargetProcessId", "ParentProcessId", "NewProcessId", "Hashes",
    "SourcePort", "DestinationPort", "DestPort", "IpPort", "IpAddress",
    "Protocol", "Initiated",
    "Direction", "SourceIsIpv6", "DestinationIsIpv6", "IsExecutable",
    "Archived", "LogonType", "SourceThreadId", "TargetThreadId", "NewThreadId",
    "EventType", "MessageNumber", "MessageTotal", "ParentProcessName",
    # ruído de envelope Logstash/NXLog irrelevante p/ Silver
    "@version", "tags", "SourceModuleName", "SourceModuleType", "SourceName",
    "ThreadID", "ProcessID", "ExecutionProcessID", "ProviderGuid", "Task",
    "Keywords", "SeverityValue", "Version", "OpcodeValue", "EventType",
    "Domain", "AccountType", "Category", "SubjectLogonId",
}


def deterministic_parse(raw: str, source_file: str | None = None) -> tuple[dict, CoverageReport]:
    rec, msg_parsed = load_raw(raw)
    silver: dict = {c: None for c in schema.SILVER_COLUMNS}

    event_id = _to_int(rec.get("EventID"))
    channel = rec.get("Channel")
    log_source = schema.derive_log_source(event_id, channel)

    silver["source_file"] = source_file
    silver["event_id"] = event_id
    silver["log_source"] = log_source
    silver["channel"] = channel

    # coalesce direto
    for col, keys in schema.COALESCE_MAP.items():
        silver[col] = _coalesce(rec, keys)

    # hostname curto
    if silver["hostname_fqdn"]:
        silver["hostname_nk"] = str(silver["hostname_fqdn"]).split(".")[0].upper()

    # record_number / ports / threads / logon_type como int
    silver["record_number"] = _to_int(silver["record_number"])
    silver["collector_port"] = _to_int(silver["collector_port"])
    silver["source_port"] = _to_int(_coalesce(rec, ["SourcePort"]))
    silver["source_port"] = silver["source_port"] or _to_int(rec.get("IpPort"))
    silver["destination_port"] = _to_int(_coalesce(rec, ["DestinationPort", "DestPort"]))
    silver["source_thread_id"] = _to_int(rec.get("SourceThreadId"))
    silver["target_thread_id"] = _to_int(rec.get("TargetThreadId"))
    silver["new_thread_id"] = _to_int(rec.get("NewThreadId"))
    silver["logon_type"] = _to_int(rec.get("LogonType"))
    silver["message_number"] = _to_int(rec.get("MessageNumber"))
    silver["message_total"] = _to_int(rec.get("MessageTotal"))

    # PIDs — Sysmon decimal (process_id) vs Security/WFP hex (raw_process_id)
    silver["process_id"] = _to_int(_coalesce(rec, ["ProcessId", "SourceProcessId"])) \
        if log_source == "sysmon" else None
    silver["target_process_id"] = _to_int(rec.get("TargetProcessId"))
    silver["parent_process_id"] = _to_int(rec.get("ParentProcessId"))
    if log_source in ("windows_security", "wfp"):
        rp = _coalesce(rec, ["NewProcessId", "ProcessId"])
        if rp is not None:
            silver["raw_process_id_original"] = str(rp)
            silver["raw_process_id"] = _to_int(rp)
        silver["raw_parent_process_id"] = _to_int(rec.get("ParentProcessId"))

    # hashes
    for col, val in _parse_hashes(rec.get("Hashes")).items():
        silver[col] = val

    # rede
    silver["network_protocol"] = _norm_protocol(rec.get("Protocol"))
    silver["network_direction"] = _norm_direction(rec.get("Initiated"), rec.get("Direction"))
    silver["source_is_ipv6"] = _to_bool(rec.get("SourceIsIpv6"))
    silver["destination_is_ipv6"] = _to_bool(rec.get("DestinationIsIpv6"))

    # arquivo
    silver["file_is_executable"] = _to_bool(rec.get("IsExecutable"))
    silver["file_archived"] = _to_bool(rec.get("Archived"))

    # registro: sub-tipo (12=Create/Delete, 13=SetValue)
    if event_id in (12, 13):
        silver["registry_action"] = rec.get("EventType")

    # image_name = basename
    if silver["image_path"]:
        silver["image_name"] = re.split(r"[\\/]", str(silver["image_path"]))[-1]

    # timestamps
    dt, flag, off = _reconcile_time(rec, log_source)
    if dt:
        silver["event_utc_time"] = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        silver["event_date"] = dt.strftime("%Y-%m-%d")
    silver["time_source_flag"] = flag
    silver["tz_offset_applied_seconds"] = off
    for col in ("event_local_time", "ingest_event_time", "event_received_time",
                "file_creation_utc_time"):
        d = _parse_ts(silver[col])
        if d:
            silver[col] = d.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    # DQ status default
    silver["dq_status"] = "passed"

    # cobertura
    critical = [c for c in ("event_id", "hostname_nk", "record_number",
                            "event_utc_time") if silver.get(c) in (None, "")]
    unmapped = {k: (str(v)[:80] if v is not None else "")
                for k, v in rec.items()
                if k not in _CONSUMED and k not in schema.NOISE_KEYS
                and rec.get(k) not in (None, "", "-")}
    report = CoverageReport(
        event_id=event_id,
        log_source=log_source,
        unknown_event_id=event_id not in schema.KNOWN_EVENT_IDS,
        message_parsed=msg_parsed,
        missing_critical=critical,
        unmapped_keys=unmapped,
    )
    return silver, report
