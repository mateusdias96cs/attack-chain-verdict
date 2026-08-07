"""
Contrato do schema Silver — espelha docs/medallion/ddl_bronze_silver.sql
(silver_windows_security.cleansed_security_event) e as regras de
docs/medallion/medallion_architecture.md.

Este módulo NÃO desenha o schema (isso já existe no DDL) — ele o codifica para
que tanto o parser determinístico quanto o agente Groq escrevam nas MESMAS
colunas, na mesma ordem, sem quebrar a apresentação dos dados.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Ordem canônica das colunas Silver (idêntica ao DDL). O output final é
# emitido nesta ordem para preservar "a forma de escrita e apresentação".
# ---------------------------------------------------------------------------
SILVER_COLUMNS: list[str] = [
    # natural key / lineage
    "source_file", "hostname_nk", "hostname_fqdn", "channel", "record_number",
    # classificação
    "event_id", "log_source",
    # timestamps reconciliados
    "event_utc_time", "event_date", "event_local_time", "ingest_event_time",
    "event_received_time", "file_creation_utc_time", "time_source_flag",
    "tz_offset_applied_seconds",
    # host / collector
    "collector_host", "collector_port",
    # identidade
    "subject_sid", "subject_account_name", "subject_domain", "subject_account_type",
    "target_sid", "target_account_name", "target_domain",
    # processo (ator)
    "process_guid", "process_id", "image_path", "image_name", "company", "product",
    "description", "original_file_name", "file_version", "command_line",
    "current_directory", "integrity_level", "hash_sha1", "hash_md5", "hash_sha256",
    "hash_imphash", "parent_process_guid", "parent_process_id", "parent_image",
    "parent_command_line", "logon_guid", "terminal_session_id",
    # processo (alvo — EventID 8/10)
    "target_process_guid", "target_process_id", "target_image", "granted_access",
    "call_trace", "source_thread_id", "target_thread_id", "new_thread_id",
    # processo fallback (Security/WFP, sem ProcessGuid)
    "raw_process_image", "raw_process_id", "raw_process_id_original",
    "raw_parent_process_image", "raw_parent_process_id",
    # rede
    "source_ip", "source_is_ipv6", "destination_ip", "destination_is_ipv6",
    "source_port", "destination_port", "network_protocol", "network_direction",
    "network_action",
    # arquivo
    "target_filename", "file_is_executable", "file_archived",
    # registro
    "registry_target_object", "registry_details", "registry_action",
    # dns
    "dns_query_name", "dns_query_status", "dns_query_results",
    # object access
    "object_name", "object_type", "handle_id", "access_mask", "access_list",
    # logon
    "logon_type", "logon_id", "authentication_package", "elevated_token",
    "workstation_name",
    # powershell
    "script_block_text", "script_block_id", "message_number", "message_total",
    # genérico / lineage
    "message_raw", "rule_name", "severity", "event_result", "opcode",
    # zero-perda: JSON de toda chave bruta não-mapeada e não-ruído (auditoria)
    "unmapped_json",
    # metadados DQ
    "dq_status", "dq_failed_rules",
]

# ---------------------------------------------------------------------------
# Coalesce: coluna Silver -> lista de chaves candidatas (no JSON bruto OU no
# bloco Message). Ordem = prioridade. Primeiro valor não-nulo vence.
# ---------------------------------------------------------------------------
COALESCE_MAP: dict[str, list[str]] = {
    "hostname_fqdn": ["Hostname"],
    "channel": ["Channel"],
    "record_number": ["RecordNumber"],
    "severity": ["Severity"],
    "rule_name": ["RuleName"],
    "opcode": ["Opcode"],
    # collector
    "collector_host": ["host"],
    "collector_port": ["port"],
    # timestamps
    "event_local_time": ["EventTime"],
    "ingest_event_time": ["@timestamp"],
    "event_received_time": ["EventReceivedTime"],
    "file_creation_utc_time": ["CreationUtcTime"],
    # identidade
    "subject_sid": ["SubjectUserSid", "UserID", "RemoteUserID"],
    "subject_account_name": ["SubjectUserName", "AccountName", "User"],
    "subject_domain": ["SubjectDomainName", "Domain"],
    "subject_account_type": ["AccountType"],
    "target_sid": ["TargetUserSid"],
    "target_account_name": ["TargetUserName"],
    "target_domain": ["TargetDomainName"],
    # processo ator (Sysmon). EventID 10 usa Source* como ator.
    "process_guid": ["ProcessGuid", "SourceProcessGUID", "SourceProcessGuid"],
    # Image/SourceImage (Sysmon); ImagePath/ServiceFileName = binário do serviço
    # instalado (System 7045 / Security 4697) — mesmo papel de "executável do evento".
    "image_path": ["Image", "SourceImage", "ImagePath", "ServiceFileName"],
    "company": ["Company"],
    "product": ["Product"],
    "description": ["Description"],
    "original_file_name": ["OriginalFileName"],
    "file_version": ["FileVersion"],
    "command_line": ["CommandLine"],
    "current_directory": ["CurrentDirectory"],
    "integrity_level": ["IntegrityLevel"],
    "parent_process_guid": ["ParentProcessGuid"],
    "parent_image": ["ParentImage"],
    "parent_command_line": ["ParentCommandLine"],
    "logon_guid": ["LogonGuid"],
    "terminal_session_id": ["TerminalSessionId"],
    # processo alvo (8/10)
    "target_process_guid": ["TargetProcessGUID", "TargetProcessGuid"],
    "target_image": ["TargetImage"],
    "granted_access": ["GrantedAccess"],
    "call_trace": ["CallTrace"],
    # processo fallback (Security/WFP)
    "raw_process_image": ["NewProcessName", "ProcessName", "Application"],
    "raw_parent_process_image": ["ParentProcessName"],
    # rede
    "source_ip": ["SourceIp", "SourceAddress", "IpAddress"],
    "destination_ip": ["DestinationIp", "DestAddress"],
    "network_action": ["LayerName"],
    # arquivo
    "target_filename": ["TargetFilename"],
    # registro
    "registry_target_object": ["TargetObject"],
    "registry_details": ["Details"],
    # dns
    "dns_query_name": ["QueryName"],
    "dns_query_status": ["QueryStatus"],
    "dns_query_results": ["QueryResults"],
    # object access
    "object_name": ["ObjectName"],
    "object_type": ["ObjectType"],
    "handle_id": ["HandleId"],
    "access_mask": ["AccessMask"],
    "access_list": ["AccessList"],
    # logon
    "authentication_package": ["AuthenticationPackageName"],
    "workstation_name": ["WorkstationName"],
    "logon_id": ["TargetLogonId", "SubjectLogonId", "LogonId"],
    # powershell
    "script_block_text": ["ScriptBlockText"],
    "script_block_id": ["ScriptBlockId"],
    # genérico
    "message_raw": ["Message"],
}

# Chaves que exigem normalização especial (tratadas fora do COALESCE_MAP):
#   ProcessId/SourceProcessId (decimal) -> process_id
#   TargetProcessId (decimal) -> target_process_id
#   ParentProcessId (decimal) -> parent_process_id
#   NewProcessId/ProcessId (hex) -> raw_process_id (+ _original)
#   Hashes -> hash_sha1/md5/sha256/imphash
#   SourcePort/DestinationPort/DestPort -> int
#   Protocol -> network_protocol (normalizado)
#   Initiated/Direction -> network_direction
#   Source/DestinationIsIpv6, IsExecutable, Archived -> bool
#   LogonType, SourceThreadId, TargetThreadId, NewThreadId -> int
#   EventType (12/13) -> registry_action
#   MessageNumber/MessageTotal -> int

# ---------------------------------------------------------------------------
# Derivação de log_source (NÃO deriva de Channel sozinho — WFP compartilha
# Channel='Security' com Windows Security, ver medallion_architecture.md §0).
# ---------------------------------------------------------------------------
SYSMON_EVENT_IDS = {1, 3, 5, 7, 8, 9, 10, 11, 12, 13, 17, 18, 22, 23}
WFP_EVENT_IDS = {5156, 5158, 5447}
POWERSHELL_EVENT_IDS = {400, 403, 600, 800, 4103, 4104}
# Provedores adicionais relevantes de segurança. Os IDs de baixo número COLIDEM com o
# Sysmon (BITS 3 vs Sysmon 3; TerminalServices 24/25 vs Sysmon), então derive_log_source
# identifica esses provedores pelo CANAL, não pelo event_id.
SYSTEM_EVENT_IDS = {7045, 7040, 7036}          # serviço: instalação / mudança / estado
WMI_EVENT_IDS = {5857, 5858, 5859, 5860, 5861}
DEFENDER_EVENT_IDS = {1006, 1015, 1116, 1117, 5001, 5007}
RDP_EVENT_IDS = {1149, 21, 24, 25}
FIREWALL_EVENT_IDS = {2004, 2005, 2006, 2009, 2033}
# Windows Security = todo o resto (4624, 4625, 4656, 4658, 4663, 4688, 4697, ...)

# Fragmentos de nome de canal → log_source (checados ANTES do event_id p/ evitar colisão).
_CHANNEL_SOURCE = (
    ("WMI-Activity", "wmi"),
    ("Bits-Client", "bits"),
    ("TerminalServices", "rdp"),
    ("Windows Firewall", "firewall"),
    ("Windows Defender", "defender"),
)

KNOWN_EVENT_IDS = (
    SYSMON_EVENT_IDS | WFP_EVENT_IDS | POWERSHELL_EVENT_IDS |
    SYSTEM_EVENT_IDS | WMI_EVENT_IDS | DEFENDER_EVENT_IDS |
    RDP_EVENT_IDS | FIREWALL_EVENT_IDS |
    {4624, 4625, 4634, 4656, 4658, 4663, 4670, 4672, 4673,
     4688, 4689, 4690, 4697, 4703, 4627, 5140, 5145}
)


def derive_log_source(event_id: int | None, channel: str | None) -> str:
    ch = channel or ""
    # 1) provedores identificados pelo CANAL (event IDs colidem com o Sysmon)
    for frag, src in _CHANNEL_SOURCE:
        if frag in ch:
            return src
    # 2) provedores por event_id / sufixo de canal
    if event_id in WFP_EVENT_IDS:
        return "wfp"
    if event_id in SYSMON_EVENT_IDS or ch.endswith("Sysmon/Operational"):
        return "sysmon"
    if event_id in POWERSHELL_EVENT_IDS or "PowerShell" in ch:
        return "powershell"
    if event_id in SYSTEM_EVENT_IDS or ch == "System":
        return "system"
    return "windows_security"


# Canais conhecidos (DQ rule #9)
KNOWN_CHANNELS = {
    "Microsoft-Windows-Sysmon/Operational", "Security", "System",
    "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational",
    "Microsoft-Windows-WMI-Activity/Operational",
    "Microsoft-Windows-Bits-Client/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Microsoft-Windows-Windows Defender/Operational",
}

# Campos do Windows que NÃO possuem coluna Silver correspondente (ruído de
# telemetria). Ignorados no cálculo de cobertura para o LLM não disparar à toa.
NOISE_KEYS = {
    "RestrictedAdminMode", "VirtualAccount", "LmPackageName", "TransmittedServices",
    "ImpersonationLevel", "TargetLinkedLogonId", "TargetOutboundUserName",
    "TargetOutboundDomainName", "LogonProcessName", "KeyLength",
    "DestinationHostname", "SourceHostname", "DestinationPortName", "SourcePortName",
    "ResourceAttributes", "ObjectServer", "MandatoryLabel", "RemoteMachineID",
    "FilterRTID", "LayerRTID", "Payload", "ContextInfo", "ActivityID",
    "PrivilegeList",
}

# Comprimento fixo esperado de cada hash (DQ rule #14)
HASH_LENGTHS = {"hash_sha1": 40, "hash_md5": 32, "hash_sha256": 64, "hash_imphash": 32}
