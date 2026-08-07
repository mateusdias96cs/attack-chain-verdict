"""
Materialização da camada Gold para o agente de correlação temporal.

Constrói uma `fact_security_event` denormalizada na DuckDB direto dos NDJSON reais
(dadosdia1/dadosdia2), carregando exatamente as colunas que a correlação precisa —
incluindo as que o builder de teste original não trazia: parent_process_guid,
subject_account (nome, não só SID), target_filename e hash_sha256 (chave de artefato
para ligar dia1↔dia2).

Princípio central (requisito do usuário): **uma linha do tempo única**. `source_file`
é preservado como coluna de linhagem, mas NUNCA é fronteira de correlação — toda
ordenação é por `event_utc_time` (UTC canônico reconciliado). Os dois arquivos são
sequenciais com um gap de ~4,5h; a correlação atravessa esse gap via artefato.
"""
from __future__ import annotations

import os
import pathlib

import duckdb

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILES = [ROOT / "dadosdia1.json", ROOT / "dadosdia2.json"]

# EventID → log_source (WFP compartilha Channel='Security', então vem do EventID)
LOG_SOURCE_CASE = """
    CASE
        WHEN event_id IN (800, 400, 403, 600, 4103, 4104) THEN 'powershell'
        WHEN event_id IN (5156, 5157, 5158, 5447)         THEN 'wfp'
        WHEN event_id BETWEEN 1 AND 255                   THEN 'sysmon'
        WHEN event_id BETWEEN 4600 AND 4799               THEN 'windows_security'
        ELSE 'unknown'
    END
"""

# EventID → categoria legível (subset relevante p/ correlação)
EVENT_CATEGORY_CASE = """
    CASE event_id
        WHEN 1    THEN 'process_create'
        WHEN 3    THEN 'network_connect'
        WHEN 7    THEN 'image_load'
        WHEN 8    THEN 'create_remote_thread'
        WHEN 10   THEN 'process_access'
        WHEN 11   THEN 'file_create'
        WHEN 12   THEN 'registry_create_delete'
        WHEN 13   THEN 'registry_set_value'
        WHEN 22   THEN 'dns_query'
        WHEN 23   THEN 'file_delete'
        WHEN 4688 THEN 'process_create'
        WHEN 4624 THEN 'logon'
        WHEN 4625 THEN 'logon_failure'
        WHEN 4663 THEN 'object_access'
        WHEN 4656 THEN 'object_access_request'
        WHEN 5156 THEN 'network_connect'
        WHEN 5158 THEN 'network_bind'
        WHEN 800  THEN 'powershell_pipeline'
        WHEN 4103 THEN 'powershell_module'
        WHEN 4104 THEN 'powershell_script_block'
        ELSE 'other'
    END
"""

# Contas "de máquina"/bem-conhecidas que não representam um ator humano (ruído).
NON_ACTOR_ACCOUNTS = (
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
    "-", "N/A", "", "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2",
)


def _read_expr(sample: int | None) -> tuple[str, str]:
    files = "[" + ",".join(f"'{f.as_posix()}'" for f in DATA_FILES if f.exists()) + "]"
    read = (f"read_json({files}, format='newline_delimited', records='auto', "
            f"filename=true, ignore_errors=true, maximum_object_size=16000000, "
            f"sample_size=-1)")
    src = "regexp_replace(regexp_replace(filename, '.*/', ''), '\\.json$', '')"
    qualify = (f"QUALIFY row_number() OVER (PARTITION BY {src} ORDER BY (SELECT 1)) "
               f"<= {int(sample)}") if sample else ""
    return read, qualify


def build_gold(con: duckdb.DuckDBPyConnection, sample: int | None = None) -> None:
    """Constrói `fact_security_event` (denormalizada) na conexão dada."""
    read, qualify = _read_expr(sample)
    src = "regexp_replace(regexp_replace(filename, '.*/', ''), '\\.json$', '')"

    # Um único parse por linha: extrai todos os campos num VARCHAR[] (memória).
    paths = [
        "$.Hostname", "$.Channel", "$.RecordNumber", "$.EventID",              # 1-4
        "$.UtcTime", "$.EventTime",                                            # 5-6
        "$.SubjectUserSid", "$.UserID", "$.RemoteUserID", "$.TargetUserSid",   # 7-10
        "$.SubjectUserName", "$.User", "$.AccountName", "$.TargetUserName",    # 11-14
        "$.ProcessGuid", "$.ProcessId", "$.Image", "$.CommandLine", "$.Hashes",# 15-19
        "$.ParentProcessGuid", "$.ParentImage",                               # 20-21
        "$.TargetProcessGUID", "$.TargetImage", "$.GrantedAccess",            # 22-24
        "$.NewProcessId", "$.NewProcessName",                                 # 25-26
        "$.SourceIp", "$.SourceAddress", "$.DestinationIp", "$.DestAddress",  # 27-30
        "$.SourcePort", "$.DestinationPort", "$.DestPort", "$.Protocol",      # 31-34
        "$.TargetFilename", "$.TargetObject", "$.Details",                    # 35-37
        "$.QueryName", "$.EventType",                                         # 38-39
        "$.Signed", "$.SignatureStatus",                                      # 40-41
    ]
    path_list = "[" + ",".join(f"'{p}'" for p in paths) + "]"

    con.execute(f"""
        CREATE TABLE fact_stage AS
        WITH raw AS (
            SELECT {src} AS source_file,
                   json_extract_string(json, {path_list}) AS v
            FROM {read}
            WHERE json IS NOT NULL
            {qualify}
        )
        SELECT
            source_file,
            upper(split_part(v[1], '.', 1))                        AS hostname_nk,
            v[2]                                                   AS channel,
            TRY_CAST(v[3] AS BIGINT)                               AS record_number,
            TRY_CAST(v[4] AS INT)                                  AS event_id,
            TRY_STRPTIME(v[5], '%Y-%m-%d %H:%M:%S.%f')             AS utc_ts,
            TRY_STRPTIME(v[6], '%Y-%m-%d %H:%M:%S')                AS local_ts,
            coalesce(v[7], v[8], v[9])                             AS subject_sid,
            v[10]                                                  AS target_sid,
            -- nome de conta do ator (sem domínio), minúsculo p/ agrupar
            lower(regexp_replace(coalesce(v[11], v[12], v[13]), '^.*\\\\', '')) AS subject_account,
            lower(regexp_replace(v[14], '^.*\\\\', ''))            AS target_account,
            v[15]                                                  AS process_guid,
            TRY_CAST(v[16] AS BIGINT)                              AS process_id,
            v[17]                                                  AS image_path,
            reverse(split_part(reverse(v[17]), '\\', 1))           AS image_name,
            v[18]                                                  AS command_line,
            lower(regexp_extract(v[19], 'SHA256=([0-9A-Fa-f]+)', 1)) AS hash_sha256,
            v[20]                                                  AS parent_process_guid,
            v[21]                                                  AS parent_image,
            v[22]                                                  AS target_process_guid,
            v[23]                                                  AS target_image,
            v[24]                                                  AS granted_access,
            TRY_CAST(coalesce(v[25], v[16]) AS BIGINT)             AS raw_process_id,
            v[26]                                                  AS raw_process_image,
            coalesce(v[27], v[28])                                 AS source_ip,
            coalesce(v[29], v[30])                                 AS destination_ip,
            TRY_CAST(v[31] AS INT)                                 AS source_port,
            TRY_CAST(coalesce(v[32], v[33]) AS INT)                AS destination_port,
            v[34]                                                  AS network_protocol,
            v[35]                                                  AS target_filename,
            v[36]                                                  AS registry_target_object,
            v[37]                                                  AS registry_details,
            v[38]                                                  AS dns_query_name,
            v[39]                                                  AS event_result,
            CASE WHEN lower(v[40]) = 'true' THEN true
                 WHEN lower(v[40]) = 'false' THEN false ELSE NULL END AS signed,
            v[41]                                                  AS signature_status
        FROM raw
    """)

    # calibração de timezone (fallback quando não há UtcTime)
    offset = con.execute("""
        SELECT coalesce(median(epoch(utc_ts) - epoch(local_ts)), 0)
        FROM fact_stage WHERE utc_ts IS NOT NULL AND local_ts IS NOT NULL
    """).fetchone()[0]

    # Fact final: reconcilia event_utc_time, deriva log_source/category, dedup no NK.
    con.execute(f"""
        CREATE TABLE fact_security_event AS
        SELECT * EXCLUDE (rn, utc_ts, local_ts) FROM (
            SELECT
                s.*,
                {LOG_SOURCE_CASE.replace('event_id', 's.event_id')}      AS log_source,
                {EVENT_CATEGORY_CASE.replace('event_id', 's.event_id')}  AS event_category,
                coalesce(s.utc_ts, s.local_ts + INTERVAL ({int(offset)}) SECOND) AS event_utc_time,
                CASE WHEN s.utc_ts IS NOT NULL THEN 'utc_time_native'
                     WHEN s.local_ts IS NOT NULL THEN 'event_time_calibrated'
                     ELSE 'unresolved' END AS time_source_flag,
                row_number() OVER (
                    PARTITION BY s.source_file, s.hostname_nk, s.channel, s.record_number
                    ORDER BY (SELECT 1)
                ) AS rn
            FROM fact_stage s
            WHERE s.hostname_nk IS NOT NULL AND s.channel IS NOT NULL
              AND s.record_number IS NOT NULL
        )
        WHERE rn = 1 AND event_utc_time IS NOT NULL
    """)
    con.execute("DROP TABLE fact_stage")

    # marca atores humanos (não-máquina, não bem-conhecido) p/ focar a correlação
    non_actor = ",".join(f"'{a.lower()}'" for a in NON_ACTOR_ACCOUNTS)
    con.execute(f"""
        ALTER TABLE fact_security_event ADD COLUMN is_actor BOOLEAN;
        UPDATE fact_security_event SET is_actor =
            subject_account IS NOT NULL
            AND subject_account NOT IN ({non_actor})
            AND subject_account NOT LIKE '%$'
    """)


def open_gold(sample: int | None = None,
              db_path: str | None = None,
              rebuild: bool = False,
              memory_limit: str = "4GB",
              threads: int = 2) -> duckdb.DuckDBPyConnection:
    """Abre (ou constrói) o warehouse gold on-disk, memory-safe p/ WSL."""
    if db_path is None:
        tmp = pathlib.Path(os.environ.get("AGENTECVE_DUCKDB_TMP", ROOT / ".duckdb_tmp"))
        tmp.mkdir(parents=True, exist_ok=True)
        db_path = str(tmp / "temporal.duckdb")
        spill = (tmp / "spill").as_posix()
    else:
        spill = str(pathlib.Path(db_path).parent / "spill")

    exists = pathlib.Path(db_path).exists()
    if exists and rebuild:
        pathlib.Path(db_path).unlink()
        exists = False

    con = duckdb.connect(db_path)
    con.execute(f"PRAGMA temp_directory='{spill}'")
    con.execute(f"PRAGMA memory_limit='{memory_limit}'")
    con.execute(f"PRAGMA threads={threads}")
    con.execute("PRAGMA preserve_insertion_order=false")

    already = exists and con.execute(
        "SELECT count(*) FROM information_schema.tables "
        "WHERE table_name='fact_security_event'").fetchone()[0] == 1
    if not already:
        build_gold(con, sample=sample)
    return con
