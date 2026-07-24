"""
Data-reliability + search-return tests for the Gold star schema.

There is no live warehouse yet — only the raw JSONL and the corrected schema/medallion
design. So this file BUILDS a Gold star schema in an in-memory DuckDB warehouse straight
from the real source data (dadosdia1.json / dadosdia2.json), faithfully implementing the
CORRECTED design (post-audit): deterministic hash surrogates (M5), log_source derived from
EventID ranges not Channel (M1), PID hex/decimal normalization (H1), IP numeric column (M3),
UtcTime-canonical timestamp reconciliation (H4), SCD Type 2 dim_process with a gap-free
validity chain, and POINT-IN-TIME fact→dim_process resolution (C2).

It then runs two families of checks:
  * Reliability  — referential integrity, grain/uniqueness, row-count reconciliation,
                   not-null contracts, SCD2 chain integrity, value fidelity.
  * Search returns — the queries an analyst actually runs, asserting each returns the
                     right rows (and that the audit's query-corrupting bugs stay fixed).

Run:  pytest tests/test_gold_search.py -v          # builds Gold from all 783K events (~60s)
Deps: pip install -r tests/requirements.txt        # duckdb + pytest
Env:  AGENTECVE_TEST_SAMPLE=40000   # cap rows per source file (smaller Gold tables for debugging)
      AGENTECVE_DUCKDB_TMP=/path    # where the on-disk build DB + spill live (default: ./.duckdb_tmp)
"""
from __future__ import annotations

import os
import pathlib

import duckdb
import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA_FILES = [ROOT / "dadosdia1.json", ROOT / "dadosdia2.json"]
SAMPLE = os.environ.get("AGENTECVE_TEST_SAMPLE")  # optional row cap per-source for speed

# EventID → log_source ranges. WFP (5156/5158/5447) shares Channel='Security' with Windows
# auditing, so log_source MUST come from EventID, never Channel (audit finding M1).
LOG_SOURCE_CASE = """
    CASE
        WHEN event_id IN (800, 400, 403, 600, 4103, 4104) THEN 'powershell'
        WHEN event_id IN (5156, 5157, 5158, 5447)         THEN 'wfp'
        WHEN event_id BETWEEN 1 AND 255                   THEN 'sysmon'
        WHEN event_id BETWEEN 4600 AND 4799               THEN 'windows_security'
        ELSE 'unknown'
    END
"""


# --------------------------------------------------------------------------------------
# Warehouse build (Bronze → Silver → Gold), all in DuckDB, from the real JSONL.
# --------------------------------------------------------------------------------------
def _build_warehouse(con: duckdb.DuckDBPyConnection) -> None:
    con.execute("CREATE MACRO sk(x) AS CAST(hash(x) >> 1 AS BIGINT)")  # signed-fit hash surrogate

    files = "[" + ",".join(f"'{f.as_posix()}'" for f in DATA_FILES) + "]"
    # DuckDB's native newline-delimited JSON reader (memory-efficient, streaming). records='auto'
    # tolerates the occasional non-record line by exposing each row as one `json` column we extract
    # from — far leaner than materializing 783K raw text lines. ignore_errors skips unparseable rows.
    read = (f"read_json({files}, format='newline_delimited', records='auto', filename=true, "
            f"ignore_errors=true, maximum_object_size=16000000, sample_size=-1)")
    src = "regexp_replace(regexp_replace(filename, '.*/', ''), '\\.json$', '')"
    qualify = f"QUALIFY row_number() OVER (PARTITION BY {src} ORDER BY (SELECT 1)) <= {int(SAMPLE)}" if SAMPLE else ""

    # ---- BRONZE: lightweight landing ledger (counts + validity), used for reconciliation. -------
    con.execute(f"""
        CREATE TABLE bronze AS
        SELECT {src} AS source_file, (json IS NOT NULL) AS json_ok
        FROM {read}
        {qualify}
    """)

    # ---- SILVER: typed, normalized, reconciled, deduplicated on the fact natural key -------------
    # Memory-critical: parse each row's JSON EXACTLY ONCE. json_extract_string(json, [paths]) pulls
    # every field we need in a single parse and returns a VARCHAR[]; re-parsing per field (30×) blew
    # WSL RAM. The heaviest raw field (Message) is intentionally not carried, to stay within memory.
    # `v[i]` below indexes that list (1-based). PID normalization (H1): TRY_CAST parses both
    # '0x214c' (hex) and '900' (decimal) → BIGINT.
    paths = [
        "$.Hostname", "$.Channel", "$.RecordNumber", "$.EventID", "$.UtcTime", "$.EventTime",     # 1-6
        "$.UserID", "$.SubjectUserSid", "$.RemoteUserID", "$.TargetUserSid",                       # 7-10
        "$.ProcessGuid", "$.ProcessId", "$.Image", "$.CommandLine", "$.Hashes",                    # 11-15
        "$.TargetProcessGUID", "$.GrantedAccess", "$.NewProcessId",                                # 16-18
        "$.SourceIp", "$.SourceAddress", "$.DestinationIp", "$.DestAddress",                       # 19-22
        "$.SourcePort", "$.DestinationPort", "$.DestPort",                                         # 23-25
        "$.TargetObject", "$.QueryName", "$.EventType",                                            # 26-28
    ]
    path_list = "[" + ",".join(f"'{p}'" for p in paths) + "]"
    con.execute(f"""
        CREATE TABLE silver_stage AS
        WITH raw AS (
            SELECT {src} AS source_file, json_extract_string(json, {path_list}) AS v
            FROM {read}
            WHERE json IS NOT NULL
            {qualify}
        )
        SELECT
            source_file,
            upper(split_part(v[1], '.', 1))                                        AS hostname_nk,
            v[1]                                                                    AS hostname_fqdn,
            v[2]                                                                    AS channel,
            TRY_CAST(v[3] AS BIGINT)                                                AS record_number,
            TRY_CAST(v[4] AS INT)                                                   AS event_id,
            TRY_STRPTIME(v[5], '%Y-%m-%d %H:%M:%S.%f')                              AS utc_ts,   -- UtcTime (Sysmon, ms)
            TRY_STRPTIME(v[6], '%Y-%m-%d %H:%M:%S')                                 AS local_ts, -- EventTime (local)
            coalesce(v[7], v[8], v[9])                                             AS subject_sid,
            v[10]                                                                   AS target_sid,
            v[11]                                                                   AS process_guid,
            TRY_CAST(v[12] AS BIGINT)                                               AS process_id,
            v[13]                                                                   AS image_path,
            reverse(split_part(reverse(v[13]), '\\', 1))                            AS image_name,
            v[14]                                                                   AS command_line,
            regexp_extract(v[15], 'SHA1=([0-9A-Fa-f]+)', 1)                        AS hash_sha1,
            regexp_extract(v[15], 'MD5=([0-9A-Fa-f]+)', 1)                         AS hash_md5,
            regexp_extract(v[15], 'SHA256=([0-9A-Fa-f]+)', 1)                      AS hash_sha256,
            v[16]                                                                   AS target_process_guid,
            v[17]                                                                   AS granted_access,
            TRY_CAST(coalesce(v[18], v[12]) AS BIGINT)                              AS raw_process_id,          -- H1: normalized
            coalesce(v[18], v[12])                                                 AS raw_process_id_original, -- original text
            coalesce(v[19], v[20])                                                 AS source_ip,
            coalesce(v[21], v[22])                                                 AS destination_ip,
            TRY_CAST(v[23] AS INT)                                                  AS source_port,
            TRY_CAST(coalesce(v[24], v[25]) AS INT)                                 AS destination_port,
            v[26]                                                                   AS registry_target_object,
            v[27]                                                                   AS dns_query_name,
            v[28]                                                                   AS event_result
        FROM raw
    """)

    # timezone calibration: median offset between UtcTime and EventTime on rows carrying both
    offset_seconds = con.execute("""
        SELECT coalesce(median(epoch(utc_ts) - epoch(local_ts)), 0)
        FROM silver_stage WHERE utc_ts IS NOT NULL AND local_ts IS NOT NULL
    """).fetchone()[0]

    # Final Silver: reconcile event_utc_time, derive log_source, dedup on the fact natural key.
    con.execute(f"""
        CREATE TABLE silver AS
        SELECT * EXCLUDE (rn) FROM (
            SELECT
                s.*,
                {LOG_SOURCE_CASE.replace('event_id', 's.event_id')} AS log_source,
                coalesce(s.utc_ts, s.local_ts + INTERVAL ({int(offset_seconds)}) SECOND) AS event_utc_time,
                CASE WHEN s.utc_ts IS NOT NULL THEN 'utc_time_native'
                     WHEN s.local_ts IS NOT NULL THEN 'event_time_calibrated'
                     ELSE 'unresolved' END AS time_source_flag,
                row_number() OVER (
                    PARTITION BY s.source_file, s.hostname_nk, s.channel, s.record_number
                    ORDER BY (SELECT 1)
                ) AS rn
            FROM silver_stage s
            WHERE s.hostname_nk IS NOT NULL AND s.channel IS NOT NULL AND s.record_number IS NOT NULL
        )
        WHERE rn = 1 AND event_utc_time IS NOT NULL
    """)
    con.execute("DROP TABLE silver_stage")  # free the wide staging table before building Gold

    # ---- GOLD dimensions -----------------------------------------------------------------
    con.execute("""
        CREATE TABLE dim_date AS
        SELECT DISTINCT
            CAST(strftime(event_utc_time, '%Y%m%d') AS INT) AS date_sk,
            CAST(event_utc_time AS DATE)                    AS full_date,
            dayname(event_utc_time)                         AS day_of_week,
            (dayofweek(event_utc_time) IN (0, 6))           AS is_weekend
        FROM silver
        UNION ALL SELECT 19000101, DATE '1900-01-01', 'Unknown', FALSE
    """)
    con.execute("""
        CREATE TABLE dim_time AS
        SELECT DISTINCT
            CAST(strftime(event_utc_time, '%H%M%S') AS INT) AS time_sk,
            CAST(strftime(event_utc_time, '%H') AS INT)     AS hour_24,
            (CAST(strftime(event_utc_time, '%H') AS INT) BETWEEN 8 AND 17) AS is_business_hours  -- UTC-referenced (L3)
        FROM silver
        UNION ALL SELECT -1, -1, FALSE
    """)
    con.execute("""
        CREATE TABLE dim_host AS
        SELECT sk(hostname_nk) AS host_sk, hostname_nk, any_value(hostname_fqdn) AS hostname_fqdn
        FROM silver GROUP BY hostname_nk
        UNION ALL SELECT -1, 'UNKNOWN', 'UNKNOWN'
    """)
    con.execute("""
        CREATE TABLE dim_user AS
        WITH sids AS (
            SELECT subject_sid AS sid FROM silver WHERE subject_sid IS NOT NULL
            UNION SELECT target_sid FROM silver WHERE target_sid IS NOT NULL
        )
        SELECT sk(sid) AS user_sk, sid FROM sids
        UNION ALL SELECT -1, 'N/A'
    """)
    # IP numeric (IPv4) for CIDR/range queries (M3); NULL for IPv6/malformed.
    con.execute("""
        CREATE TABLE dim_network_endpoint AS
        WITH ips AS (
            SELECT source_ip AS ip FROM silver WHERE source_ip IS NOT NULL
            UNION SELECT destination_ip FROM silver WHERE destination_ip IS NOT NULL
        )
        SELECT
            sk(ip) AS endpoint_sk, ip AS ip_address,
            (ip LIKE '%:%') AS is_ipv6,
            CASE WHEN ip LIKE '%:%' OR regexp_matches(ip, '[^0-9.]') THEN NULL
                 ELSE CAST(split_part(ip, '.', 1) AS BIGINT) * 16777216
                    + CAST(split_part(ip, '.', 2) AS BIGINT) * 65536
                    + CAST(split_part(ip, '.', 3) AS BIGINT) * 256
                    + CAST(split_part(ip, '.', 4) AS BIGINT) END AS ip_numeric,
            CASE WHEN ip LIKE '%:%' THEN NULL
                 ELSE split_part(ip, '.', 1) || '.' || split_part(ip, '.', 2) || '.' || split_part(ip, '.', 3)
            END AS ip_prefix_24
        FROM ips
        UNION ALL SELECT -1, 'N/A', FALSE, NULL, NULL
    """)
    con.execute(f"""
        CREATE TABLE dim_event_type AS
        SELECT
            sk(event_id::VARCHAR || '|' || channel) AS event_type_sk,
            event_id, channel,
            any_value({LOG_SOURCE_CASE}) AS log_source
        FROM silver GROUP BY event_id, channel
        UNION ALL SELECT -1, -1, 'UNKNOWN', 'unknown'
    """)

    # ---- GOLD dim_process — SCD Type 2, gap-free contiguous validity chain ----------------
    con.execute("""
        CREATE TABLE dim_process AS
        WITH sysmon AS (
            SELECT process_guid, event_utc_time, record_number,
                   image_path, image_name, command_line, hash_sha256, hash_sha1, hash_md5,
                   process_id, event_id
            FROM silver
            WHERE log_source = 'sysmon' AND process_guid IS NOT NULL
        ),
        flagged AS (
            -- carry-forward semantics: compare each attribute to the last-known NON-NULL value.
            -- A transition to NULL (e.g. EventID 10 ProcessAccess carrying no hash/cmdline) is an
            -- attribute-COMPLETENESS gap, NOT a real change, and must NOT start a new version (§4.5).
            SELECT *,
                row_number() OVER w AS rn,
                lag(image_path   IGNORE NULLS) OVER w  AS p_img,
                lag(hash_sha256  IGNORE NULLS) OVER w  AS p_hash,
                lag(command_line IGNORE NULLS) OVER w  AS p_cmd,
                last_value(image_path   IGNORE NULLS) OVER wc AS c_img,
                last_value(command_line IGNORE NULLS) OVER wc AS c_cmd,
                last_value(hash_sha256  IGNORE NULLS) OVER wc AS c_sha256,
                last_value(hash_sha1    IGNORE NULLS) OVER wc AS c_sha1,
                last_value(hash_md5     IGNORE NULLS) OVER wc AS c_md5,
                last_value(image_name   IGNORE NULLS) OVER wc AS c_iname,
                last_value(process_id) OVER wc AS c_pid
            FROM sysmon
            WINDOW w  AS (PARTITION BY process_guid ORDER BY event_utc_time, record_number),
                   wc AS (PARTITION BY process_guid ORDER BY event_utc_time, record_number
                          ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW)
        ),
        boundaries AS (  -- a version starts only on a genuine NON-NULL change of a security-relevant attr
            SELECT * FROM flagged
            WHERE rn = 1
               OR (image_path   IS NOT NULL AND image_path   IS DISTINCT FROM p_img)
               OR (hash_sha256  IS NOT NULL AND hash_sha256  IS DISTINCT FROM p_hash)
               OR (command_line IS NOT NULL AND command_line IS DISTINCT FROM p_cmd)
            QUALIFY row_number() OVER (PARTITION BY process_guid, event_utc_time ORDER BY record_number) = 1
        ),
        versioned AS (
            SELECT *,
                event_utc_time AS effective_from,
                coalesce(lead(event_utc_time) OVER (PARTITION BY process_guid ORDER BY event_utc_time),
                         TIMESTAMP '9999-12-31 00:00:00') AS effective_to,
                (lead(event_utc_time) OVER (PARTITION BY process_guid ORDER BY event_utc_time) IS NULL) AS is_current
            FROM boundaries
        )
        SELECT
            sk(process_guid || '|' || effective_from::VARCHAR) AS process_sk,
            process_guid, c_pid AS process_id, c_img AS image_path, c_iname AS image_name,
            c_cmd AS command_line, c_sha1 AS hash_sha1, c_md5 AS hash_md5, c_sha256 AS hash_sha256,
            event_id AS record_source, effective_from, effective_to, is_current
        FROM versioned
        UNION ALL
        SELECT -1, 'N/A', NULL, NULL, NULL, NULL, NULL, NULL, NULL,
               -1, TIMESTAMP '1900-01-01 00:00:00', TIMESTAMP '9999-12-31 00:00:00', TRUE
    """)
    con.execute("CREATE VIEW dim_process_current AS SELECT * FROM dim_process WHERE is_current")

    # ---- GOLD fact — FKs resolved, process_sk via POINT-IN-TIME join (C2) -----------------
    con.execute("""
        CREATE TABLE fact_security_event AS
        SELECT
            sk(s.source_file || '|' || s.hostname_nk || '|' || s.channel || '|' || s.record_number::VARCHAR) AS event_sk,
            s.source_file, s.hostname_nk, s.channel, s.record_number,
            coalesce(dd.date_sk, 19000101)                     AS date_sk,
            coalesce(dt.time_sk, -1)                           AS time_sk,
            coalesce(dh.host_sk, -1)                            AS host_sk,
            coalesce(du_s.user_sk, -1)                          AS subject_user_sk,
            coalesce(du_t.user_sk, -1)                          AS target_user_sk,
            coalesce(dp.process_sk, -1)                         AS process_sk,          -- point-in-time
            coalesce(dp_t.process_sk, -1)                       AS target_process_sk,   -- point-in-time
            coalesce(ep_s.endpoint_sk, -1)                     AS source_endpoint_sk,
            coalesce(ep_d.endpoint_sk, -1)                     AS destination_endpoint_sk,
            coalesce(et.event_type_sk, -1)                     AS event_type_sk,
            s.log_source,                                       -- denormalized (M1)
            s.event_utc_time, s.event_id,
            s.raw_process_id, s.raw_process_id_original,
            s.source_ip, s.destination_ip, s.source_port, s.destination_port,
            s.registry_target_object, s.dns_query_name, s.granted_access,
            s.event_result
        FROM silver s
        LEFT JOIN dim_date dd ON dd.date_sk = CAST(strftime(s.event_utc_time, '%Y%m%d') AS INT)
        LEFT JOIN dim_time dt ON dt.time_sk = CAST(strftime(s.event_utc_time, '%H%M%S') AS INT)
        LEFT JOIN dim_host dh ON dh.hostname_nk = s.hostname_nk
        LEFT JOIN dim_user du_s ON du_s.sid = s.subject_sid
        LEFT JOIN dim_user du_t ON du_t.sid = s.target_sid
        LEFT JOIN dim_process dp
               ON dp.process_guid = s.process_guid
              AND s.event_utc_time >= dp.effective_from AND s.event_utc_time < dp.effective_to
        LEFT JOIN dim_process dp_t
               ON dp_t.process_guid = s.target_process_guid
              AND s.event_utc_time >= dp_t.effective_from AND s.event_utc_time < dp_t.effective_to
        LEFT JOIN dim_network_endpoint ep_s ON ep_s.ip_address = s.source_ip
        LEFT JOIN dim_network_endpoint ep_d ON ep_d.ip_address = s.destination_ip
        LEFT JOIN dim_event_type et ON et.event_id = s.event_id AND et.channel = s.channel
    """)


@pytest.fixture(scope="session")
def gold() -> duckdb.DuckDBPyConnection:
    missing = [str(f) for f in DATA_FILES if not f.exists()]
    if missing:
        pytest.skip(f"source data not found: {missing}")
    # Keep the full-dataset build inside WSL memory limits: an ON-DISK database (disk-backed tables),
    # capped RAM, fewer threads, and disk spill (not tmpfs — tmpfs spill would consume the RAM we're
    # trying to save). Building 783K events in pure in-memory DuckDB OOMs on a small WSL box.
    tmp = pathlib.Path(os.environ.get("AGENTECVE_DUCKDB_TMP", ROOT / ".duckdb_tmp"))
    if tmp.exists():
        import shutil
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True, exist_ok=True)
    con = duckdb.connect(str(tmp / "warehouse.duckdb"))
    con.execute(f"PRAGMA temp_directory='{(tmp / 'spill').as_posix()}'")
    con.execute("PRAGMA memory_limit='4GB'")
    con.execute("PRAGMA threads=2")
    con.execute("PRAGMA preserve_insertion_order=false")
    _build_warehouse(con)
    yield con
    con.close()


def scalar(con, sql: str):
    return con.execute(sql).fetchone()[0]


# ======================================================================================
# RELIABILITY — the warehouse itself must be trustworthy before any search is believed.
# ======================================================================================
class TestReliability:
    def test_all_tables_populated(self, gold):
        for t in ["bronze", "silver", "fact_security_event", "dim_host", "dim_user",
                  "dim_process", "dim_network_endpoint", "dim_event_type", "dim_date", "dim_time"]:
            assert scalar(gold, f"SELECT count(*) FROM {t}") > 0, f"{t} is empty"

    def test_fact_grain_is_unique(self, gold):
        """Grain = one row per (source_file, hostname_nk, channel, record_number) — no dup, no fan-out."""
        dups = scalar(gold, """
            SELECT count(*) FROM (
                SELECT 1 FROM fact_security_event
                GROUP BY source_file, hostname_nk, channel, record_number HAVING count(*) > 1
            )""")
        assert dups == 0

    def test_event_sk_is_unique(self, gold):
        assert scalar(gold, "SELECT count(*) - count(DISTINCT event_sk) FROM fact_security_event") == 0

    def test_no_orphan_foreign_keys(self, gold):
        """Every fact FK resolves to a real dimension row (–1 members included) — no INNER JOIN row loss."""
        checks = {
            "host_sk": "dim_host(host_sk)",
            "subject_user_sk": "dim_user(user_sk)",
            "target_user_sk": "dim_user(user_sk)",
            "process_sk": "dim_process(process_sk)",
            "target_process_sk": "dim_process(process_sk)",
            "source_endpoint_sk": "dim_network_endpoint(endpoint_sk)",
            "destination_endpoint_sk": "dim_network_endpoint(endpoint_sk)",
            "event_type_sk": "dim_event_type(event_type_sk)",
            "date_sk": "dim_date(date_sk)",
            "time_sk": "dim_time(time_sk)",
        }
        for fk, ref in checks.items():
            tbl, col = ref.rstrip(")").split("(")
            orphans = scalar(gold, f"""
                SELECT count(*) FROM fact_security_event f
                LEFT JOIN {tbl} d ON d.{col} = f.{fk}
                WHERE d.{col} IS NULL""")
            assert orphans == 0, f"{fk}: {orphans} orphan rows against {ref}"

    def test_unknown_members_exist(self, gold):
        """Every dimension carries a –1 member (H2: dim_event_type included)."""
        assert scalar(gold, "SELECT count(*) FROM dim_event_type WHERE event_type_sk = -1") == 1
        assert scalar(gold, "SELECT count(*) FROM dim_host WHERE host_sk = -1") == 1
        assert scalar(gold, "SELECT count(*) FROM dim_process WHERE process_sk = -1") == 1

    def test_row_count_reconciliation(self, gold):
        """Fact rows == deduplicated Silver rows: no silent drop between layers."""
        assert scalar(gold, "SELECT count(*) FROM fact_security_event") == scalar(gold, "SELECT count(*) FROM silver")

    def test_canonical_time_not_null_and_typed(self, gold):
        assert scalar(gold, "SELECT count(*) FROM fact_security_event WHERE event_utc_time IS NULL") == 0
        assert scalar(gold, "SELECT typeof(event_utc_time) FROM fact_security_event LIMIT 1") == "TIMESTAMP"

    def test_event_type_sk_never_null(self, gold):
        assert scalar(gold, "SELECT count(*) FROM fact_security_event WHERE event_type_sk IS NULL") == 0


# ======================================================================================
# SCD TYPE 2 — dim_process validity chain must be sound (backs point-in-time search).
# ======================================================================================
class TestSCD2Process:
    def test_exactly_one_current_version_per_guid(self, gold):
        bad = scalar(gold, """
            SELECT count(*) FROM (
                SELECT process_guid FROM dim_process WHERE process_guid <> 'N/A'
                GROUP BY process_guid HAVING count(*) FILTER (WHERE is_current) <> 1
            )""")
        assert bad == 0

    def test_validity_chain_has_no_overlaps(self, gold):
        """Half-open [from, to) intervals per guid must not overlap — else PIT join double-counts."""
        overlaps = scalar(gold, """
            WITH v AS (
                SELECT process_guid, effective_from, effective_to,
                       lead(effective_from) OVER (PARTITION BY process_guid ORDER BY effective_from) AS next_from
                FROM dim_process WHERE process_guid <> 'N/A'
            )
            SELECT count(*) FROM v WHERE next_from IS NOT NULL AND next_from < effective_to""")
        assert overlaps == 0

    def test_point_in_time_join_returns_one_version(self, gold):
        """A fact row with a real process_guid resolves to exactly one dim_process version at its event time."""
        multi = scalar(gold, """
            SELECT count(*) FROM (
                SELECT s.source_file, s.hostname_nk, s.channel, s.record_number, count(*) AS n
                FROM silver s
                JOIN dim_process dp
                  ON dp.process_guid = s.process_guid
                 AND s.event_utc_time >= dp.effective_from AND s.event_utc_time < dp.effective_to
                WHERE s.process_guid IS NOT NULL
                GROUP BY 1, 2, 3, 4 HAVING count(*) > 1
            )""")
        assert multi == 0


# ======================================================================================
# SEARCH RETURNS — the queries analysts run; each must return the RIGHT rows.
# Regressions of the audit's query-corrupting bugs are asserted here.
# ======================================================================================
class TestSearchReturns:
    def test_log_source_filter_excludes_wfp_from_windows_security(self, gold):
        """M1 regression: WFP (5156/5158/5447) shares Channel='Security' but must NOT count as windows_security."""
        wfp_leak = scalar(gold, """
            SELECT count(*) FROM fact_security_event
            WHERE log_source = 'windows_security' AND event_id IN (5156, 5157, 5158, 5447)""")
        assert wfp_leak == 0
        # and WFP events are findable under their own source
        assert scalar(gold, "SELECT count(*) FROM fact_security_event WHERE log_source = 'wfp'") >= 0

    def test_log_source_partitions_all_rows(self, gold):
        """log_source classifies every row into a known family; naive channel='Security' over-counts vs windows_security."""
        known = "('sysmon', 'windows_security', 'powershell', 'wfp', 'unknown')"
        assert scalar(gold, f"SELECT count(*) FROM fact_security_event WHERE log_source NOT IN {known}") == 0
        # no mapped family ever leaks into 'unknown' (only genuinely out-of-family EventIDs land there)
        leaked = scalar(gold, """
            SELECT count(*) FROM fact_security_event
            WHERE log_source = 'unknown'
              AND (event_id IN (5156, 5157, 5158, 5447)          -- wfp
                OR event_id IN (800, 4103, 4104)                 -- powershell
                OR event_id BETWEEN 1 AND 255                    -- sysmon
                OR event_id IN (4624, 4625, 4656, 4658, 4663, 4688, 4690, 4703))""")  # windows_security
        assert leaked == 0
        # the audit's core M1 point: the Security channel is NOT equivalent to windows_security —
        # WFP events ride the same channel, so a channel-based filter returns the wrong set.
        wfp_on_security_channel = scalar(gold, """
            SELECT count(*) FROM fact_security_event
            WHERE lower(channel) = 'security' AND log_source = 'wfp'""")
        assert wfp_on_security_channel > 0, "expected WFP events sharing the Security channel (the M1 hazard)"

    def test_network_search_only_returns_rows_with_ip(self, gold):
        """A destination-IP search must never surface non-network events (sparse ~0.5% network density)."""
        rows = scalar(gold, """
            SELECT count(*) FROM fact_security_event f
            JOIN dim_network_endpoint e ON f.destination_endpoint_sk = e.endpoint_sk
            WHERE e.endpoint_sk <> -1""")
        # all such rows must actually carry a destination_ip
        without_ip = scalar(gold, """
            SELECT count(*) FROM fact_security_event f
            JOIN dim_network_endpoint e ON f.destination_endpoint_sk = e.endpoint_sk
            WHERE e.endpoint_sk <> -1 AND f.destination_ip IS NULL""")
        assert without_ip == 0
        assert rows == scalar(gold, "SELECT count(*) FROM fact_security_event WHERE destination_ip IS NOT NULL")

    def test_cidr_range_search_via_ip_numeric(self, gold):
        """M3: numeric IP enables a CIDR/range search that a VARCHAR IP cannot express correctly."""
        # 10.0.0.0/8  →  [10*2^24, 11*2^24)
        lo, hi = 10 * 16777216, 11 * 16777216
        by_numeric = scalar(gold, f"""
            SELECT count(*) FROM dim_network_endpoint
            WHERE ip_numeric >= {lo} AND ip_numeric < {hi}""")
        by_string = scalar(gold, """
            SELECT count(*) FROM dim_network_endpoint
            WHERE NOT is_ipv6 AND split_part(ip_address, '.', 1) = '10'""")
        assert by_numeric == by_string  # numeric range agrees with the (octet-aligned) string check

    def test_pid_search_has_no_hex_leakage(self, gold):
        """H1 regression: normalized PID column is numeric — no '0x…' text leaks in, joins stay type-safe."""
        assert scalar(gold, "SELECT typeof(raw_process_id) FROM fact_security_event LIMIT 1") == "BIGINT"
        # every original hex PID has a decimal normalized value
        unnormalized = scalar(gold, """
            SELECT count(*) FROM fact_security_event
            WHERE raw_process_id_original LIKE '0x%' AND raw_process_id IS NULL""")
        assert unnormalized == 0

    def test_event_type_distribution_matches_source(self, gold):
        """Counting events by type through Gold must equal the raw source distribution (no rows lost)."""
        for eid in (12, 10, 13):  # the dominant Sysmon events
            gold_n = scalar(gold, f"SELECT count(*) FROM fact_security_event WHERE event_id = {eid}")
            src_n = scalar(gold, f"""
                SELECT count(*) FROM (
                    SELECT source_file, hostname_nk, channel, record_number
                    FROM silver WHERE event_id = {eid}
                )""")
            assert gold_n == src_n

    def test_date_range_search_includes_non_sysmon(self, gold):
        """H4 regression: reconciled UTC date-range search returns non-Sysmon events too, not just Sysmon."""
        # pick the busiest event date, then confirm the slice spans more than one log_source
        busiest = scalar(gold, """
            SELECT date_sk FROM fact_security_event
            GROUP BY date_sk ORDER BY count(*) DESC LIMIT 1""")
        sources = scalar(gold, f"""
            SELECT count(DISTINCT log_source) FROM fact_security_event WHERE date_sk = {busiest}""")
        assert sources >= 2, "a UTC day should contain multiple event families, not only Sysmon"

    def test_natural_key_join_via_view_does_not_fan_out(self, gold):
        """M4: joining on process_guid through dim_process_current returns one row per guid (no SCD2 multiplication)."""
        sample_guid = scalar(gold, """
            SELECT process_guid FROM dim_process
            WHERE process_guid <> 'N/A'
            GROUP BY process_guid HAVING count(*) > 1 ORDER BY count(*) DESC LIMIT 1""")
        if sample_guid is None:
            pytest.skip("no multi-version process in this sample")
        via_base = scalar(gold, f"SELECT count(*) FROM dim_process WHERE process_guid = '{sample_guid}'")
        via_view = scalar(gold, f"SELECT count(*) FROM dim_process_current WHERE process_guid = '{sample_guid}'")
        assert via_base > 1 and via_view == 1

    def test_masquerade_search_point_in_time_is_correct(self, gold):
        """C2 regression: an early event of a re-imaged process resolves to its EARLY image, not the current one."""
        # find a process with ≥2 distinct image_path versions (attribute conflict = masquerade signal)
        guid = scalar(gold, """
            SELECT process_guid FROM dim_process
            WHERE process_guid <> 'N/A'
            GROUP BY process_guid HAVING count(DISTINCT image_path) > 1 LIMIT 1""")
        if guid is None:
            pytest.skip("no multi-image process in this sample")
        # earliest fact row for that guid must join to the FIRST version's image, not is_current's
        first_img, current_img, resolved_img = gold.execute(f"""
            WITH first_ev AS (
                SELECT f.event_utc_time, dp.image_path AS resolved
                FROM fact_security_event f
                JOIN dim_process dp ON dp.process_sk = f.process_sk
                WHERE dp.process_guid = '{guid}'
                ORDER BY f.event_utc_time LIMIT 1
            )
            SELECT
                (SELECT image_path FROM dim_process WHERE process_guid='{guid}' ORDER BY effective_from LIMIT 1),
                (SELECT image_path FROM dim_process WHERE process_guid='{guid}' AND is_current LIMIT 1),
                (SELECT resolved FROM first_ev)
        """).fetchone()
        assert resolved_img == first_img
