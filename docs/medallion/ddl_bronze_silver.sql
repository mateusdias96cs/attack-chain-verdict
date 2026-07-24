-- ============================================================================
-- Bronze + Silver DDL — Windows Security Telemetry (Sysmon + Security + PowerShell + WFP)
-- Source: dadosdia1.json (196,081 rows) / dadosdia2.json (587,286 rows) — NDJSON,
--         MITRE ATT&CK "dmevals" / APT29 eval.
-- Platform: ANSI SQL / PostgreSQL-compatible types (portable to Delta/Iceberg with the
--           substitutions noted inline — JSONB -> VARIANT/STRING, IDENTITY -> hash surrogate
--           for parallel-writer lakehouse deployments, INTERVAL -> BIGINT seconds, etc.)
-- Companion doc: docs/medallion/medallion_architecture.md (layer design, DQ gates, load order)
-- Gold DDL (already designed, NOT duplicated here): docs/schema/ddl.sql
-- ============================================================================
-- Conventions:
--   *_raw    = unparsed/lightly-typed Bronze column, no reconciliation applied
--   *_nk     = natural/business key (Silver+)
--   snake_case throughout Silver; Bronze keeps the *_raw suffix to make clear these are
--   landing-only columns, not yet validated or reconciled.
-- ============================================================================


-- ============================================================================
-- SCHEMA SEPARATION
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS bronze_windows_security;
CREATE SCHEMA IF NOT EXISTS silver_windows_security;
-- gold_windows_security schema holds docs/schema/ddl.sql's objects (dim_*, fact_security_event) —
-- created there, referenced here only.


-- ============================================================================
-- BRONZE — raw_windows_security_event
-- Grain: one row = one line of the source NDJSON = one raw ingestion event.
-- Write mode: APPEND ONLY. Never updated, never merged, never hard-deleted.
-- Schema-on-read: only envelope/lineage fields are promoted as typed columns;
-- every other field (the ~90-field union across EventID 1/3/7/8/10/11/12/13/22/23/
-- 4624/4625/4656/4658/4663/4688/4690/4703/800/4103/4104/5156/5158/5447) lives in raw_json.
-- ============================================================================
CREATE TABLE bronze_windows_security.raw_windows_security_event (
    bronze_pk                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    -- On Delta 3.x+: native IDENTITY works as-is.
    -- On Iceberg / parallel writers: replace with a deterministic surrogate, e.g.
    --   bronze_pk BIGINT GENERATED ALWAYS AS (hash(source_file, source_row_number))
    -- so reruns of the same file+line are idempotent.

    -- ---- Lineage / ingestion metadata (required — see medallion-config.yaml) --------
    source_system             VARCHAR(50)   NOT NULL DEFAULT 'windows_security_telemetry',
    source_file                VARCHAR(20)   NOT NULL,     -- 'dadosdia1' | 'dadosdia2'
    source_row_number           BIGINT        NOT NULL,     -- 1-based line ordinal within source_file (NOT the payload's own RecordNumber)
    ingest_batch_id               VARCHAR(64),               -- ETL run id, for incremental reruns
    ingest_timestamp                TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- when this row was landed

    -- ---- Partition-pruning envelope columns (best-effort, NOT reconciled) -----------
    -- FIX H4/M2: renamed event_date -> bronze_partition_date to kill the misleading "event date"
    -- semantics. This column MIXES time zones by design (true-UTC date from UtcTime on Sysmon
    -- rows, UNRECONCILED collector-local date from EventTime on Security/WFP/PowerShell rows —
    -- offset ~UTC-4), so two events 4s apart can land in different partitions in the ~4h/day
    -- window where local and UTC dates diverge.
    --   * DO NOT use bronze_partition_date for cross-source date-range queries or replay/backfill
    --     scoping — it is a coarse physical partition key ONLY. Use Silver.event_date (derived from
    --     the reconciled event_utc_time) for any correct business-date filter.
    --   * FIX M2: NOT NULL with a 1900-01-01 sentinel so parse-error / missing-timestamp rows land
    --     in a known, queryable partition instead of an implicit NULL bucket that predicate pushdown skips.
    bronze_partition_date            DATE          NOT NULL DEFAULT DATE '1900-01-01',
    event_id                          INT,                    -- maps to: EventID (native JSON int, not a coercion)
    channel_raw                        VARCHAR(120),           -- maps to: Channel
    hostname_raw                        VARCHAR(255),          -- maps to: Hostname
    record_number_raw                    BIGINT,               -- maps to: RecordNumber

    -- ---- Timestamp fields, landed as unparsed TEXT (no type coercion at Bronze) -----
    utc_time_raw                          VARCHAR(30),          -- maps to: UtcTime
                                                                 -- NULL on 100% of non-Sysmon-channel rows — expected (see §0 finding)
    event_time_raw                         VARCHAR(30),         -- maps to: EventTime (local/collector time)
    ingest_event_time_raw                   VARCHAR(35),        -- maps to: @timestamp (Logstash ingest time)
    event_received_time_raw                  VARCHAR(30),       -- maps to: EventReceivedTime (NXLog receipt time)

    -- ---- Full raw fidelity ------------------------------------------------------------
    raw_json                                  JSONB,            -- parsed JSON object; NULL if parse_error = TRUE
                                                                  -- Delta 4.x/Iceberg v3: use VARIANT type instead of JSONB
                                                                  -- Older lakehouse targets: STRING + JSON path functions at query time
    raw_line                                   TEXT      NOT NULL,  -- exact original NDJSON line bytes, always populated
    parse_error                                 BOOLEAN   NOT NULL DEFAULT FALSE,
    parse_error_message                          VARCHAR(500)
);

-- Partitioning (lakehouse physical layout — illustrative, not enforced by this ANSI DDL):
--   Delta:   PARTITIONED BY (bronze_partition_date, source_file)
--            TBLPROPERTIES ('delta.autoOptimize.optimizeWrite'='true','delta.autoOptimize.autoCompact'='true')
--   Iceberg: PARTITIONED BY (bronze_partition_date, source_file)   -- or days(ingest_timestamp) for ingestion-date partitioning

-- Postgres-only staging/dev indexes (lakehouse targets rely on partition pruning + file stats
-- instead of B-tree indexes; keep these only if Bronze is materialized in an OLTP store for testing):
CREATE INDEX ix_bronze_event_date_source ON bronze_windows_security.raw_windows_security_event (bronze_partition_date, source_file);
CREATE INDEX ix_bronze_channel_event_id ON bronze_windows_security.raw_windows_security_event (channel_raw, event_id);
CREATE INDEX ix_bronze_hostname ON bronze_windows_security.raw_windows_security_event (hostname_raw);
-- Defensive uniqueness on the physical lineage key (protects against a loader bug double-appending
-- the same file+line — NOT a business dedup key, that is Silver's job on the payload's own natural key):
CREATE UNIQUE INDEX uq_bronze_lineage ON bronze_windows_security.raw_windows_security_event (source_file, source_row_number);


-- ============================================================================
-- SILVER — cleansed_security_event
-- Grain: one row = one raw event, deduplicated and typed. Same grain as Bronze and as
-- Gold's fact_security_event.
-- Write mode: incremental MERGE (upsert) on the natural key below.
-- Natural key / dedup key (see medallion_architecture.md §0, §5.1 for the empirical
-- validation): (source_file, hostname_nk, channel, record_number).
--   - Unique WITHIN each source file (confirmed: 196,081/196,081 and 587,286/587,286
--     distinct triples of (Hostname, Channel, RecordNumber)).
--   - NOT unique ACROSS files (1,631 collisions confirmed to be different real events) —
--     source_file is a required key component, not defensive redundancy.
-- ============================================================================
CREATE TABLE silver_windows_security.cleansed_security_event (
    silver_event_id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,  -- Silver-internal surrogate; NOT Gold's event_sk

    -- ---- Natural key / dedup / lineage ------------------------------------------------
    source_file                    VARCHAR(20)   NOT NULL,
    hostname_nk                     VARCHAR(100)  NOT NULL,     -- parsed short host name, e.g. 'SCRANTON'
    hostname_fqdn                    VARCHAR(255)  NOT NULL,    -- raw Hostname, e.g. 'SCRANTON.dmevals.local'
    channel                           VARCHAR(80)   NOT NULL,   -- maps to: Channel
    record_number                      BIGINT        NOT NULL,  -- maps to: RecordNumber
    _bronze_source_row_number             BIGINT,               -- lineage back to Bronze

    -- ---- Event classification ---------------------------------------------------------
    event_id                                INT           NOT NULL,   -- maps to: EventID
    log_source                               VARCHAR(20)   NOT NULL,  -- 'sysmon'|'windows_security'|'powershell'|'wfp'
                                                                       -- derived from EventID ranges, NOT Channel alone —
                                                                       -- WFP (5156/5158/5447) shares Channel='Security' with
                                                                       -- windows_security EventIDs (confirmed by sampling)

    -- ---- Reconciled timestamps (see medallion_architecture.md §5.2) -------------------
    event_utc_time                            TIMESTAMP     NOT NULL,  -- canonical: UtcTime (Sysmon) or calibrated EventTime (else)
    -- FIX H3: materialized partition column the partitioning clause below actually requires.
    -- Delta needs a real (generated) column — it has no Iceberg-style hidden partition transform.
    -- Derived from the RECONCILED event_utc_time, so (unlike Bronze.bronze_partition_date) this IS
    -- the correct business date and IS safe for cross-source date-range queries.
    event_date                                DATE          GENERATED ALWAYS AS (CAST(event_utc_time AS DATE)) STORED,
    event_local_time                           TIMESTAMP,              -- maps to: EventTime, cast
    ingest_event_time                           TIMESTAMP,             -- maps to: @timestamp, cast
    event_received_time                          TIMESTAMP,            -- maps to: EventReceivedTime, cast
    file_creation_utc_time                        TIMESTAMP,           -- maps to: CreationUtcTime (EventID 11 only)
    time_source_flag                               VARCHAR(25)   NOT NULL DEFAULT 'utc_time_native',
                                                                        -- 'utc_time_native' | 'event_time_calibrated' | 'unresolved'
    tz_offset_applied_seconds                       INT,               -- audit: offset (seconds) applied when calibrated;
                                                                        -- INT seconds chosen over INTERVAL for lakehouse portability

    -- ---- Host / collector ---------------------------------------------------------------
    collector_host                                    VARCHAR(255),    -- maps to: host (NXLog/Logstash shipper identity)
    collector_port                                     INT,            -- maps to: port

    -- ---- User identity (role-neutral at Silver; Gold resolves subject/target roles) -----
    subject_sid                                         VARCHAR(184),  -- coalesced: UserID | SubjectUserSid | RemoteUserID
    subject_account_name                                 VARCHAR(100), -- coalesced: AccountName | SubjectUserName
    subject_domain                                        VARCHAR(100),-- coalesced: Domain | SubjectDomainName
    subject_account_type                                   VARCHAR(30),-- maps to: AccountType
    target_sid                                              VARCHAR(184),  -- maps to: TargetUserSid (logon events only)
    target_account_name                                      VARCHAR(100), -- maps to: TargetUserName
    target_domain                                             VARCHAR(100), -- maps to: TargetDomainName

    -- ---- Process (acting role) — natural key = process_guid; Sysmon-channel only --------
    process_guid                                               VARCHAR(38),   -- maps to: ProcessGuid
    process_id                                                  BIGINT,       -- normalized decimal PID (from Sysmon decimal-string ProcessId)
    image_path                                                   VARCHAR(500),-- maps to: Image
    image_name                                                    VARCHAR(260),-- derived basename of image_path
    company                                                        VARCHAR(200),
    product                                                         VARCHAR(200),
    description                                                      VARCHAR(500),
    original_file_name                                                VARCHAR(260),
    file_version                                                       VARCHAR(100),
    command_line                                                        VARCHAR(4000),
    current_directory                                                    VARCHAR(500),
    integrity_level                                                       VARCHAR(20),
    hash_sha1                                                              CHAR(40),   -- parsed from Hashes "SHA1=..."
    hash_md5                                                                CHAR(32),  -- parsed from Hashes "MD5=..."
    hash_sha256                                                              CHAR(64), -- parsed from Hashes "SHA256=..."
    hash_imphash                                                              CHAR(32),-- parsed from Hashes "IMPHASH=..."
    parent_process_guid                                                        VARCHAR(38),
    parent_process_id                                                           BIGINT,
    parent_image                                                                 VARCHAR(500),
    parent_command_line                                                           VARCHAR(4000),
    logon_guid                                                                     VARCHAR(38),
    terminal_session_id                                                             VARCHAR(10),

    -- ---- Process (target/acted-upon role — EventID 8/10) ---------------------------------
    target_process_guid                                                              VARCHAR(38),  -- maps to: TargetProcessGUID
    target_process_id                                                                 BIGINT,       -- normalized
    target_image                                                                       VARCHAR(500),-- maps to: TargetImage
    granted_access                                                                      VARCHAR(20),-- maps to: GrantedAccess (hex)
    call_trace                                                                           VARCHAR(4000),
    source_thread_id                                                                      INT,
    target_thread_id                                                                       INT,
    new_thread_id                                                                           INT,

    -- ---- Security-channel process fallback (no ProcessGuid; see process_correlation_bridge)
    raw_process_image                                                                        VARCHAR(500), -- maps to: NewProcessName | ProcessName | Application
    raw_process_id                                                                            BIGINT,       -- normalized decimal (from hex "0x..." or decimal string)
    raw_process_id_original                                                                    VARCHAR(20), -- original text, preserved for audit (rule #11)
    raw_parent_process_image                                                                    VARCHAR(500),-- maps to: ParentProcessName
    raw_parent_process_id                                                                        BIGINT,     -- normalized decimal

    -- ---- Network (EventID 3 Sysmon NetworkConnect + 5156/5158/5447 WFP; ~0.5% density) ----
    source_ip                                                                                     VARCHAR(45),  -- coalesced: SourceIp | SourceAddress
    source_is_ipv6                                                                                 BOOLEAN,     -- maps to: SourceIsIpv6 (text 'true'/'false' cast)
    destination_ip                                                                                  VARCHAR(45),-- coalesced: DestinationIp | DestAddress
    destination_is_ipv6                                                                              BOOLEAN,   -- maps to: DestinationIsIpv6
    source_port                                                                                       INT,      -- maps to: SourcePort (text cast to INT)
    destination_port                                                                                   INT,     -- coalesced: DestinationPort | DestPort
    network_protocol                                                                                    VARCHAR(10), -- normalized lowercase 'tcp'/'udp' (Sysmon text or WFP numeric '6'/'17')
    network_direction                                                                                    VARCHAR(10), -- normalized 'inbound'/'outbound' (Sysmon Initiated bool or WFP %%code via ref_windows_message_code)
    network_action                                                                                        VARCHAR(10), -- 'allowed' for EventID 5156, etc.

    -- ---- File (EventID 11, 23) --------------------------------------------------------------
    target_filename                                                                                        VARCHAR(1000), -- maps to: TargetFilename
    file_is_executable                                                                                      BOOLEAN,       -- maps to: IsExecutable (text cast)
    file_archived                                                                                            BOOLEAN,      -- maps to: Archived (text cast)

    -- ---- Registry (EventID 12, 13, 4663 Key objects) -----------------------------------------
    registry_target_object                                                                                    VARCHAR(1000), -- maps to: TargetObject
    registry_details                                                                                           VARCHAR(2000), -- maps to: Details
    registry_action                                                                                             VARCHAR(20),  -- parsed sub-type from EventType/Message (CreateKey/DeleteKey/SetValue)

    -- ---- DNS (EventID 22) --------------------------------------------------------------------
    dns_query_name                                                                                              VARCHAR(500),
    dns_query_status                                                                                             VARCHAR(10),
    dns_query_results                                                                                            VARCHAR(2000),

    -- ---- Object access / Security auditing (4656, 4658, 4663, 4690, 4703) ---------------------
    object_name                                                                                                   VARCHAR(1000),
    object_type                                                                                                    VARCHAR(50),
    handle_id                                                                                                       VARCHAR(20),
    access_mask                                                                                                      VARCHAR(20),
    access_list                                                                                                       VARCHAR(500),

    -- ---- Logon (4624, 4625) --------------------------------------------------------------------
    logon_type                                                                                                        INT,
    logon_id                                                                                                           VARCHAR(20),
    authentication_package                                                                                              VARCHAR(50),
    elevated_token                                                                                                       BOOLEAN, -- decoded via ref_windows_message_code ('%%1842'-style)
    workstation_name                                                                                                      VARCHAR(100),

    -- ---- PowerShell (800, 4103, 4104) ------------------------------------------------------------
    script_block_text                                                                                                     VARCHAR(8000),
    script_block_id                                                                                                        VARCHAR(38),
    message_number                                                                                                          INT,
    message_total                                                                                                           INT,

    -- ---- Generic / lineage -----------------------------------------------------------------------
    message_raw                                                                                                             TEXT,
    rule_name                                                                                                                VARCHAR(200),
    severity                                                                                                                  VARCHAR(10),
    event_result                                                                                                              VARCHAR(20),
    opcode                                                                                                                     VARCHAR(20),

    -- ---- Silver metadata / DQ ---------------------------------------------------------------------
    _created_at                                                                                                                TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    _updated_at                                                                                                                 TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    dq_status                                                                                                                   VARCHAR(25) NOT NULL DEFAULT 'passed',  -- 'passed'|'passed_with_warnings'|'quarantined'
    dq_failed_rules                                                                                                              VARCHAR(500), -- comma-separated rule names (see medallion_architecture.md §4.1), NULL when dq_status='passed'

    CONSTRAINT uq_silver_event_nk UNIQUE (source_file, hostname_nk, channel, record_number)
);

CREATE INDEX ix_silver_event_utc_time ON silver_windows_security.cleansed_security_event (event_utc_time);
CREATE INDEX ix_silver_hostname_channel ON silver_windows_security.cleansed_security_event (hostname_nk, channel);
CREATE INDEX ix_silver_process_guid ON silver_windows_security.cleansed_security_event (process_guid) WHERE process_guid IS NOT NULL;
CREATE INDEX ix_silver_event_id ON silver_windows_security.cleansed_security_event (event_id);

-- Partitioning (lakehouse physical layout) — FIX H3: now partitions on the concrete generated
-- event_date column declared above (business date from reconciled event_utc_time, NOT ingestion date):
--   Delta:   PARTITIONED BY (event_date)                    -- the STORED generated column above
--   Iceberg: PARTITIONED BY days(event_utc_time)            -- hidden transform (event_date column optional)


-- ============================================================================
-- SILVER — security_event_quarantine
-- Same shape as cleansed_security_event (minus strict NOT NULL constraints) plus DQ
-- failure metadata. Rows failing a CRITICAL rule from medallion_architecture.md §4.1
-- land here instead of the main table. Never silently dropped.
-- ============================================================================
CREATE TABLE silver_windows_security.security_event_quarantine (
    LIKE silver_windows_security.cleansed_security_event INCLUDING DEFAULTS,
    -- LIKE ... INCLUDING DEFAULTS is Postgres-specific convenience; on a lakehouse target,
    -- materialize the equivalent column list explicitly (CTAS from cleansed_security_event's schema).
    _quarantined_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    _quarantine_reason        VARCHAR(500) NOT NULL
);


-- ============================================================================
-- SILVER — process_correlation_bridge
-- Probabilistic PID <-> ProcessGuid correlation for Security/WFP-channel rows (no native
-- ProcessGuid available — see medallion_architecture.md §5.3, implements the enrichment
-- opportunity flagged but explicitly deferred by star_schema.md §6.3).
-- OPTIONAL / investigative only. Does NOT feed fact_security_event.process_sk, which
-- remains -1 for these rows per the committed Gold contract in docs/schema/ddl.sql.
-- ============================================================================
CREATE TABLE silver_windows_security.process_correlation_bridge (
    bridge_id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_file                  VARCHAR(20)  NOT NULL,
    hostname_nk                   VARCHAR(100) NOT NULL,
    channel                        VARCHAR(80)  NOT NULL,
    record_number                   BIGINT       NOT NULL,   -- ties back to cleansed_security_event's natural key
    event_utc_time                    TIMESTAMP    NOT NULL,
    raw_process_id                     BIGINT       NOT NULL,  -- normalized decimal PID being resolved
    candidate_process_guid              VARCHAR(38),           -- resolved Sysmon ProcessGuid; NULL if unmatched
    match_method                         VARCHAR(30)  NOT NULL, -- 'pid_time_window_unique'|'pid_time_window_ambiguous'|'unmatched'
    match_confidence                      VARCHAR(10)  NOT NULL,-- 'high'|'low'|'none'
    candidate_window_seconds               INT,                -- lease-window size used (audit; see §5.3 ProcessTerminate caveat)
    computed_at                             TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_bridge_nk UNIQUE (source_file, hostname_nk, channel, record_number)
);

CREATE INDEX ix_bridge_candidate_guid ON silver_windows_security.process_correlation_bridge (candidate_process_guid) WHERE candidate_process_guid IS NOT NULL;


-- ============================================================================
-- SILVER — ref_windows_message_code
-- Static reference/lookup table for Windows Event Log "%%NNNNN"-style message codes
-- observed in the raw data (e.g. Direction "%%14592" on WFP events, ElevatedToken "%%1842",
-- TokenElevationType "%%1938"). Seeded from Microsoft's published Security-auditing
-- message-string table — an external, authoritative source, intentionally NOT populated
-- with guessed values in this DDL (see medallion_architecture.md §8 confidence note).
-- ============================================================================
CREATE TABLE silver_windows_security.ref_windows_message_code (
    message_code       VARCHAR(10)  NOT NULL,   -- e.g. '%%14592'
    code_domain          VARCHAR(50)  NOT NULL, -- e.g. 'wfp_direction' | 'elevated_token' | 'token_elevation_type'
    meaning                VARCHAR(100) NOT NULL,-- e.g. 'Inbound'
    CONSTRAINT pk_ref_windows_message_code PRIMARY KEY (message_code, code_domain)
);
-- Seed rows intentionally omitted here — populate from the authoritative Microsoft source
-- before enabling the network_direction / elevated_token normalization rules in the
-- Bronze -> Silver transformation job.


-- ============================================================================
-- SILVER — quality audit log (mirrors medallion-config.yaml's quality.audit_log pattern)
-- ============================================================================
CREATE TABLE silver_windows_security.dq_audit_log (
    check_id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    layer                 VARCHAR(20)  NOT NULL,   -- 'bronze_to_silver' | 'silver_to_gold'
    table_name              VARCHAR(100) NOT NULL,
    rule_name                 VARCHAR(100) NOT NULL,  -- see medallion_architecture.md §4.1 rule names
    total_records                BIGINT       NOT NULL,
    passed_records                  BIGINT       NOT NULL,
    failed_records                    BIGINT       NOT NULL,
    pass_rate                           DECIMAL(6,5) NOT NULL,
    threshold                             DECIMAL(6,5) NOT NULL,
    severity                                VARCHAR(10)  NOT NULL,  -- 'critical'|'warning'|'info'
    gate_passed                               BOOLEAN      NOT NULL,
    checked_at                                  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- End of Bronze/Silver DDL.
-- Next stage: Gold — see docs/schema/ddl.sql (dim_date, dim_time, dim_host, dim_user,
-- dim_process, dim_network_endpoint, dim_event_type, fact_security_event) and
-- docs/medallion/medallion_architecture.md §6 for load order, surrogate key generation,
-- and late-arriving dimension handling.
-- ============================================================================
