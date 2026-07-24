# Medallion Architecture — Windows Security Telemetry (Sysmon + Security + PowerShell + WFP)

> **Scope:** Bronze and Silver layer design that lands the already-designed Gold star schema
> (`docs/schema/star_schema.md`, `docs/schema/ddl.sql`).
> **Source:** `dadosdia1.json` (196,081 rows), `dadosdia2.json` (587,286 rows) — NDJSON, MITRE
> ATT&CK "dmevals" / APT29 evaluation dataset. Grounded in `docs/data_profile.md` **and** direct
> sampling/validation of the raw files performed while writing this document (see §0).
> **Platform:** ANSI SQL / PostgreSQL-compatible DDL types; physical target is a lakehouse table
> format (Delta Lake or Iceberg on Parquet) — format-specific syntax (partitioning, MERGE,
> Z-order/liquid clustering) is called out separately, not hard-required to a single vendor.
> **KB grounding:** medallion/concepts/{bronze,silver,gold}-layer.md, medallion/patterns/
> {layer-transitions,data-quality-gates,incremental-loading,schema-evolution}.md,
> medallion/specs/medallion-config.yaml, data-modeling/concepts/scd-types.md.

---

## 0. Findings From Direct Raw-Data Validation (new, not in the prior docs)

Before finalizing the layer design, three open questions flagged in `star_schema.md` were
resolved by sampling and lightweight full-file scans of both NDJSON files (script left in
scratchpad, not committed):

| Question (from star_schema.md) | Finding | Evidence |
|---|---|---|
| Is `UtcTime` present on 100% of Security/WFP rows? | **No.** `UtcTime` is emitted **only** on `Channel = "Microsoft-Windows-Sysmon/Operational"`. All Security-channel EventIDs (4624/4625/4656/4658/4663/4688/4690/4703) **and** all WFP EventIDs (5156/5158/5447, which also carry `Channel = "Security"`) **and** all PowerShell EventIDs (800/4103/4104) never have a `UtcTime` key at all. | Direct sampling of EventID 1/3/10/11/13/22/23 (all have `UtcTime`) vs. 4688/4624/4663/5156/800/4103/4104 (none have `UtcTime`). |
| Are `RecordNumber` sequences disjoint across `dadosdia1.json`/`dadosdia2.json`? | **No — confirmed non-disjoint.** Within each file, `(Hostname, Channel, RecordNumber)` is 100% unique (196,081/196,081 and 587,286/587,286 distinct). **Across** the two files, 1,631 `(Hostname, Channel, RecordNumber)` triples collide, and spot-checking collisions shows they are **different real events** (different `EventID`, different `UtcTime`) that happen to share a recycled `RecordNumber` because the two files come from separate collection windows. `source_file` is therefore a **required**, non-optional component of the dedup/natural key — it is not defensive redundancy. | Full-file scan of both files; example: `(SCRANTON.dmevals.local, Microsoft-Windows-Sysmon/Operational, 346760)` = EventID 12 @ `2020-05-02 02:56:14.969` in day1 vs. EventID 10 @ `2020-05-02 08:22:09.687` in day2. |
| Does WFP share `Channel` with Windows Security auditing? | **Yes.** EventID 5156/5158/5447 (WFP) are emitted on `Channel = "Security"` — the **same** channel string as 4624/4625/4656/4658/4663/4688/4690/4703. `log_source` (`sysmon`/`windows_security`/`powershell`/`wfp`) **cannot** be derived from `Channel` alone for the Security-channel rows; it must branch on `EventID` ranges. | Direct sampling of a `EventID:5156` record: `"Channel":"Security"`. |

Two additional field-level facts, confirmed by sampling, that shape the Silver typing rules:

- **`EventTime` is local time (observed offset UTC-4 in this dataset), `UtcTime`/`@timestamp` are
  UTC.** Confirmed by comparing `EventTime`/`UtcTime` on the same Sysmon record
  (`EventTime: 2020-05-01 22:55:23` vs. `UtcTime: 2020-05-02 02:55:23.551`). The offset is **not**
  hardcoded in this design — see §3.3.
- **`ProcessId`/`NewProcessId` have two incompatible textual encodings depending on source:**
  Sysmon emits decimal strings (`"ProcessId":"8524"`), Security/WFP emit hex strings
  (`"NewProcessId":"0x214c"`, `"ProcessId":"0x1158"`). Both must be normalized to a common
  `BIGINT` in Silver; the Gold DDL's `raw_process_id VARCHAR(20)` comment already anticipated this
  ("hex string, e.g. '0x214c'") — Silver is where the two encodings are actually reconciled.

---

## 1. Data-Flow Overview

```
                                   RAW NDJSON (append-only files)
                                   dadosdia1.json (196,081 lines)
                                   dadosdia2.json (587,286 lines)
                                              │
                                              │  1 line = 1 JSON object = 1 Windows Event Log record
                                              ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  BRONZE  —  bronze_windows_security.raw_windows_security_event                     │
│  Append-only · schema-on-read · full raw fidelity (raw_line + raw_json)            │
│  + envelope columns for partition pruning (event_date, source_file, channel_raw,   │
│    event_id, hostname_raw, record_number_raw)                                      │
│  + lineage metadata (source_file, source_row_number, ingest_timestamp)             │
│  Partitioned by (event_date, source_file)                                          │
└───────────────────────────────────────┬──────────────────────────────────────────┘
                                         │  Bronze→Silver quality gate (structural — §4)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  SILVER  —  silver_windows_security.cleansed_security_event                        │
│  Typed · snake_case · deduplicated on (source_file, hostname_nk, channel,          │
│  record_number) · UtcTime/EventTime reconciled → event_utc_time · Hashes parsed ·  │
│  ProcessId hex/decimal normalized · network/registry/logon/PowerShell columns      │
│  typed · DQ-gated (passed / quarantined)                                           │
│                                                                                     │
│  + silver_windows_security.process_correlation_bridge (probabilistic PID↔ProcessGuid│
│    correlation for Security/WFP-channel rows — see §5)                             │
│  + silver_windows_security.security_event_quarantine (failed DQ rows)              │
│  + silver_windows_security.ref_windows_message_code (static %%code lookup)         │
│  Partitioned by event_date (business date, not ingestion date)                     │
└───────────────────────────────────────┬──────────────────────────────────────────┘
                                         │  Silver→Gold quality gate (referential — §4)
                                         ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│  GOLD  —  star schema (docs/schema/ddl.sql, already designed — referenced here)    │
│                                                                                     │
│   dim_date · dim_time · dim_event_type   (Type 0, static seeds — load first)       │
│   dim_host · dim_user · dim_network_endpoint  (Type 1 — load second, from Silver    │
│                                              DISTINCT extracts)                     │
│   dim_process                            (Type 2 SCD — load third, ordered by      │
│                                            event_utc_time per process_guid)         │
│   fact_security_event                    (load last — resolves all FKs by lookup,  │
│                                            defaults to -1 "Unknown" member)         │
└──────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Table Naming & Schema Separation

Following the KB naming convention (`medallion/quick-reference.md`), adapted to this single
domain ("windows_security"):

| Layer | Schema/database | Table pattern | Concrete tables |
|---|---|---|---|
| Bronze | `bronze_windows_security` | `raw_{source}_{entity}` | `raw_windows_security_event` |
| Silver | `silver_windows_security` | `cleansed_{entity}` | `cleansed_security_event`, `process_correlation_bridge`, `security_event_quarantine`, `ref_windows_message_code` |
| Gold | `gold_windows_security` (existing `docs/schema/ddl.sql`, unqualified in that file) | `dim_{entity}` / `fact_{entity}` | `dim_date`, `dim_time`, `dim_host`, `dim_user`, `dim_process`, `dim_network_endpoint`, `dim_event_type`, `fact_security_event` |

**Bronze is one table, not four** (one per source family), even though the KB pattern is
`raw_{source}_{entity}`. Rationale: unlike a typical multi-source Bronze estate where each source
system has its own ingestion cadence/contract, all four telemetry families here arrive through
**one physical pipeline** (NXLog `im_msvistalog` → Logstash → the same two NDJSON files),
discriminated in-record by `EventID`/`Channel`, not by separate source connections. Splitting
Bronze by source would require parsing `EventID` before landing — which violates "never transform
in Bronze." A single `raw_windows_security_event` table with `event_id`/`channel_raw` promoted as
filterable envelope columns achieves the same partition-pruning benefit without any parsing logic
in the Bronze write path.

---

## 3. Bronze Layer

**Table:** `bronze_windows_security.raw_windows_security_event`
**Purpose:** land every line of both NDJSON files with zero data loss, zero transformation,
full replay capability.

### 3.1 Schema

| Column | Type | Source | Notes |
|---|---|---|---|
| `bronze_pk` | `BIGINT IDENTITY` | generated | Postgres-style surrogate; on Delta/Iceberg, omit or replace with a deterministic hash of `(source_file, source_row_number)` — see §7.2 |
| `source_system` | `VARCHAR(50)` | constant `'windows_security_telemetry'` | required KB metadata column |
| `source_file` | `VARCHAR(20) NOT NULL` | which NDJSON file | `'dadosdia1'` \| `'dadosdia2'` |
| `source_row_number` | `BIGINT NOT NULL` | 1-based line ordinal in that file | lineage / exact-replay key, distinct from the payload's own `RecordNumber` |
| `ingest_timestamp` | `TIMESTAMP NOT NULL DEFAULT now()` | ingestion wall-clock | required by task spec |
| `ingest_batch_id` | `VARCHAR(64)` | ETL run id | optional but recommended for incremental reruns |
| `event_date` | `DATE` | best-effort date part of `UtcTime` (Sysmon rows) else `EventTime` | **partition column only** — not validated/reconciled here; Silver owns the authoritative `event_utc_time` |
| `event_id` | `INT` | `EventID` (native JSON int — landing it typed is not "coercion", the source already emits an int) | |
| `channel_raw` | `VARCHAR(120)` | `Channel` | |
| `hostname_raw` | `VARCHAR(255)` | `Hostname` | |
| `record_number_raw` | `BIGINT` | `RecordNumber` | |
| `utc_time_raw` | `VARCHAR(30)` | `UtcTime` (text, unparsed) | **NULL on all non-Sysmon-channel rows** — expected, not an error (§0) |
| `event_time_raw` | `VARCHAR(30)` | `EventTime` (text, unparsed) | |
| `ingest_event_time_raw` | `VARCHAR(35)` | `@timestamp` (text, unparsed) | |
| `event_received_time_raw` | `VARCHAR(30)` | `EventReceivedTime` (text, unparsed) | |
| `raw_json` | `JSONB` (Postgres) / `VARIANT` (Delta 4.x, Iceberg v3) / `STRING` fallback | the full parsed JSON object | primary machine-queryable copy of the record |
| `raw_line` | `TEXT NOT NULL` | the exact original NDJSON line bytes | defensive fidelity — survives if `raw_json` re-serialization would ever normalize something (key order, float formatting); also the only usable copy for lines that fail JSON parsing |
| `parse_error` | `BOOLEAN NOT NULL DEFAULT FALSE` | set by the loader | line landed even if JSON-invalid — never dropped |
| `parse_error_message` | `VARCHAR(500)` | loader-captured exception text | NULL when `parse_error = FALSE` |

No other field is promoted. The ~90-field union across all EventIDs (process, file, registry,
network, logon, PowerShell attributes — full list in `star_schema.md` §10) lives entirely inside
`raw_json`/`raw_line` at this layer; that is the point of schema-on-read.

### 3.2 Partitioning

`PARTITION BY (event_date, source_file)`.

- `event_date` gives natural time-range pruning (only 2 calendar dates in this dataset:
  2020-05-01/02, but the pattern generalizes to a continuously-loaded pipeline).
- `source_file` is kept as a **second** partition key, not folded into `event_date`, because the
  two files are separate ingestion batches with separate lineage/replay semantics (§0) even when
  their `event_date` values overlap — reprocessing "just `dadosdia2`" must be a partition-scoped
  operation, not a full-date rewrite.
- Delta: `PARTITIONED BY (event_date, source_file)` with `'delta.autoOptimize.optimizeWrite'='true'`,
  `'delta.autoOptimize.autoCompact'='true'` (small-file problem is real here — each Bronze write
  batch is one file-load event).
- Iceberg: `PARTITIONED BY (event_date, source_file)` (Iceberg hidden partitioning also allows
  `days(ingest_timestamp)` if ingestion-date partitioning is preferred operationally).

### 3.3 Transformations

**None**, per the medallion Bronze contract (`medallion/concepts/bronze-layer.md` "Wrong —
Transforming Data in Bronze"). The only non-identity operations are: (1) JSON parse (for
`raw_json`) with a fallback to `parse_error=TRUE` + `raw_json=NULL` rather than a rejected write,
and (2) the best-effort `event_date` partition derivation, which is a coarse substring/cast, not a
timezone reconciliation (that is explicitly Silver's job — see §0's `UtcTime`/`EventTime` finding).

### 3.4 Load Strategy

**Full append, always.** `write_mode = append` (per `medallion-config.yaml`). Each of the two
source files is loaded exactly once as a batch job (`source_file` + `source_row_number` make the
load idempotent — a rerun with the same file can be deduplicated on that pair before Silver even
runs, or the loader can `TRUNCATE + reload` a single `source_file` partition for a full redo
without touching the other file's partition). No merge/upsert logic belongs at this layer — Bronze
never updates a row in place (`Common Pitfalls`: "Hard-delete in Bronze" / "Skip deduplication in
Silver" — deduplication is explicitly deferred to Silver, not attempted here).

### 3.5 Shift-Left Structural Validation (not a transformation)

Per `medallion/concepts/bronze-layer.md` "Shift-Left Quality at Bronze": validate structure, not
content, before writing:
- File is non-empty NDJSON.
- Every line parses as valid JSON, OR is captured with `parse_error=TRUE` (never silently
  dropped).
- `EventID` key exists on the parsed object (if `raw_json` parsed successfully) — if absent, still
  land the row; flag via `parse_error_message = 'missing EventID'` for Silver-layer triage.

This is a sanity check, not a business rule (`amount > 0`-style rules are explicitly a Silver
concern).

---

## 4. Data-Quality Gates Between Layers

| Gate | Location | Enforcement | Action on failure |
|---|---|---|---|
| Structural (parseable JSON, non-empty file) | Bronze write path | Hard block only if the **entire file** is unparseable/empty; per-row failures still land with `parse_error=TRUE` | Row lands in Bronze regardless; excluded from Silver's `event_id IN (valid set)` gate downstream |
| Business/type validation (Silver DQ table §4.1) | Bronze → Silver | `threshold` per rule (see table below); rows failing any **critical** rule route to `security_event_quarantine` instead of `cleansed_security_event` | Logged to a quality audit table (mirrors `medallion-config.yaml`'s `quality.audit_log` pattern); does not halt the pipeline (`halt_on_failure=false`) unless the aggregate pass rate for a critical rule drops below threshold |
| Referential readiness (Silver → Gold) | Silver → Gold | Every dimension lookup must resolve to a real surrogate key or the reserved `-1` "Unknown" member (`star_schema.md` §7) — enforced by the Gold load SQL itself (`LEFT JOIN ... COALESCE(dim.sk, -1)`), not by Silver | None — Gold guarantees zero row loss by construction via the `-1` default member convention already defined in `ddl.sql` |

### 4.1 Silver Data-Quality Expectations

| # | Rule name | Column(s) | Check | Threshold | Severity | Rationale |
|---|---|---|---|---|---|---|
| 1 | `event_id_not_null` | `event_id` | not null | 1.00 | critical | Grain-defining field |
| 2 | `event_id_in_valid_set` | `event_id` | `IN (1,3,7,8,10,11,12,13,22,23,4624,4625,4656,4658,4663,4688,4690,4703,800,4103,4104,5156,5158,5447)` | 0.999 | warning | Anything outside the known set from `data_profile.md` is either a new legitimate EventID (schema evolution — §7.3) or corruption; never dropped, always flagged |
| 3 | `hostname_not_null` | `hostname_raw` → `hostname_nk` | not null, non-empty | 1.00 | critical | Profile confirms `Hostname` observed on 100% of sampled events; a null here indicates a structurally broken record |
| 4 | `hostname_in_known_set` | `hostname_nk` | `IN` the 4 observed hosts (`SCRANTON`,`NEWYORK`,`NASHUA`,`UTICA`) | 0.999 | info | New hostnames aren't wrong (host could be added to the eval), just worth flagging for `dim_host` growth |
| 5 | `record_number_not_null` | `record_number` | not null, castable to `BIGINT` | 1.00 | critical | Natural-key component |
| 6 | `dedup_key_unique` | `(source_file, hostname_nk, channel, record_number)` | unique after `ROW_NUMBER()` dedup | 1.00 | critical | See §0 finding — enforced via `UNIQUE` constraint on `cleansed_security_event`; violated rows route to quarantine, not silently merged |
| 7 | `event_utc_time_resolved` | `event_utc_time` | not null after reconciliation (§3.3 logic: `UtcTime` for Sysmon-channel, calibrated `EventTime` otherwise) | 1.00 | critical | Every downstream `date_sk`/`time_sk` join depends on this; should be 0 failures given §0's findings, any failure means both `UtcTime` and `EventTime` were absent — genuinely corrupt record |
| 8 | `time_source_flag_set` | `time_source_flag` | `IN ('utc_time_native','event_time_calibrated')`, never `'unresolved'` at scale | 0.999 | warning | Surfaces calibration drift/DST edge cases early |
| 9 | `channel_in_known_set` | `channel` | `IN ('Microsoft-Windows-Sysmon/Operational','Security','Windows PowerShell','Microsoft-Windows-PowerShell/Operational')` | 0.999 | warning | Matches the 4 observed channels; note WFP shares `'Security'` with Windows Security auditing (§0) |
| 10 | `process_guid_format` | `process_guid` | when present, matches `^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$` | 0.999 | warning | Only populated for Sysmon-channel rows by construction |
| 11 | `process_id_normalizable` | `raw_process_id_original` | parses under **either** decimal-string (Sysmon) **or** `0x`-hex-string (Security/WFP) format | 0.995 | warning | Confirmed dual-encoding in §0 — anything matching neither format is a genuine anomaly |
| 12 | `ip_format_valid` | `source_ip`, `destination_ip` | when non-null (only ~0.4–0.6% of rows per profile), matches IPv4 or IPv6 regex | 0.99 | warning | Sparse but must be clean when present — feeds `dim_network_endpoint` |
| 13 | `subject_identity_present` | `subject_sid` OR `subject_account_name` | at least one non-null | 0.995 | warning | Guarantees `dim_user` lookup never needs a bare NULL; residual gap defaults to the `-1` Unknown member in Gold, not dropped |
| 14 | `hash_fields_well_formed` | `hash_sha1/md5/sha256/imphash` | when parsed from `Hashes`, correct fixed hex length (40/32/64/32) | 0.99 | info | Parsing bug detector for the `SHA1=...,MD5=...,...` split logic |
| 15 | `network_port_range` | `source_port`, `destination_port` | `0–65535` when non-null | 0.999 | warning | Basic sanity on parsed network fields |
| 16 | `no_cross_batch_key_collision` | `(hostname_nk, channel, record_number)` without `source_file` | count of rows sharing this partial key `> 1` is expected and monitored, not treated as a dedup failure | n/a (informational) | info | Documents the §0 finding operationally — an audit view, not a blocking rule; guards against a future refactor accidentally dropping `source_file` from the key |

Rows failing any **critical** rule are written to `security_event_quarantine` (same shape as the
main table plus `dq_failed_rules`) instead of `cleansed_security_event`; `warning`/`info` failures
are still loaded to `cleansed_security_event` with `dq_status='passed_with_warnings'` and the
specific rule names recorded in `dq_failed_rules`, so downstream consumers can filter without
losing rows outright — consistent with the KB's "shift-left, don't halt on non-critical failures"
guidance.

---

## 5. Silver Layer

**Table:** `silver_windows_security.cleansed_security_event`
**Purpose:** one conformed, typed, deduplicated, snake_case row per raw event — the single source
of truth Gold's dimension/fact ETL reads from.

### 5.1 Deduplication Key

`(source_file, hostname_nk, channel, record_number)` — **confirmed** unique within each source
file (0 collisions in 196,081 + 587,286 rows) but **not** unique across files (1,631 collisions,
mapping to genuinely different events — §0). Dedup logic, mirroring the KB pattern
(`silver-layer.md` "Deduplicate using business key + latest ingestion"):

```sql
ROW_NUMBER() OVER (
    PARTITION BY source_file, hostname_nk, channel, record_number
    ORDER BY ingest_timestamp DESC
) = 1
```

Applied defensively (today's data has zero true intra-key duplicates, but Bronze re-ingestion/
backfill reruns could introduce them without this step). This key is identical to the fact table's
declared natural key in `ddl.sql` (`uq_fact_security_event_nk`), so the Silver→Gold `MERGE` join
condition is a straight column match with no re-derivation.

### 5.2 Timestamp Reconciliation (implements star_schema.md §6, resolves the open question in §0)

```sql
event_utc_time = CASE
    WHEN channel_raw = 'Microsoft-Windows-Sysmon/Operational' AND utc_time_raw IS NOT NULL
        THEN CAST(utc_time_raw AS TIMESTAMP)                         -- native UTC, ms precision
    WHEN event_time_raw IS NOT NULL
        THEN CAST(event_time_raw AS TIMESTAMP) + tz_offset_calibrated  -- see below
    ELSE NULL                                                         -- should not occur (rule #7)
END
```

`tz_offset_calibrated` is **computed empirically per load batch**, not hardcoded, because Bronze
gives us the means to do so correctly: every Sysmon-channel row carries **both** `UtcTime` and
`EventTime`. The calibration query:

```sql
SELECT hostname_raw, MODE() WITHIN GROUP (ORDER BY (CAST(utc_time_raw AS TIMESTAMP)
                                                       - CAST(event_time_raw AS TIMESTAMP)))
                       AS tz_offset
FROM   bronze_windows_security.raw_windows_security_event
WHERE  channel_raw = 'Microsoft-Windows-Sysmon/Operational'
GROUP  BY hostname_raw;
```

...produces one offset per host (this dataset shows a consistent +4:00:00 across all 4 hosts —
that is a **discovered value**, not an assumption baked into the design; a production pipeline
recalibrates every load to survive DST transitions or collector reconfiguration). The offset used
is recorded in `tz_offset_applied` for audit, and `time_source_flag` records which branch fired
(`'utc_time_native'` vs `'event_time_calibrated'`).

### 5.3 Process Correlation Gap — Proposed Silver-Layer Enrichment

`star_schema.md` §6.3 explicitly deferred this to the medallion/ETL layer: Sysmon-channel rows
carry `ProcessGuid` natively; Security/WFP-channel rows never do, only a recycled `ProcessId` (now
confirmed dual-encoded — decimal vs. hex, §0) plus an image path. The Gold fact table's committed
contract is `process_sk = -1` for all Security/WFP rows (never force-fit) — **this design does not
change that contract.** Instead it adds an **optional, probabilistic bridge**:

**`silver_windows_security.process_correlation_bridge`** — one row per Security/WFP-channel event
attempting a PID-based correlation:

1. Build a per-host "PID lease" candidate set from Sysmon rows: for each `(hostname, process_id)`
   decimal pair, the candidate interval starts at the Sysmon `EventID 1` (ProcessCreate)
   `event_utc_time` for that `ProcessGuid`. **Caveat, stated explicitly:** this dataset's captured
   Sysmon EventID set (`1,3,7,8,10,11,12,13,22,23` per `data_profile.md`) does **not** include
   EventID 5 (ProcessTerminate), so there is no reliable lease **end** boundary from Sysmon alone.
   The bridge therefore uses a conservative, configurable lease window (default: next
   `ProcessCreate` reusing the same PID on that host, capped at a fallback ceiling, e.g. 60
   minutes) and always records `candidate_window_seconds` so the assumption is auditable, not
   hidden.
2. For each Security/WFP row, normalize `raw_process_id` (hex → decimal) and look up which
   `ProcessGuid` "owned" that PID on that host at `event_utc_time`.
3. Classify: `match_method = 'pid_time_window_unique'` (exactly one candidate) →
   `match_confidence = 'high'`; `'pid_time_window_ambiguous'` (PID reuse collision inside the
   window) → `match_confidence = 'low'` (all ties recorded, most temporally-adjacent flagged);
   `'unmatched'` → `match_confidence = 'none'`.
4. The bridge is consumed only by an **optional** Gold-adjacent investigative view
   (`gold_windows_security.v_process_correlation_hint`, not part of `ddl.sql`'s committed FK
   graph) — analysts can `LEFT JOIN` through it for kill-chain reconstruction, but
   `fact_security_event.process_sk` stays `-1` for these rows exactly as `star_schema.md` §6.3
   specifies. This keeps the Gold contract unchanged while still delivering the enrichment the
   schema designer flagged as valuable.

### 5.4 Other Normalizations

- **`Hashes` parsing** — `SHA1=...,MD5=...,SHA256=...,IMPHASH=...` split into
  `hash_sha1/hash_md5/hash_sha256/hash_imphash` at Silver (not deferred to Gold) so
  `dim_process`'s Gold load is a straight column selection.
- **`ProcessId` normalization** — decimal string (Sysmon) or `0x`-prefixed hex string
  (Security/WFP `ProcessId`/`NewProcessId`) both cast to `BIGINT`; original text preserved in
  `raw_process_id_original` for audit (confirms/refutes rule #11 above).
- **`network_protocol`** — Sysmon emits text (`'tcp'`/`'udp'`); WFP emits an IANA protocol number
  as text (`'6'`/`'17'` observed) — normalized to lowercase `'tcp'`/`'udp'` via a small `CASE`/
  lookup.
- **`network_direction`** — Sysmon's boolean-as-text `Initiated` (`'true'`/`'false'`) is mapped to
  `'outbound'`/`'inbound'`; WFP's `Direction` field uses Windows `%%`-prefixed message codes
  (observed: `"%%14592"`) that are **not** guessed inline here — they resolve through
  `silver_windows_security.ref_windows_message_code`, a small static reference table seeded from
  Microsoft's published Security-auditing message-string table (external, authoritative source —
  not fabricated for this document). The same table also resolves `ElevatedToken`
  (`"%%1842"`-style) and `TokenElevationType` codes observed in the raw data.
- **Boolean-as-text fields** (`SourceIsIpv6`, `DestinationIsIpv6`, `Initiated`, `IsExecutable`,
  `Archived` — all observed as the strings `"true"`/`"false"` in the raw JSON, not native JSON
  booleans) cast to `BOOLEAN`.
- **snake_case renaming** — every column renamed per the mapping table already published in
  `star_schema.md` §10 (`ProcessGuid → process_guid`, `TargetFilename → target_filename`, etc.);
  this document does not re-derive that mapping, it implements it.

### 5.5 Partitioning

`PARTITION BY event_date` (business date derived from the now-reconciled `event_utc_time`, **not**
`ingest_timestamp` — per KB guidance "Silver: Partitioning by business date, not ingestion date").
`source_file` is deliberately **not** a Silver partition key (unlike Bronze) — once reconciled and
deduplicated, Silver rows are organized for query/analysis by when the security event happened,
not by which raw file it arrived in; lineage back to the file is preserved as a column
(`source_file`), not a physical partition.

### 5.6 Load Strategy

**Incremental `MERGE`/upsert**, watermarked on `ingest_timestamp` (mirrors
`medallion/patterns/incremental-loading.md`): each run reads only Bronze rows with
`ingest_timestamp > high_watermark(silver_table)`, deduplicates the incoming batch, and merges on
the natural key. This is safe to run repeatedly and safe against partial Bronze reprocessing
because the natural key (§5.1) is stable and collision-checked.

---

## 6. Gold Layer (reference — DDL already exists)

Gold DDL is **not duplicated here** — see `docs/schema/ddl.sql` (7 dimensions + `fact_security_event`)
and `docs/schema/star_schema.md` for grain, SCD rationale, and the ER diagram. This section only
adds the medallion-level orchestration contract that DDL alone doesn't express: **load order**,
**surrogate key generation**, and **late-arriving dimension handling**.

### 6.1 Load Order

```
Phase 1 (no dependency, static/derived — refresh rarely, full overwrite):
    dim_date          ← generated calendar range (not sourced from Silver)
    dim_time           ← generated 86,400-row seed (not sourced from Silver)
    dim_event_type       ← static ~23-row seed (EventID × Channel reference)

Phase 2 (Type 1, small reference dimensions — incremental upsert from Silver DISTINCT extracts):
    dim_host            ← SELECT DISTINCT hostname_nk, hostname_fqdn, ... FROM silver.cleansed_security_event
    dim_user              ← SELECT DISTINCT COALESCE(subject_sid, target_sid), ... (both roles unioned)
    dim_network_endpoint    ← SELECT DISTINCT source_ip/destination_ip (both roles unioned)

Phase 3 (Type 2, ordered — must run after Phase 2, and must process rows in event_utc_time order
per process_guid to build a correct version history):
    dim_process              ← incremental SCD2 MERGE (§6.3), driven by Sysmon-channel Silver rows

Phase 4 (fact — must run last, depends on all dimensions above being current):
    fact_security_event        ← lookup every FK against the dimensions loaded in Phases 1–3;
                                  unresolved lookups fall back to the reserved -1 member (never
                                  a bare NULL, per star_schema.md §7) — this makes Phase 4 safe to
                                  run even if a dimension row hasn't landed yet (§6.4).
                                  FIX C2: process_sk / target_process_sk are resolved by a
                                  POINT-IN-TIME join to dim_process (see §6.5), NOT is_current.
```

Phases 1–3 are independent of each other and can run in parallel; Phase 4 has a hard dependency on
all three finishing (or on the `-1` fallback absorbing any not-yet-loaded reference, per §6.4).

### 6.2 Surrogate Key Generation  *(FIX M5 — now committed in DDL, not a side note)*

`ddl.sql` no longer uses `GENERATED ALWAYS AS IDENTITY` for any dimension or the fact.
Identity sequences are incompatible with **Iceberg** (no such construct) and behave
non-deterministically under the **incremental `MERGE`/upsert** load pattern these tables actually
use (re-matched rows can get new IDs across reruns/parallel writers). All surrogate keys are now
**deterministic hash surrogates**, computed at load time from the natural key:

| Table | Surrogate formula |
|---|---|
| `dim_host` | `host_sk = hash(hostname_nk)` |
| `dim_user` | `user_sk = hash(sid)` |
| `dim_network_endpoint` | `endpoint_sk = hash(ip_address)` |
| `dim_process` (SCD2) | `process_sk = hash(process_guid, effective_from)` — includes `effective_from` so every version gets a distinct, stable key |
| `fact_security_event` | `event_sk = hash(source_file, hostname_nk, channel, record_number)` — the dedup NK, so the fact `MERGE` is rerun-idempotent |

Implementation: use the engine's 64-bit hash (`xxhash64`/`farm_fingerprint`) or
`CAST(CONV(SUBSTR(MD5(<nk>),1,15),16,10) AS BIGINT)` for portability. The reserved `-1` member
rows are inserted with the literal `-1` (not a hash). Because these are deterministic, rerunning
any Gold batch reproduces identical surrogates for the same natural key + SCD version — the
idempotency an identity sequence cannot guarantee. Hash-collision risk at these cardinalities
(≤ a few thousand dim rows, <1M facts) is negligible for a 64-bit space.

### 6.3 `dim_process` SCD Type 2 Merge Detail  *(FIX C1 — single `MERGE` was broken)*

Each new Sysmon-channel sighting of a `ProcessGuid` in Silver is a candidate new version. **A
single `MERGE` cannot load this correctly**: a `process_guid` is normally re-sighted many times
per batch (Registry 12/13 and ProcessAccess 10 dominate the data), so multiple source rows would
all match the one `is_current = TRUE` target row via `ON target.process_guid = source.process_guid`
— which raises the "multiple source rows matched the same target row" runtime error on Delta/
Spark/Snowflake/Postgres `MERGE`, or nondeterministically keeps one version and silently drops the
rest of the chain. SCD2 against a batch that contains *several new versions per key* must be built
in **ordered passes**, one version rank at a time.

**Step A — reduce each contiguous run of identical attributes to a single candidate version.**
Only genuine attribute *changes* (narrow diff: image path / hashes / command line — the
`star_schema.md` §4.5 masquerade signal, NOT attribute-completeness differences like EventID 10
carrying only `Image`+`ProcessId`) start a new version. `LAG` over the security-relevant columns
collapses repeat sightings so re-sightings with the same values don't spawn spurious versions:

```sql
CREATE TEMP VIEW process_versions AS
WITH sightings AS (
    SELECT process_guid, event_utc_time, image_path, hash_sha256, command_line, /* ...all attrs... */,
           ROW_NUMBER() OVER (PARTITION BY process_guid ORDER BY event_utc_time) AS rn,
           LAG(image_path)   OVER (PARTITION BY process_guid ORDER BY event_utc_time) AS prev_image,
           LAG(hash_sha256)  OVER (PARTITION BY process_guid ORDER BY event_utc_time) AS prev_hash,
           LAG(command_line) OVER (PARTITION BY process_guid ORDER BY event_utc_time) AS prev_cmd
    FROM   silver_windows_security.cleansed_security_event
    WHERE  process_guid IS NOT NULL
)
SELECT *,
       -- a version boundary = first sighting OR a real change in a security-relevant field
       ROW_NUMBER() OVER (PARTITION BY process_guid ORDER BY event_utc_time) -- keep event order
FROM   sightings
WHERE  rn = 1
   OR  image_path   IS DISTINCT FROM prev_image
   OR  hash_sha256  IS DISTINCT FROM prev_hash
   OR  command_line IS DISTINCT FROM prev_cmd;
-- Re-number the SURVIVING version-boundary rows sequentially per process_guid:
--   version_seq = ROW_NUMBER() OVER (PARTITION BY process_guid ORDER BY event_utc_time)
```

**Step B — apply one `version_seq` at a time (multi-pass loop).** For `k = 1, 2, 3, …` until no
rows remain at rank `k`, run a `MERGE` whose source is filtered to `version_seq = k` — guaranteeing
**at most one source row per `process_guid`** per `MERGE`, which is what makes the statement legal:

```sql
-- pass k (loop in the orchestrator until source has no rows at this rank)
MERGE INTO dim_process AS target
USING (SELECT * FROM process_versions WHERE version_seq = :k) AS source
ON  target.process_guid = source.process_guid AND target.is_current = TRUE
WHEN MATCHED AND (
        target.image_path   IS DISTINCT FROM source.image_path  OR
        target.hash_sha256  IS DISTINCT FROM source.hash_sha256 OR
        target.command_line IS DISTINCT FROM source.command_line )
    THEN UPDATE SET target.effective_to = source.event_utc_time, target.is_current = FALSE;
-- then insert the new current version for every guid whose current row was just closed
-- (or that had no current row), with process_sk = hash(process_guid, effective_from):
INSERT INTO dim_process (process_sk, process_guid, ..., effective_from, effective_to, is_current)
SELECT hash(s.process_guid, s.event_utc_time), s.process_guid, ...,
       s.event_utc_time, TIMESTAMP '9999-12-31 00:00:00', TRUE
FROM   process_versions s
WHERE  s.version_seq = :k
  AND  NOT EXISTS (SELECT 1 FROM dim_process d
                   WHERE d.process_guid = s.process_guid AND d.is_current = TRUE);
```

Because passes run in ascending `version_seq` order, each version's `effective_from` closes the
prior version's `effective_to`, producing a gap-free, contiguous validity chain. The number of
passes equals the maximum distinct-version count for any single `process_guid` in the batch
(small in practice). Set-based single-`MERGE` SCD2 is only valid when the source is pre-guaranteed
one-row-per-key; here it is not, so the loop is mandatory, not an optimization choice.

### 6.4 Late-Arriving Dimension Strategy

Because Phase 4 (fact) can in principle run before every Phase 2/3 dimension row exists (e.g., a
`dim_user` natural key never before seen appears in this batch's fact rows), the load uses the
standard Kimball "inferred member" pattern, adapted to this design's `-1` convention:

1. Fact load performs a `LEFT JOIN` to each dimension on its natural key.
2. Unmatched rows get `COALESCE(dim.sk, -1)` — the row loads immediately, never blocked,
   never a bare NULL FK (already the committed rule in `ddl.sql` §7).
3. **Difference from a bare "-1 forever" outcome:** for `dim_user`/`dim_host`/`dim_network_endpoint`
   (Type 1, cheap to backfill), the natural key that failed to resolve is captured in a small
   `late_arriving_keys` staging table and **re-attempted on the next Phase 2 run** — once the real
   dimension row lands, a corrective `UPDATE fact_security_event SET subject_user_sk = ...
   WHERE subject_user_sk = -1 AND <original natural key predicate>` reconciles it. This is
   necessary in practice only for a continuously-loaded pipeline; for this fixed 2-day batch
   dataset, running Phase 2 before Phase 4 in the same batch avoids the scenario entirely — the
   corrective-update path is documented for forward-looking production use, not required to load
   this dataset once.
4. `dim_process` (Type 2) is **not** eligible for `-1`-then-backfill correction in the same way,
   because a wrong `-1` assignment followed by a real Type 2 version insert would require
   rewriting historical fact rows against a versioned dimension — instead, Phase 3 is a hard
   prerequisite of Phase 4 in the orchestration DAG (no late-arriving path for `dim_process`).

### 6.5 Fact → `dim_process` Point-in-Time Resolution  *(FIX C2)*

`process_sk` and `target_process_sk` must be resolved to the `dim_process` version that was valid
**at the moment the event fired**, not the version that happens to be `is_current` when Phase 4
runs. Resolving to `is_current` misattributes every earlier event of a `process_guid` to its
*latest* attribute state — so a `ProcessCreate` at 10:00 with `svchost.exe` would be joined to a
03:00-next-day masquerading `Image` path, making the exact conflicting-Image signal
`star_schema.md` §4.5 says this design exists to detect **invisible from the fact join**. Resolve
with a range predicate on the canonical event time:

```sql
-- acting process (Sysmon-channel rows carrying a ProcessGuid)
LEFT JOIN dim_process dp
       ON dp.process_guid = s.process_guid
      AND s.event_utc_time >= dp.effective_from
      AND s.event_utc_time <  dp.effective_to        -- half-open interval; no double-match at a version boundary
-- then process_sk = COALESCE(dp.process_sk, -1)
```

The same half-open point-in-time join resolves `target_process_sk` via `s.target_process_guid`.
Consequences for orchestration: Phase 4 cannot resolve `process_sk` until **all** of that batch's
`dim_process` versions exist (already guaranteed — Phase 3 is a hard prerequisite, §6.4.4), and it
must join each fact row to its own as-of-event-time version rather than reading whatever is current
at pipeline end. The `ix_dim_process_pit (process_guid, effective_from, effective_to)` index in
`ddl.sql` backs this lookup; the `is_current` partial index is for the `dim_process_current`
convenience view only, never for fact FK resolution.

---

## 7. Incremental vs. Full-Load Strategy Summary

| Layer / table | Write mode | Trigger | Watermark | Full-reload scenario |
|---|---|---|---|---|
| Bronze `raw_windows_security_event` | Append only | New file arrival (batch: 2 files today) | `source_file` (file-level, not row-level) | Reprocess one `source_file` partition (`event_date`,`source_file`) without touching the other |
| Silver `cleansed_security_event` | Incremental `MERGE` (upsert) | Scheduled after Bronze append completes | `ingest_timestamp > high_watermark(silver)` | Full Bronze→Silver replay if reconciliation logic changes (e.g., a corrected `tz_offset_calibrated`) |
| Silver `process_correlation_bridge` | Incremental append/recompute | After `cleansed_security_event` merge | same watermark | Recompute in full if the lease-window heuristic (§5.3) changes |
| Gold `dim_date`/`dim_time`/`dim_event_type` | Full overwrite (Type 0) | Rare (schema/calendar range change only) | n/a | Trivial — always regenerable |
| Gold `dim_host`/`dim_user`/`dim_network_endpoint` | Incremental `MERGE` (Type 1) | After Silver merge | Silver `_updated_at` | Full rebuild is cheap (small dimensions) |
| Gold `dim_process` | Incremental `MERGE` (Type 2, append-mostly) | After Silver merge | Silver `_updated_at`, ordered by `event_utc_time` per `process_guid` | Full rebuild requires replaying all Silver Sysmon-channel rows in `event_utc_time` order — expensive but correct |
| Gold `fact_security_event` | Incremental `MERGE` on the fact natural key | After all dimension phases | Silver `_updated_at` | Full rebuild = re-run Phase 4 against a fully current dimension set |

---

## 8. Confidence

**Confidence: 0.95** — standard medallion layering (Bronze append/schema-on-read, Silver
cleanse/dedupe/type, Gold star schema) applied to an already-designed, KB-aligned Gold contract.
Held at 0.95 rather than higher because: (1) the `tz_offset_calibrated` value and the WFP
lease-window heuristic in §5.2/§5.3 are dataset-specific empirical findings from this 2-day
sample, not universal constants — a production pipeline must recompute them per load, as
designed, but that recomputation logic itself is new and unverified against a longer time series;
(2) the `%%`-message-code lookup table (`ref_windows_message_code`) is specified structurally but
intentionally left unseeded here to avoid fabricating Microsoft's authoritative code-to-meaning
mapping — populating it is a required follow-up before `network_direction`/`elevated_token`
normalization can run in Silver.
