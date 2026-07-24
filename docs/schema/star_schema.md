# Star Schema — Windows Security Telemetry (Sysmon + Security + PowerShell + WFP)

> Source: `dadosdia1.json` (196,081 records), `dadosdia2.json` (587,286 records) — NDJSON, MITRE ATT&CK
> "dmevals" / APT29 evaluation dataset. Grounded in `/mnt/c/Users/Admin/agentecve/docs/data_profile.md`
> and direct sampling of representative EventIDs (1, 3, 10, 11, 12, 13, 22, 23, 4688, 4624, 4663, 5156, 4104, 800).
>
> **Target layer:** Gold (dimensional mart) of a medallion lakehouse. Bronze = raw NDJSON as-is;
> Silver = typed/cleaned/deduplicated events + parsed sub-fields; Gold = this star schema.
> Table format, partitioning, and physical clustering are **out of scope** here — see
> `medallion-architect` and `sql-optimizer` for those decisions.

---

## 1. Grain Statement

> **One row in `fact_security_event` = one raw security telemetry event = one line in the
> source NDJSON file = one Windows Event Log record (one `RecordNumber` within one
> `Channel` on one `Hostname`).**

This is a **factless fact table** (Kimball "event/transaction grain with no natural numeric
measure"). The only true measure is the implicit occurrence count. There is no double-counting
risk, no pre-aggregation, and no mixing of grains — every EventID (Sysmon 1–23, Security
4656/4658/4663/4688/4690/4703/4624/4625, PowerShell 800/4103/4104, WFP 5156/5158/5447) lands as
exactly one fact row, regardless of how many or how few attributes that EventID populates.

**Row-level idempotency / natural key:** `(source_file, hostname_nk, channel, record_number)`.
Windows scopes `RecordNumber` per host per channel, so this triple (quadrupled with the source
file for defensive re-ingestion safety) uniquely identifies a raw event and is used as the
dedup/upsert key from Silver → Gold.

---

## 2. Why a Wide Factless Fact Instead of Many Narrow Facts

The 4 telemetry families (Sysmon, Windows Security, PowerShell, WFP) share almost no fields in
common beyond `UtcTime`/`EventTime`, `Hostname`, `EventID`, `Channel`, and *some* notion of
process/user. Splitting into per-EventID fact tables would satisfy 3NF-style purity but breaks
the two things a SOC analyst actually wants:

1. **Timeline reconstruction** — "show me everything that happened on host X between T1 and T2"
   requires a `UNION` across N fact tables instead of one filtered scan.
2. **Cross-technique correlation** (the whole point of an APT29 eval dataset) — a single kill
   chain touches ProcessCreate → NetworkConnect → RegistrySetValue → FileCreate → PowerShell
   ScriptBlock in seconds; those need to be joinable on `process_sk`/`host_sk` without a fan-out
   of UNIONs.

This mirrors how commercial SIEM normalized schemas (Splunk CIM, Microsoft Sentinel ASIM) handle
heterogeneous security logs: one wide event table with **nullable, EventID-scoped attribute
columns**, not per-source-type fact tables. See §5 for the explicit satellite-vs-fact-column
decision per attribute group.

---

## 3. ER Diagram (ASCII)

```
                                   dim_date (date_sk PK)
                                          │
                                   dim_time (time_sk PK)
                                          │
        dim_host ──────┐                 │                ┌────── dim_network_endpoint
     (host_sk PK)       │                 │                │        (endpoint_sk PK)
                         │                 │                │        [source_endpoint_sk]
                         │                 │                │        [destination_endpoint_sk]
                         ▼                 ▼                ▼
   dim_user ────►  ┌─────────────────────────────────────────────┐  ◄──── dim_event_type
(user_sk PK)       │                                             │       (event_type_sk PK)
 [subject_user_sk] │            fact_security_event               │        junk/reference dim
 [target_user_sk]  │        grain = 1 row per raw event           │       (EventID, Channel)
                    │                                             │
   dim_process ───► │  event_sk PK  |  natural key (dedup):       │
(process_sk PK)     │  source_file, hostname_nk, channel,          │
 SCD Type 2         │  record_number                               │
 [process_sk]       │                                             │
 [target_process_sk]│  + ~30 nullable EventID-scoped attribute      │
                    │    columns (file/registry/process-access/    │
                    │    network/logon/PowerShell — see §5)         │
                    └─────────────────────────────────────────────┘

Cardinality: every FK edge above is fact-side MANY : dim-side ONE.
All FKs are NOT NULL with a "-1 = Not Applicable / Unknown" default member row
(never a bare NULL FK) — see §7.
```

### Relationship / cardinality summary

| Dimension | FK(s) on fact | Optional? | Cardinality (dim rows) | Relationship |
|---|---|---|---|---|
| `dim_date` | `date_sk` | Always populated | ~2 (2020-05-01/02, expandable) | fact N : dim 1 |
| `dim_time` | `time_sk` | Always populated | 86,400 (static seed, 1/sec) | fact N : dim 1 |
| `dim_host` | `host_sk` | Always populated | ~4 | fact N : dim 1 |
| `dim_user` | `subject_user_sk`, `target_user_sk` | subject always; target only for logon events (else -1) | ~9–12 | fact N : dim 1 (role-playing, 2 FKs to same table) |
| `dim_process` | `process_sk`, `target_process_sk` | process_sk populated for Sysmon-channel events; target_process_sk only for EventID 8/10; else -1 | grows with distinct `ProcessGuid` (thousands) | fact N : dim 1 (role-playing) |
| `dim_network_endpoint` | `source_endpoint_sk`, `destination_endpoint_sk` | Only ~0.4–0.6% of rows (NetworkConnect + WFP) | small, distinct IPs seen | fact N : dim 1 |
| `dim_event_type` | `event_type_sk` | Always populated | ~23 (static seed) | fact N : dim 1 |

---

## 4. Dimension-by-Dimension Rationale

### 4.1 `dim_date` — conformed, Type 0 (static/derived, no SCD)
Derived purely from `UtcTime` (see §6 for timestamp reconciliation). Standard Kimball date
dimension: `date_sk` as `YYYYMMDD` INT, calendar attributes, `is_weekend`. Populated for the
observed range plus a small buffer; trivially regenerable, never updated in place — dates don't
change, so no SCD applies.

### 4.2 `dim_time` — conformed, Type 0 (static seed)
Requested explicitly to keep time-of-day separate from the calendar date and from the raw
millisecond timestamp. Grain = **1 row per second of day** (86,400 rows), `time_sk` = `HHMMSS`
as INT. Enables fast "outside business hours" / "activity clustered around midnight" security
analysis (a classic APT tradecraft signal) without re-deriving `EXTRACT(HOUR FROM ...)` on every
query. The fact table *also* keeps the full-precision `event_utc_time TIMESTAMP` for millisecond
ordering/joins — `date_sk`/`time_sk` are for fast categorical slicing, not a replacement for the
raw timestamp.

### 4.3 `dim_host` — conformed, SCD Type 1
Natural key: `hostname_nk` (short name parsed from `Hostname`, e.g. `SCRANTON` from
`SCRANTON.dmevals.local`). Only **4 distinct hosts** in the dataset (per profile) — this is
reference-quality data. SCD Type 1 (overwrite) is justified: hostnames don't meaningfully change
identity mid-evaluation, and per the anti-pattern guidance ("SCD Type 2 everywhere → storage
bloat, unnecessary complexity"), Type 2 buys nothing here. Also carries the log-collector
metadata (`host`, `port` — Logstash/NXLog shipper identity) as low-value but free attributes.

### 4.4 `dim_user` — conformed, SCD Type 1, **role-playing dimension**
Natural key: SID (`UserID` / `SubjectUserSid` / `TargetUserSid` — coalesced), falling back to
`DOMAIN\AccountName` only when SID is absent (rare, e.g. some WFP `RemoteUserID` fields). SID is
preferred because it's the one truly stable Windows identity attribute across all 4 telemetry
sources. Only **~9–12 distinct users** — small, low-churn reference dimension. SCD Type 1: for a
2-day forensic evaluation window there's no meaningful "history" of `AccountName`/`Domain`
changing for the same SID.

**Role-playing:** Security-channel logon events (4624/4625) expose *two* identities per event —
the `Subject*` (who performed the logon attempt, often the SYSTEM/service account) and the
`Target*` (the account being logged into). Sysmon/PowerShell events only carry one identity
(`User`/`AccountName`+`Domain`+`UserID`). Rather than building two physical tables, `dim_user` is
reused twice via role aliasing: `fact.subject_user_sk` (always populated) and
`fact.target_user_sk` (populated only for logon events with a distinct target; `-1` otherwise).

*Forward-looking note:* if this pipeline evolves into a continuously-loaded production SOC
warehouse (not a fixed 2-day eval), upgrade to Type 2 to catch account-rename / SID-reuse
anomalies — attribute *change itself* becomes a security signal at that point.

### 4.5 `dim_process` — conformed, **SCD Type 2**
Natural key: `ProcessGuid` (Sysmon-generated, globally unique **per process instance** —
critically, this already solves the classic "PID gets recycled by the OS" problem, so
`ProcessId` must never be used as a key; see anti-pattern §8). Grain of the dimension = one
version of one process's known attributes.

Type 2 is justified here for a reason specific to security telemetry, not "history for its own
sake": **the same `ProcessGuid` is observed incrementally across multiple EventIDs with
different attribute completeness.**
- EventID 1 (ProcessCreate) delivers the *full* attribute set: `Image`, `Hashes`,
  `CommandLine`, `CurrentDirectory`, `IntegrityLevel`, `Company`, `FileVersion`, parent info.
- EventID 3/7/10/11/12/13/22/23 reference the *same* `ProcessGuid` but only carry `Image` +
  `ProcessId` (no hashes/command line).
- EventID 8/10 additionally reference the process in a **second role** (`SourceProcessGUID`
  performing the action, `TargetProcessGUID` being acted upon).

Each new attribute-bearing sighting is loaded as a new dated version
(`effective_from`/`effective_to`/`is_current`) rather than blind-overwritten. This gives two
concrete security benefits beyond standard Kimball SCD2 rationale: (1) an auditable "what did we
know about this process, and when" trail, and (2) if the *same* `ProcessGuid` ever shows a
conflicting `Image` path across sightings, that discrepancy is a strong process-masquerading /
DLL-hijack signal that a Type-1 overwrite would silently erase.

`Hashes` (`SHA1=...,MD5=...,SHA256=...,IMPHASH=...`) is parsed into 4 discrete hash columns.

### 4.6 `dim_network_endpoint` — conformed, SCD Type 1
Natural key: `ip_address` (+ `is_ipv6` to disambiguate representation). **Sparse** — only
~0.4–0.6% of fact rows reference it (NetworkConnect EventID 3 + WFP 5156/5158/5447), which is why
it's still modeled as a proper dimension (small, denormalizes cleanly) rather than embedded flat
on the fact: the same IP recurs across many events and benefits from conformed reuse
(`source_endpoint_sk`/`destination_endpoint_sk` both point here — role-playing, same as
`dim_user`).

**Deliberately excluded from this dimension:** `SourcePort`/`DestinationPort`. Destination ports
are low-cardinality and meaningful (445, 3389, 53...) but source ports are largely ephemeral
(high-cardinality, no descriptive value) — bundling them into the endpoint dimension would
explode its cardinality for no analytical benefit. Ports stay as degenerate scalar columns
directly on the fact (`source_port`, `destination_port`), per standard Kimball guidance to keep
highly-cardinal degenerate identifiers off dimension tables.

`SourceHostname`/`DestinationHostname` (DNS reverse-resolution) are **always empty** per the
profile — the `hostname` column is retained (nullable) for schema completeness/future
enrichment, not because current data populates it.

### 4.7 `dim_event_type` — junk/reference dimension, Type 0 (static seed, no SCD)
Natural key: `(event_id, channel)`. ~23 distinct combinations across all 4 sources — genuinely
static reference data (Sysmon's EventID 12 will always mean "Registry object added or deleted").
Combines `EventID`, `Channel`, `SourceName`, `Task`, a normalized `log_source`
(`sysmon`/`windows_security`/`powershell`/`wfp`), and a human-readable `event_category` +
`event_name` parsed once from the `Message` header (e.g. "Process accessed"). This absorbs what
would otherwise be a low-cardinality junk dimension of flags, keeping the fact table's core
identity compact and queries like `WHERE event_category = 'process_access'` cheap and readable.

---

## 5. Event-Type-Specific Attributes: Fact Columns vs. Satellite — Decision & Justification

**Decision: nullable columns directly on `fact_security_event`, grouped by domain, NOT separate
satellite tables** — with one documented exception (§5.1).

Justification:
1. **1:1 with the grain, not repeating.** Each attribute (e.g. `target_filename`,
   `registry_details`, `granted_access`) is scalar per event — there is no multivalued/repeating
   group here that would violate 1NF. A satellite table only pays for itself when attributes are
   genuinely multivalued (e.g. `dns_query_results` *could* be exploded into a bridge table of
   one-row-per-resolved-IP — flagged as an optional Silver-layer enhancement, not required for
   Gold).
2. **Mutually exclusive by EventID, not independently sparse.** File attributes are populated
   only for EventID 11/23, registry only for 12/13, etc. — this isn't N independently-nullable
   dimensions each requiring a join; it's one wide row where exactly one attribute group is
   non-null. Satellite-izing this would force a LEFT JOIN fan-out for the majority of common
   queries ("show me all file creates") for no query-performance gain.
2b. This is consistent with the requirement's own framing (network fields at ~0.5% density
   already live in a dimension because they're **reusable/conformed** across event types, not
   because they're sparse — sparsity alone doesn't drive the satellite-vs-column decision; entity
   reusability does).
3. **Storage cost is negligible at this volume.** ~780K rows total; even at ~30 nullable
   VARCHAR columns, this is a non-issue for a Gold-layer columnar table (Parquet/Delta/Iceberg
   store NULLs essentially free per-column). If this were row-store OLTP at 100x the volume, the
   calculus would differ — noted as a deferred decision for `medallion-architect`.
4. **No additive numeric measures exist to protect.** The "nullable fact measures" anti-pattern
   (SUM/AVG silently dropping rows) does not apply — this is a factless fact table; the nullable
   columns here are categorical/descriptive attributes of the event, not measures.

Column groups (all nullable, mutually exclusive by `event_type_sk`):

| Group | EventIDs | Columns |
|---|---|---|
| File | 11, 23 | `target_filename`, `file_creation_utc_time`, `file_is_executable`, `file_archived` |
| Registry | 12, 13, 4663 (Key objects) | `registry_target_object`, `registry_details`, `registry_action` |
| Process access / injection | 8, 10 | `granted_access`, `call_trace`, `source_thread_id`, `target_thread_id`, `new_thread_id` |
| DNS | 22 | `dns_query_name`, `dns_query_status`, `dns_query_results` |
| Object access (Security auditing) | 4656, 4658, 4663, 4690, 4703 | `object_name`, `object_type`, `handle_id`, `access_mask`, `access_list` |
| Logon | 4624, 4625 | `logon_type`, `logon_id`, `authentication_package`, `elevated_token`, `workstation_name` |
| PowerShell | 800, 4103, 4104 | `script_block_text`, `script_block_id`, `message_number`, `message_total` |
| Network (see also `dim_network_endpoint`) | 3, 5156, 5158, 5447 | `source_port`, `destination_port`, `network_protocol`, `network_direction`, `network_action` |
| Security-channel process fallback (see §6.3) | 4624/4625/4656/4658/4663/4688/4690/4703/5156/5158/5447 | `raw_process_image`, `raw_process_id`, `raw_parent_process_image`, `raw_parent_process_id` |
| Generic / lineage | all | `message_raw`, `rule_name`, `severity`, `event_result`, `opcode` |

### 5.1 Documented exception: `script_block_text`
PowerShell `ScriptBlockText` (EventID 4104) can carry multi-KB script bodies — materially larger
than every other attribute. It is **included on the fact table by default** to keep the star
schema single-join for BI tools, but flagged here as the one candidate for extraction into an
optional 1:1 extension table (`fact_powershell_scriptblock(event_sk PK/FK, script_block_text)`)
if the chosen Gold physical format/row-store makes wide-row scans on non-PowerShell queries
measurably slower. This is a storage-format decision, deferred to `medallion-architect`.

---

## 6. Timestamp Reconciliation

The raw events carry up to 4 timestamp fields:

| Field | Meaning | Precision | Used as |
|---|---|---|---|
| `UtcTime` | Sysmon/event-source UTC event time | milliseconds | **Canonical `event_utc_time`** → drives `date_sk`/`time_sk` |
| `EventTime` | Collector-local time (observed = UTC-4, i.e. collector host's local TZ) | seconds | Retained as `event_local_time` for shipper-clock-skew QA only |
| `@timestamp` | Logstash ingest time (ISO8601 Z) | milliseconds | Retained as `ingest_event_time` — measures pipeline latency, NOT event time |
| `EventReceivedTime` | NXLog receipt time | seconds | Retained as `event_received_time` — secondary pipeline-latency signal |
| `CreationUtcTime` (EventID 11 only) | File's actual creation time (may predate the FileCreate log event, e.g. renamed/moved files) | milliseconds | Kept as the event-specific `file_creation_utc_time` attribute, distinct from `event_utc_time` |

**Rule:** `UtcTime` is authoritative for `date_sk`, `time_sk`, and `event_utc_time` on every
row. Where `UtcTime` is absent (verify at Silver-layer; not observed missing in sampled EventIDs
but Security/WFP events should be double-checked during Bronze→Silver typing) fall back to
`EventTime` and flag the row (`time_source_flag` — recommended Silver-layer QA column, not
included in the Gold DDL below to keep the star schema clean; escalate to `data-quality-analyst`
for the freshness/completeness test design). All other timestamp fields are retained as
degenerate audit columns on the fact — never dropped, since ingest-latency analysis is a
legitimate downstream use case (detecting shipper backpressure/outages).

---

## 6.3 Heterogeneous Schema: Cross-Source Process Correlation Gap

**This must be called out explicitly, not glossed over.** `dim_process`'s natural key
(`ProcessGuid`) is emitted only by **Sysmon** (EventIDs 1, 3, 7, 8, 10, 11, 12, 13, 22, 23).
**Windows Security-channel events (4624/4625/4656/4658/4663/4688/4690/4703) and WFP events
(5156/5158/5447) never carry `ProcessGuid`** — they identify the process only via a decimal or
hex `ProcessId` (which Windows recycles) plus an image path/name, and only a timestamp +
`Hostname` for context.

Consequence for the fact table:
- For Sysmon-channel rows: `process_sk` resolves via `dim_process.process_guid` (join on
  `ProcessGuid`, or `SourceProcessGUID` for the "acting" role on EventID 8/10).
- For Security/WFP-channel rows: `process_sk` = `-1` (Not Applicable — no reliable join key
  exists in Gold), and the raw identifiers are preserved as fact-level degenerate columns
  (`raw_process_image`, `raw_process_id`, `raw_parent_process_image`, `raw_parent_process_id`)
  rather than being force-fit into `dim_process`.
- **Do not** attempt fuzzy correlation (matching decimal `ProcessId` + `Hostname` + time window
  to a `dim_process` row) inside this Gold star schema — that is a probabilistic Silver-layer
  enrichment decision (time-window join, PID-reuse risk) that belongs to the ETL/medallion
  design, not the dimensional model. Flagged for `medallion-architect` as a known Silver-layer
  enrichment opportunity, not a Gold-layer requirement.

This is the concrete instance of "heterogeneous schema" that matters most here: it's not just
"different EventIDs have different optional columns" (§5 handles that), it's "the very concept of
*which natural key identifies the process* differs by source channel."

---

## 7. Default / Unknown Member Rows

Per Kimball convention and the shared anti-pattern guidance ("nullable FK without default →
query errors, broken joins"), every dimension has a reserved surrogate key for
"Not Applicable / Unknown":

| Dimension | Unknown SK | Meaning |
|---|---|---|
| `dim_date` | `19000101` | Timestamp unparseable (should not occur post-Silver-QA) |
| `dim_time` | `-1` | Timestamp unparseable |
| `dim_host` | `-1` | Should not occur — `Hostname` observed on 100% of sampled events |
| `dim_user` | `-1` | Event carries no identifiable subject (rare) / no target account (common — most events aren't logons) |
| `dim_process` | `-1` | Event's process reference is off Sysmon channel (see §6.3) or absent |
| `dim_network_endpoint` | `-1` | ~99.5% of rows — event has no network component |
| `dim_event_type` | *(none needed — always resolvable from `EventID`+`Channel`, which are always present)* | — |

All fact FKs are declared `NOT NULL` with `DEFAULT -1`, guaranteeing every `JOIN` (including plain
`INNER JOIN`) against every dimension is safe with zero row loss.

---

## 8. Anti-Patterns Explicitly Avoided

| Anti-pattern | How this design avoids it |
|---|---|
| Natural/mutable key as PK/FK | `ProcessGuid` (not `ProcessId`) is the process natural key; SID (not `AccountName`) is the user natural key |
| SCD Type 2 everywhere | Only `dim_process` is Type 2, with an explicit security-specific justification; `dim_host`/`dim_user`/`dim_network_endpoint` are Type 1 |
| Nullable FK without default | Every FK has a `-1` default member row (§7) |
| Snowflaking without reason | `dim_event_type` absorbs what could be 3 separate junk dimensions (source, category, task); no unnecessary normalization of low-cardinality reference data |
| Skipping grain definition | §1 states the grain explicitly before any table was designed |
| Mixing grains in one fact | Every EventID lands as exactly 1 fact row; no pre-aggregation |
| `SELECT *` / unbounded VARCHAR | All DDL columns are explicitly typed with length bounds (see `ddl.sql`) |

---

## 9. Bus Matrix (forward-looking)

Only one fact table exists today, but the conformed dimensions are designed to be reused by
future specialized Gold marts the `medallion-architect` may split out (e.g.
`fact_network_connection`, `fact_logon`, `fact_process_lifecycle` as narrower, pre-filtered
views/marts over the same conformed dimensions):

| Dimension | fact_security_event | fact_network_connection (future) | fact_logon (future) | fact_process_lifecycle (future) |
|---|---|---|---|---|
| dim_date / dim_time | X | X | X | X |
| dim_host | X | X | X | X |
| dim_user | X | — | X | X |
| dim_process | X | X | — | X |
| dim_network_endpoint | X | X | — | — |
| dim_event_type | X | — | — | — |

---

## 10. Source Field → Target Column Mapping (Summary)

See `ddl.sql` for the authoritative, table-by-table mapping as SQL comments. Summary:

| Raw field(s) | Target |
|---|---|
| `UtcTime` | `dim_date.date_sk`, `dim_time.time_sk`, `fact.event_utc_time` |
| `EventTime`, `@timestamp`, `EventReceivedTime` | `fact.event_local_time`, `fact.ingest_event_time`, `fact.event_received_time` |
| `Hostname` | `dim_host.hostname_nk` / `hostname_fqdn` |
| `host`, `port` | `dim_host.collector_host`, `dim_host.collector_port` |
| `User`, `AccountName`+`Domain`, `UserID`, `SubjectUserName`+`SubjectDomainName`+`SubjectUserSid` | `dim_user` (subject role) |
| `TargetUserName`+`TargetDomainName`+`TargetUserSid` | `dim_user` (target role, logon events only) |
| `ProcessGuid`, `Image`, `Hashes`, `CommandLine`, `ProcessId`, `ParentProcessGuid`, `ParentImage`, `ParentCommandLine`, `IntegrityLevel`, `Company`, `Product`, `Description`, `OriginalFileName`, `FileVersion`, `CurrentDirectory`, `LogonGuid` | `dim_process` |
| `SourceProcessGUID`/`SourceProcessId`/`SourceImage`, `TargetProcessGUID`/`TargetProcessId`/`TargetImage` | `dim_process` (2 roles), `fact.granted_access`, `fact.call_trace` |
| `NewProcessName`/`NewProcessId`, `ProcessName`/`ProcessId` (Security/WFP channel), `ParentProcessName`, `Application` | `fact.raw_process_image`, `fact.raw_process_id` (fallback — see §6.3) |
| `SourceIp`/`SourceAddress`, `DestinationIp`/`DestAddress`, `SourceIsIpv6`, `SourceHostname`/`DestinationHostname` | `dim_network_endpoint` (2 roles) |
| `SourcePort`, `DestinationPort`/`DestPort`, `Protocol`, `Initiated`/`Direction` | `fact.source_port`, `fact.destination_port`, `fact.network_protocol`, `fact.network_direction` |
| `EventID`, `Channel`, `SourceName`, `Task` | `dim_event_type` |
| `TargetFilename`, `CreationUtcTime`, `IsExecutable`, `Archived` | `fact.target_filename`, `file_creation_utc_time`, `file_is_executable`, `file_archived` |
| `TargetObject`, `Details`, `EventType` (registry sub-type) | `fact.registry_target_object`, `registry_details`, `registry_action` |
| `QueryName`, `QueryStatus`, `QueryResults` | `fact.dns_query_name`, `dns_query_status`, `dns_query_results` |
| `ObjectName`, `ObjectType`, `HandleId`, `AccessMask`, `AccessList` | `fact.object_*`, `access_mask`, `access_list` |
| `LogonType`, `TargetLogonId`, `AuthenticationPackageName`, `ElevatedToken`, `WorkstationName` | `fact.logon_*` |
| `ScriptBlockText`, `ScriptBlockId`, `MessageNumber`, `MessageTotal` | `fact.script_block_*`, `message_number`, `message_total` |
| `Message`, `RuleName`, `Severity`, `EventType` (generic), `Opcode` | `fact.message_raw`, `rule_name`, `severity`, `event_result`, `opcode` |
| `RecordNumber`, `Channel`, `Hostname` (+ source file) | `fact` natural key / dedup columns |

---

**Confidence:** 0.93 | **Impact:** HIGH (foundational Gold-layer contract for downstream medallion design)
**Sources:** KB: data-modeling/concepts/dimensional-modeling.md, data-modeling/patterns/star-schema.md, data-modeling/concepts/scd-types.md, shared/anti-patterns.md | Grounded in: docs/data_profile.md + direct sampling of dadosdia1.json (EventIDs 1, 3, 10, 11, 12, 13, 22, 23, 4688, 4624, 4663, 5156, 4104, 800)

*Confidence note:* held below 0.95 because two items require Silver-layer validation not
performable from the profile alone: (1) whether `UtcTime` is present on 100% of Security/WFP rows
(not just the sampled ones), and (2) whether `RecordNumber` sequences are genuinely disjoint
across `dadosdia1.json`/`dadosdia2.json` for the same host+channel (assumed defensively handled
via the `source_file` component of the natural key either way).
