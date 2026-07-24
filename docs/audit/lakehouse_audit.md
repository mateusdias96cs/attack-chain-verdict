# Lakehouse Audit — Windows Security Telemetry Star Schema + Medallion Design

> **Scope:** Bug audit only (no redesign). Reviewed `docs/data_profile.md`, `docs/schema/star_schema.md`,
> `docs/schema/ddl.sql`, `docs/medallion/medallion_architecture.md`, `docs/medallion/ddl_bronze_silver.sql`.
> **Method:** Line-by-line cross-check of DDL vs. prose vs. empirical findings already recorded in the
> design docs themselves (§0 of `medallion_architecture.md`), looking specifically for defects that
> corrupt query results or silently degrade query performance.

---

## Remediation Status — ALL 15 FIXED (2026-07-22)

Every finding was remediated across `docs/schema/ddl.sql`, `docs/medallion/ddl_bronze_silver.sql`,
and `docs/medallion/medallion_architecture.md`. Both DDL files re-validated: clean parse under the
Postgres dialect (sqlglot) and all seed-INSERT column/value arities match. Fixes are tagged inline
with `FIX <id>` markers.

| ID | Fix applied |
|----|-------------|
| C1 | `dim_process` SCD2 load rewritten as an ordered **multi-pass** MERGE (one `version_seq` per pass → at most one source row per key), with a `LAG`-based change-detection view (`medallion_architecture.md` §6.3). |
| C2 | Fact `process_sk`/`target_process_sk` now resolved by **point-in-time** half-open range join (`event_utc_time ∈ [effective_from, effective_to)`), new `ix_dim_process_pit` index, new §6.5. |
| H1 | Fact `raw_process_id`/`raw_parent_process_id` → `BIGINT` (normalized decimal) + separate `*_original VARCHAR` audit columns; matches Silver & the correlation bridge. |
| H2 | `dim_event_type` gets a `-1` unknown member; `fact.event_type_sk` gets `DEFAULT -1`. |
| H3 | Silver `event_date` materialized as a `GENERATED ALWAYS AS (CAST(event_utc_time AS DATE)) STORED` column; partition clause points at it. |
| H4 | Bronze `event_date` renamed `bronze_partition_date`, documented as TZ-mixed/ingestion-approximate, cross-source date queries routed to Silver. |
| M1 | `log_source` denormalized onto the fact (safe direct filter); `channel` flagged ambiguous (WFP shares `'Security'`). |
| M2 | `bronze_partition_date` made `NOT NULL DEFAULT '1900-01-01'` sentinel (no NULL partition bucket). |
| M3 | `dim_network_endpoint` gains `ip_numeric NUMERIC(39,0)` + `ip_prefix_24` for CIDR/range queries. |
| M4 | `dim_process_current` view added as the safe natural-key join surface; hazard documented. |
| M5 | All surrogate keys → **deterministic hash surrogates** (no `IDENTITY`); Iceberg-compatible, MERGE-idempotent; §6.2 rewritten. |
| M6 | Inert B-tree `CREATE INDEX` on the fact replaced with Delta `ZORDER` / Iceberg `WRITE ORDERED` clustering directives (+ RDBMS fallback). |
| L1 | `dim_network_endpoint` NK aligned to single-column `ip_address` in both DDL and doc. |
| L2 | `dim_date` out-of-range date handling documented (extend calendar + late-arriving member). |
| L3 | `dim_time.is_business_hours` documented as UTC-referenced (not host-local). |

---

## Executive Summary

This is an unusually self-aware design — several classic Kimball/medallion anti-patterns (nullable
FK, natural-key-as-PK, hardcoded TZ offsets, SCD2-everywhere) are explicitly called out and avoided.
The bugs found here are mostly **second-order**: places where the design's own stated intent
(SCD2 point-in-time attribution, PID normalization, partitioning by business date, "-1 never
NULL") is not actually what the accompanying DDL/SQL implements, plus a few concrete
type/constraint mismatches between the Silver and Gold DDL files.

**Total findings: 15**
- **CRITICAL: 2**
- **HIGH: 4**
- **MEDIUM: 6**
- **LOW / PLAUSIBLE: 3**

The two CRITICAL findings both concern `dim_process` (the one SCD Type 2 dimension): the documented
`MERGE` statement will error or silently mis-version whenever a process is observed more than once
per load batch (the *normal* case, not an edge case — it's the entire reason SCD2 was chosen), and
the fact table's `process_sk` is resolved to the *current* version of a process rather than the
version that was actually true *at the time of the event*, which defeats the stated
"detect process masquerading via conflicting Image path" rationale (`star_schema.md` §4.5).

---

## Findings (CRITICAL → LOW)

### C1 — CRITICAL — `dim_process` SCD2 `MERGE` breaks on >1 new version per batch
**Location:** `docs/medallion/medallion_architecture.md` §6.3 (lines ~426–441), governs
`docs/schema/ddl.sql` `dim_process`

**Failing scenario:** A single Silver→Gold Phase-3 run processes a `ProcessGuid` that was sighted by
EventID 1 (ProcessCreate, full detail) and then again by EventID 11 (FileCreate) and EventID 12
(RegistrySetValue) later in the same load window — the *exact* multi-sighting pattern that
`star_schema.md` §4.5 cites as the reason for choosing SCD2 in the first place. The documented
`MERGE`:
```sql
ON target.process_guid = source.process_guid AND target.is_current = TRUE
WHEN MATCHED AND (...) THEN UPDATE ...
WHEN NOT MATCHED THEN INSERT ...
```
has **all 3 source rows matching the same single current target row** via the `ON` clause. Standard
`MERGE` semantics (Delta, Snowflake, Postgres `MERGE`, Spark SQL) raise a runtime error
("multiple source rows matched the same target row") in this situation, or — on engines that
don't error — nondeterministically pick one source row, silently dropping the others from the
version chain. This is not a rare edge case: it is the **modal case** for this dataset (Registry
12/13 and ProcessAccess 10 "dominate" per `data_profile.md`, meaning most `ProcessGuid`s are
re-sighted many times per load).

**Root cause:** The `MERGE`'s `ON` predicate only pins down "current row," not "one row per
distinct new version" — it needs an intermediate `ROW_NUMBER()`-collapsed single "latest new
state per process_guid" derivation before the `MERGE`, or an iterative/recursive version-chain
build, not a one-shot `MERGE` against a batch containing multiple new versions per key.

**Fix:** Pre-aggregate `source` to at most one candidate row per `process_guid` per `MERGE`
invocation (e.g., loop over `version_seq` sequentially, or collapse multi-version batches into a
single "final attribute state changed since last-known version" row before the `MERGE`, then run
the `MERGE`/insert pass repeatedly — once per `version_seq` — until the batch's version chain is
fully applied). Document this explicitly as a multi-pass loop, not a single `MERGE` statement.

---

### C2 — CRITICAL — `fact_security_event.process_sk` resolves to "current" dim_process version, not the version valid at event time
**Location:** `docs/schema/ddl.sql` line 181 (`CREATE INDEX ix_dim_process_current ... WHERE
is_current = TRUE`), `docs/medallion/medallion_architecture.md` §6.1 Phase 4 ("lookup every FK
against the dimensions loaded in Phases 1–3")

**Failing scenario:** `ProcessGuid X` is created (EventID 1) at `2020-05-01 10:00:00` with
`Image = 'C:\Windows\System32\svchost.exe'`. Later the same `ProcessGuid` is re-sighted (EventID
10, ProcessAccess) at `2020-05-02 03:00:00` with a **conflicting** `Image` path — the exact
DLL-hijack/masquerade signal `star_schema.md` §4.5 says this design exists to catch, which creates
a *new* `dim_process` version (`is_current = TRUE` moves to the new row, old row gets
`effective_to` closed). The fact row for the **original 10:00:00 ProcessCreate event** was already
loaded with `process_sk` pointing at whatever was `is_current = TRUE` at the moment Phase 4 ran for
that batch. If Phase 4 runs once at the end of a batch containing both sightings (the documented
load order — Phase 3 fully completes, *then* Phase 4 runs), **every fact row for `ProcessGuid X`
in that batch gets the same, final `process_sk`** — the 10:00:00 ProcessCreate event ends up
pointing at the 03:00:00 (masquerading) Image path, not the Image path that was actually true when
it fired. A query like `SELECT f.event_utc_time, dp.image_path FROM fact_security_event f JOIN
dim_process dp ON f.process_sk = dp.process_sk WHERE f.event_type_sk = 1 /* ProcessCreate */ AND
f.hostname_nk = 'SCRANTON'` returns the **wrong** `image_path` for the earlier event, and the
conflicting-Image signal the design brags about detecting is invisible from the fact join (you'd
only see it by separately querying `dim_process` version history directly).

**Root cause:** No temporal predicate (`source.event_utc_time BETWEEN
target.effective_from AND target.effective_to`) is specified anywhere for the fact-to-dim_process
FK resolution; only a `process_guid = ... AND is_current = TRUE` lookup pattern is evidenced (the
partial index is purpose-built for exactly that lookup, and no other lookup pattern is documented).

**Fix:** Phase 4's `process_sk` lookup must join Silver's `event_utc_time` against
`dim_process.effective_from`/`effective_to` as a range predicate (point-in-time join), not
`is_current = TRUE`. This also means Phase 4 cannot run once for the whole batch if that batch
contains multiple new dim_process versions — it must run **after** all of that batch's
`dim_process` versions exist, then resolve each fact row to its own as-of-event-time version, not
whatever is current at pipeline-end.

---

### H1 — HIGH — `raw_process_id` / `raw_parent_process_id` type & normalization contract mismatch between Silver and Gold
**Location:** `docs/schema/ddl.sql` lines 360–363 vs. `docs/medallion/ddl_bronze_silver.sql`
lines 179–183

**Failing scenario:** Silver (`cleansed_security_event`) does the work of normalizing
`raw_process_id` to `BIGINT` (decimal), keeping the original hex/decimal text separately in
`raw_process_id_original VARCHAR(20)`. Gold's `fact_security_event.raw_process_id`, however, is
declared `VARCHAR(20)` with the comment `-- maps to: NewProcessId | ProcessId (hex string, e.g.
'0x214c')` — i.e. Gold's own contract says this column holds the **unnormalized hex text**, not
Silver's normalized decimal `BIGINT`. Whichever column an ETL implementer actually wires up
(Silver's normalized `BIGINT`, coerced awkwardly into a `VARCHAR(20)`, or Silver's
`raw_process_id_original` hex text, ignoring the normalization work entirely), the result is
inconsistent: an analyst trying to correlate `fact_security_event.raw_process_id` against
`process_correlation_bridge.raw_process_id` (declared `BIGINT NOT NULL`, normalized decimal) will
either get a type-cast query error or — worse — a silent zero-row join if Gold ends up storing hex
text (`'0x214c'`) while the bridge stores decimal (`8524`). Same bug, same two columns, for
`raw_parent_process_id`.

**Root cause:** Gold DDL's column comment was written before/independent of the Silver-layer PID
normalization decision documented in `medallion_architecture.md` §0 ("Silver is where the two
encodings are actually reconciled") — the two DDL files disagree about what this column contains.

**Fix:** Change `fact_security_event.raw_process_id` / `raw_parent_process_id` to `BIGINT` to match
Silver's normalized value (and rename/re-comment to make clear it's the normalized decimal PID);
if the unnormalized original text is still wanted for audit fidelity, add a *separate*
`raw_process_id_original VARCHAR(20)` column on the fact, mirroring Silver, rather than overloading
one column with two contradictory meanings.

---

### H2 — HIGH — `dim_event_type` has no `-1` unknown member, but Silver DQ rules explicitly allow out-of-set EventIDs through
**Location:** `docs/schema/ddl.sql` lines 227–266 (no unknown-member INSERT, unlike every other
dimension); `docs/schema/star_schema.md` §7 ("dim_event_type: *(none needed...)*");
`docs/medallion/medallion_architecture.md` §4.1 rule #2 (`event_id_in_valid_set`, threshold
`0.999`, severity `warning`, not `critical`)

**Failing scenario:** A previously-unseen `(EventID, Channel)` combination appears in the source
data (schema evolution — e.g. Sysmon EventID 5 ProcessTerminate gets enabled later, or a new
detection rule adds EventID 4657). Silver DQ rule #2 is explicitly `warning`-severity with a
`0.999` pass-rate threshold — meaning **up to 0.1% of rows with an unrecognized `EventID` are
allowed to pass into `cleansed_security_event` rather than being quarantined.** When these rows
reach Gold's Phase 4, the `event_type_sk` lookup against the static, manually-curated
`dim_event_type` seed (Phase 1, "refresh rarely," **not** derived from Silver `DISTINCT`, unlike
`dim_host`/`dim_user`/`dim_network_endpoint`) has nothing to resolve to. `fact_security_event
.event_type_sk` is `INT NOT NULL REFERENCES dim_event_type(event_type_sk)` with **no `DEFAULT`**
and no `-1` fallback row exists in `dim_event_type` at all. The row either (a) fails the
`NOT NULL`/`REFERENCES` and the batch load errors, or (b) — more likely in practice on a lakehouse
target where FK constraints aren't physically enforced — silently gets dropped/excluded from the
fact table by whatever `INNER JOIN`-based lookup logic the ETL uses, undercounting real events
with zero visible error.

**Root cause:** `dim_event_type` was designed under the assumption "always resolvable from
EventID+Channel, which are always present" (`star_schema.md` §7), but this conflates "the columns
are always present" with "the specific value combination is always known in advance" — the second
claim is contradicted by the pipeline's own DQ rule #2, which anticipates unknown EventIDs as a
non-blocking, expected event.

**Fix:** Add a `-1` unknown-member row to `dim_event_type` (e.g. `event_id = -1, channel = 'UNKNOWN'`)
and give `fact_security_event.event_type_sk` a `DEFAULT -1`, consistent with every other dimension
in this design. Alternatively, promote `dim_event_type` to a Type-1, Silver-`DISTINCT`-derived
dimension (like `dim_host`) so new combinations self-heal instead of requiring a manual seed update.

---

### H3 — HIGH — Silver's documented partition column doesn't exist in the DDL
**Location:** `docs/medallion/ddl_bronze_silver.sql` `cleansed_security_event` (lines 102–245, no
`event_date` column anywhere) vs. the partitioning comment at lines 252–254:
```sql
-- Partitioning (lakehouse physical layout):
--   PARTITIONED BY (event_date_derived_from_event_utc_time)   -- business date, NOT ingestion date
```

**Failing scenario:** Deploying `cleansed_security_event` on **Delta Lake** — explicitly one of
the two supported target formats per this doc's header ("physical target is a lakehouse table
format (Delta Lake or Iceberg on Parquet)") — as documented. Delta requires partitioning on an
actual physical column (either a plain column populated at write time, or a `GENERATED ALWAYS AS`
computed column declared in the table schema); it has no equivalent to Iceberg's hidden partition
transforms (`days(event_utc_time)`). Since no `event_date` (or any date-typed) column is declared
anywhere in `cleansed_security_event`, `PARTITIONED BY (event_date_derived_from_event_utc_time)`
as written is **not executable** against a Delta target — there is nothing to partition by. Any
attempt to stand this table up on Delta following the doc literally fails at `CREATE TABLE` time.

**Root cause:** The partitioning strategy was described in prose/comment form assuming Iceberg-style
hidden partitioning is universally available, without accounting for Delta's requirement for a
materialized partition column, and without adding that column to the DDL.

**Fix:** Add an explicit `event_date DATE GENERATED ALWAYS AS (CAST(event_utc_time AS DATE))
STORED` (or platform-equivalent generated column) to `cleansed_security_event`, and partition on
that concrete column for Delta; keep `days(event_utc_time)` as the Iceberg-specific alternative
only where the table format actually supports it.

---

### H4 — HIGH — Bronze `event_date` mixes true-UTC dates (Sysmon) with unreconciled local-time dates (everything else)
**Location:** `docs/medallion/ddl_bronze_silver.sql` line 53 (`event_date DATE,` — "date part of
UtcTime (Sysmon rows) else EventTime"); `docs/medallion/medallion_architecture.md` §0 (`EventTime`
is local, observed offset **UTC-4**, not reconciled at Bronze — "not a timezone reconciliation" per
§3.3)

**Failing scenario:** An `EventID 4688` (Security-channel ProcessCreate) fires at
`2020-05-02 02:30:00 UTC` (`EventTime` local = `2020-05-01 22:30:00`, UTC-4). Its Bronze
`event_date` is derived from the **unreconciled** local `EventTime`, landing it in the
`event_date = 2020-05-01` partition. A Sysmon `EventID 1` fired seconds later for a related
process at `2020-05-02 02:30:05 UTC` uses the true-UTC `UtcTime`, landing it in
`event_date = 2020-05-02`. Two events that happened four seconds apart in real time end up in
**different Bronze partitions**, for every event in the ~4-hour window each day where the local
and UTC calendar dates diverge (roughly 20:00–24:00 UTC, i.e. a full quarter of every day). A
backfill/replay query scoped to `event_date = '2020-05-02'` on Bronze silently misses all
non-Sysmon events that occurred between 00:00–04:00 UTC that day (they're filed under
`2020-05-01`), and vice versa for late-day UTC events.

**Root cause:** Bronze's `event_date` derivation is explicitly "best-effort... not a timezone
reconciliation" (self-documented), used as a physical partition key for all four event families
without applying the (already-known, per §0) ~4-hour offset for non-Sysmon rows.

**Fix:** Either (a) accept and document that Bronze `event_date` is ingestion-scoped/approximate
and must never be used for cross-source date-range queries (route all such queries to Silver's
correctly-reconciled `event_date`), or (b) apply the same empirically-discovered
`tz_offset_calibrated` at Bronze write time for the `event_date` envelope column specifically (not
the full reconciliation, just enough to get the date bucket right).

---

### M1 — MEDIUM — `fact_security_event.channel` is directly filterable and ambiguous (WFP vs. Windows Security auditing)
**Location:** `docs/schema/ddl.sql` line 285 (`channel VARCHAR(80) NOT NULL`, on the fact itself)
vs. `dim_event_type.log_source` (line 233, only reachable via a join);
`docs/medallion/medallion_architecture.md` §0 ("WFP... shares Channel = 'Security'... `log_source`
cannot be derived from Channel alone")

**Failing scenario:** `SELECT COUNT(*) FROM fact_security_event WHERE channel = 'Security'`,
written by an analyst who reasonably expects this to mean "Windows Security auditing events,"
silently also includes every WFP event (5156/5158/5447), which the design's own profiling
confirms share the exact same `Channel` string. The corrected filter
(`event_type_sk IN (SELECT event_type_sk FROM dim_event_type WHERE log_source = 'windows_security')`)
requires knowing to join `dim_event_type` — nothing on the fact table itself warns that
`channel = 'Security'` is not equivalent to "Windows Security auditing only."

**Root cause:** The disambiguating attribute (`log_source`) is correctly modeled, but only in
`dim_event_type`, not denormalized onto the fact — while the raw, ambiguous `channel` column sits
directly on the fact table, inviting the natural-but-wrong direct filter.

**Fix:** Either denormalize `log_source` onto `fact_security_event` as a degenerate column
(cheap — one more low-cardinality VARCHAR at this row count), or rename the fact's `channel`
column to make its ambiguity explicit (e.g. `raw_channel`) and add a code comment pointing at
`dim_event_type.log_source` as the correct filter target.

---

### M2 — MEDIUM — Bronze `event_date` is nullable and used as a partition column
**Location:** `docs/medallion/ddl_bronze_silver.sql` line 53: `event_date DATE,` (no `NOT NULL`)

**Failing scenario:** A line fails JSON parsing (`parse_error = TRUE`, `raw_json = NULL`) or has a
malformed/missing timestamp field on a non-Sysmon channel — `event_date` has nothing to derive
from and is `NULL`. On a partitioned lakehouse table, `NULL` partition values are bucketed into a
default/catch-all partition that predicate-pushdown queries filtering `WHERE event_date =
'2020-05-01'` do not scan — these malformed/edge-case rows become invisible to any date-scoped
query, and (if parse failures cluster, e.g. a bad batch) that catch-all partition can also grow
disproportionately large (skew), degrading full-table scans that do need to see it.

**Root cause:** No `NOT NULL` constraint or `COALESCE(..., DATE '1900-01-01')`-style sentinel is
applied to a column used as a physical partition key.

**Fix:** Make `event_date` `NOT NULL` with an explicit sentinel value (e.g. `DATE '1900-01-01'`,
mirroring Gold's `dim_date` unknown-member convention) for rows where no timestamp is derivable, so
these rows land in a known, queryable partition instead of an implicit NULL bucket.

---

### M3 — MEDIUM — `dim_network_endpoint.ip_address` stored as `VARCHAR(45)`, blocking CIDR/range queries
**Location:** `docs/schema/ddl.sql` line 203: `ip_address VARCHAR(45) NOT NULL`

**Failing scenario:** `SELECT * FROM fact_security_event f JOIN dim_network_endpoint e ON
f.destination_endpoint_sk = e.endpoint_sk WHERE e.ip_address <<= '10.0.0.0/8'`-style CIDR
containment queries (a routine SOC analysis: "did anything talk to our internal RFC1918 range")
have no native operator to use against a plain `VARCHAR`. The workaround — string-prefix matching
(`LIKE '10.%'`) — is both semantically wrong for non-octet-aligned prefixes (e.g. `10.0.0.0/12`
cannot be expressed as a string prefix at all) and unusable for IPv6. There is also no numeric
representation to support ordered range scans.

**Root cause:** No `INET`/numeric (or split hi/lo `BIGINT` for IPv6) representation is carried
alongside the display-string `ip_address`.

**Fix:** Add a numeric column (e.g. `ip_numeric NUMERIC(39,0)` or platform `INET`/`IPADDRESS` type
where supported) derived at load time, or at minimum a precomputed `/8`, `/16`, `/24` prefix column
for common SOC subnet filters, alongside the existing display string.

---

### M4 — MEDIUM — Joining `fact_security_event` to `dim_process` on `process_guid` (not `process_sk`) fans out across SCD2 versions
**Location:** `docs/schema/ddl.sql` `dim_process` (Type 2, multiple rows per `process_guid`) and
`fact_security_event.process_sk`

**Failing scenario:** An analyst, working from the natural identifier they actually recognize
(`ProcessGuid`), writes `SELECT COUNT(*) FROM fact_security_event f JOIN dim_process dp ON
f.process_sk = dp.process_sk` correctly at first, but for a "how many times did this process touch
the registry" investigation naturally reaches for `... JOIN dim_process dp ON
<some derived process_guid> = dp.process_guid` (e.g. joining two fact rows through their shared
`process_guid` rather than through `process_sk`) — every `dim_process` row that shares that
`process_guid` (multiple SCD2 versions) matches, multiplying the row count by however many
attribute versions exist for that process. Nothing on the schema prevents this — there is no
enforced `is_current` filter and no documented warning against natural-key joins on `dim_process`
specifically (unlike, say, the explicit warning against using `ProcessId` as a key).

**Root cause:** SCD2's structural property (1 natural key → N surrogate rows) is not called out as
a query hazard anywhere in `star_schema.md`, even though the anti-pattern table (§8) explicitly
flags "natural/mutable key as PK/FK" for `ProcessGuid` vs. `ProcessId` but not this distinct
fan-out risk from joining on the natural key at query time.

**Fix:** Document the hazard explicitly (BI/analyst-facing note: "always join fact to `dim_process`
via `process_sk`, never `process_guid`, to avoid double-counting across SCD2 versions"), and
consider exposing a `dim_process_current` view (`WHERE is_current = TRUE`) as the safe, pre-filtered
surface for ad hoc natural-key joins.

---

### M5 — MEDIUM — `GENERATED ALWAYS AS IDENTITY` surrogate keys are incompatible with the stated lakehouse targets and load pattern
**Location:** `docs/schema/ddl.sql` lines 80, 107, 150, 202 (`dim_host`, `dim_user`, `dim_process`,
`dim_network_endpoint`); self-acknowledged (not remediated) in
`docs/medallion/medallion_architecture.md` §6.2

**Failing scenario:** Standing up `dim_host`/`dim_user`/`dim_process`/`dim_network_endpoint` on
**Iceberg** (the doc's other explicitly-named target format) fails outright — Iceberg has no
`GENERATED ALWAYS AS IDENTITY` construct at all. On Delta, these dimensions are documented (§7 of
`medallion_architecture.md`) to load via **incremental `MERGE` (upsert)**, which is precisely the
write pattern identity-sequence columns are documented to behave unpredictably with under
reprocessing/parallel writers (re-matched rows can get new IDs, or ID assignment isn't
deterministic across reruns) — the medallion doc itself names this exact risk and recommends a
deterministic hash surrogate instead, but `ddl.sql` (the "committed" artifact) still ships the
identity-column version unmodified.

**Root cause:** A known, documented incompatibility between the committed Gold DDL and the actual
deployment targets/load pattern was flagged as a "note against the DDL" rather than fixed in the
DDL.

**Fix:** Replace `GENERATED ALWAYS AS IDENTITY` with a deterministic hash surrogate (e.g.
`process_sk = hash(process_guid, effective_from)`) for any dimension loaded via incremental
`MERGE`, per the mitigation already described (but not applied) in `medallion_architecture.md`
§6.2 — at minimum for `dim_process`, which has real version churn; the small Type-1 dimensions are
lower risk but should follow the same pattern for consistency and Iceberg compatibility.

---

### M6 — MEDIUM — No Z-order/clustering/partition-transform directive for the Gold fact table; B-tree `CREATE INDEX` statements are no-ops on the stated targets
**Location:** `docs/schema/ddl.sql` lines 380–384

**Failing scenario:** `ix_fact_event_date`, `ix_fact_event_host`, `ix_fact_event_type`,
`ix_fact_event_process`, `ix_fact_event_utc_time` are declared as standard B-tree secondary
indexes. Neither Delta Lake nor Iceberg on Parquet use B-tree secondary indexes for query
acceleration — file/row-group skipping comes from partitioning, Z-order (Delta) or sort-order /
hidden partitioning + column stats (Iceberg), none of which are specified for `fact_security_event`
anywhere in either DDL file (partitioning is explicitly deferred, per the file's own header
comment, but no placeholder or TODO calls out that the `CREATE INDEX` lines themselves are inert on
those targets). A team deploying literally from this DDL could reasonably believe "yes, `host_sk`
and `event_utc_time` lookups are indexed" and be surprised by full-partition scans in production.

**Root cause:** DDL was kept "generic ANSI SQL, portable... with minor type-name substitution," but
indexing strategy does not port the same way partitioning/type syntax does — B-tree indexes have no
lakehouse equivalent, only a different mechanism (clustering keys) achieves a similar goal.

**Fix:** Replace the `CREATE INDEX` block with an explicit note plus concrete clustering directive
for the actual target, e.g. Delta `OPTIMIZE fact_security_event ZORDER BY (host_sk, event_utc_time,
process_sk, event_type_sk)` or Iceberg `WRITE ORDERED BY (host_sk, event_utc_time)` /
sort-compaction policy — covering exactly the high-selectivity SOC query columns (event time,
host, process, event type; IP columns live on the sparse `dim_network_endpoint`, lower priority).

---

### L1 — LOW / PLAUSIBLE — `dim_network_endpoint`'s documented natural key doesn't match its implemented uniqueness constraint
**Location:** `docs/schema/star_schema.md` line 169 ("Natural key: `ip_address` (+ `is_ipv6` to
disambiguate representation)") vs. `docs/schema/ddl.sql` line 208
(`CONSTRAINT uq_dim_network_endpoint_ip UNIQUE (ip_address)` — `is_ipv6` not included)

In practice a given IP address string is unambiguous with respect to family (an IPv4 dotted-quad
string is never valid IPv6 notation), so this likely causes no real-world collision in this
dataset — flagged as **PLAUSIBLE**, not confirmed, but worth reconciling: if the load logic ever
attempts an upsert keyed on the doc's stated composite `(ip_address, is_ipv6)`, it will collide
against the DDL's single-column uniqueness, and any genuinely conflicting `is_ipv6` signal for
the same string would be silently dropped/overwritten under the Type 1 policy instead of raising
a DQ flag. **Fix:** align the doc and DDL — drop `is_ipv6` from the stated natural key (it's
derivable from `ip_address` format) or add it to the `UNIQUE` constraint, whichever matches actual
load logic.

### L2 — LOW / PLAUSIBLE — `dim_date` has no "out of generated range" fallback, only "unparseable"
**Location:** `docs/schema/ddl.sql` lines 25–41; `docs/schema/star_schema.md` §7

Only the `19000101` "unparseable timestamp" sentinel exists; a **parseable** date outside the
generated calendar range (currently 2020-05-01/02 "plus buffer") has no defined fallback. On a
lakehouse target, FK constraints are typically not physically enforced, so such a fact row would
silently load with an orphaned `date_sk`, and `INNER JOIN fact TO dim_date` would drop it. Not
observable in the current fixed 2-day dataset (**PLAUSIBLE**, forward-looking only) but relevant
the moment this pipeline runs continuously. **Fix:** extend calendar generation well beyond the
known load window, or add an explicit "date not yet in dim_date" late-arriving-member handling
path analogous to the one already specified for `dim_host`/`dim_user`/`dim_network_endpoint`
(§6.4 of `medallion_architecture.md`).

### L3 — LOW — `dim_time.is_business_hours` semantics are ambiguous (UTC vs. local)
**Location:** `docs/schema/ddl.sql` line 61 (`is_business_hours ... -- reference convention, e.g.
Mon-Fri 08-18 local; adjust in load script`)

`time_sk` is derived from the canonical **UTC** `event_utc_time` (per `star_schema.md` §6), but
"business hours" is inherently a local-time concept, and the column comment self-flags this
without specifying a mechanism (which host's local offset? the design has 4 hosts, potentially
different offsets in a real deployment). Not a confirmed defect against this fixed, single-offset
dataset, but a genuine ambiguity that will produce wrong "outside business hours" security signals
the moment hosts span time zones. **Fix:** either explicitly state `dim_time`/`is_business_hours`
are UTC-referenced (and rename to avoid the "local" implication), or add a per-host offset join at
query time instead of baking a single convention into the static seed.

---

## Verified OK (checked, no defect found)

- **Dedup / natural key** `(source_file, hostname_nk, channel, record_number)` — correctly requires
  `source_file` as a non-optional component; this is empirically justified in the docs (1,631
  confirmed cross-file collisions mapping to genuinely different events) and is implemented
  identically across Silver (`uq_silver_event_nk`) and Gold (`uq_fact_security_event_nk`) with no
  drift between the two.
- **`-1` unknown-member convention** is correctly implemented with `NOT NULL DEFAULT -1` FKs for
  `dim_date`, `dim_time`, `dim_host`, `dim_user`, `dim_process`, `dim_network_endpoint` — genuinely
  prevents `INNER JOIN` row loss for those six dimensions. (`dim_event_type` is the sole exception —
  see H2.)
- **`log_source` derivation** correctly branches on `EventID` ranges rather than trusting `Channel`
  alone, correctly handling the confirmed WFP/`Channel='Security'` collision at the point where the
  value is computed (Silver). The gap is only that the computed value isn't exposed on the fact
  table (see M1) — the derivation logic itself is sound.
- **Canonical timestamp handling** — `event_utc_time` is properly typed `TIMESTAMP` (not a string)
  throughout Silver and Gold, and the per-host TZ offset is empirically discovered per load batch
  rather than hardcoded, avoiding a DST/collector-reconfiguration trap.
- **`ProcessGuid` (not `ProcessId`) used as the process natural key/dimension key everywhere** —
  correctly avoids PID-recycling corruption; `ProcessId` is retained only as an informational,
  non-key attribute, exactly as documented.
- **`dim_host`/`dim_user`/`dim_network_endpoint` self-healing from Silver `DISTINCT` extracts**
  (Phase 2) correctly avoids the late-arriving-dimension orphan risk that `dim_event_type` (a
  static, non-self-healing seed) is exposed to.
- **Bronze append-only / no-transform contract** is genuinely upheld — no business logic,
  reconciliation, or dedup happens in the Bronze DDL; `parse_error` rows are landed, never dropped.

---

**Confidence:** 0.90 | **Impact:** HIGH (Gold-layer correctness and Delta/Iceberg deployability)
**Sources:** Direct DDL/prose cross-reference of `docs/schema/ddl.sql`,
`docs/medallion/ddl_bronze_silver.sql`, `docs/schema/star_schema.md`,
`docs/medallion/medallion_architecture.md`, `docs/data_profile.md`. C1/C2/H1/H3/H4/H2/M1/M2/M3/M6
are CONFIRMED directly from cited line-level DDL/SQL text; M4/M5 are CONFIRMED as documented design
gaps (self-acknowledged or structurally evident) rather than inferred; L1/L2/L3 are marked
PLAUSIBLE — real risk given the stated design, not independently confirmed against actual data
beyond what the source docs already state.
