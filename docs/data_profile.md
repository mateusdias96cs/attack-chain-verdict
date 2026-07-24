# Data Profile — dadosdia1.json / dadosdia2.json

## Source
Windows security telemetry (MITRE ATT&CK "dmevals" / APT29 evaluation dataset).
Format: **JSONL / NDJSON** (one JSON object per line), NOT a JSON array.
Collected via NXLog (`im_msvistalog`) → Logstash (`@timestamp`, `@version`, `tags`, `host`, `port`).

| File | Records |
|------|---------|
| dadosdia1.json | 196,081 |
| dadosdia2.json | 587,286 |

## Event sources (mixed in one stream, discriminated by EventID + Channel)
- **Sysmon** (`Microsoft-Windows-Sysmon/Operational`): EventID 1–23
  - 1 ProcessCreate, 3 NetworkConnect, 7 ImageLoad, 8 CreateRemoteThread,
    10 ProcessAccess, 11 FileCreate, 12 RegistryCreateDelete, 13 RegistrySetValue,
    22 DNSQuery, 23 FileDelete
- **Windows Security** (`Security`): 4656, 4658, 4663 (object access), 4688 (proc create),
    4690, 4703, 4624/4625 (logon)
- **PowerShell** (`Windows PowerShell` / `Microsoft-Windows-PowerShell`): 800, 4103, 4104
- **Windows Filtering Platform**: 5156, 5158, 5447

## EventID distribution (day1 / day2)
Registry (12/13) and ProcessAccess (10) dominate; PowerShell (800/4103) heavy on day2.

## Field density facts
- **Network fields are SPARSE (~0.4–0.6% of rows)** — only NetworkConnect + WFP events.
  - Populated: SourceIp, DestinationIp, SourcePort, DestinationPort, Protocol,
    SourceIsIpv6, DestinationIsIpv6, Initiated
  - **SourceHostname / DestinationHostname are always empty** — DNS resolution not present in most.
- Cardinality: **4 distinct Hostnames**, ~9–12 distinct Users → small conformed dims.

## Timestamp fields (multiple, need reconciliation)
- `UtcTime` — Sysmon event time (UTC, ms precision) → **canonical event time**
- `EventTime` — local collector time
- `@timestamp` — Logstash ingest time (ISO8601 Z)
- `EventReceivedTime`, `CreationUtcTime` (event-specific)

## Key identity / correlation fields
- Process: `ProcessGuid`, `ProcessId`, `Image`, `Hashes`, `SourceProcessGUID`, `TargetProcessGUID`
- Host: `Hostname`, `host` (collector)
- User: `User`, `AccountName`, `Domain`, `UserID` (SID), `SubjectUserSid`
- Network: Source/Destination Ip/Port/IsIpv6, Protocol
- File: `TargetFilename`, `Image`, `ImageLoaded`
- Registry: `TargetObject`, `Details`
- Event: `EventID`, `Channel`, `SourceName`, `Task`, `RuleName`, `Message`

## Modeling implications
- Heterogeneous event schema → central **fact_security_event** at grain = 1 event.
- Event-type-specific attributes (network, file, registry, process-access) belong in
  satellite/sub-dimension tables or nullable columns keyed by EventID.
- Network endpoint (IP + port + protocol) is a natural conformed dimension despite sparsity.
