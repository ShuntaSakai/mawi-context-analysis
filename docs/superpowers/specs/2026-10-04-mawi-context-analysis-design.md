# MAWI Context Analysis Design

Date: 2026-10-04
Repository: `mawi-context-analysis`
Status: Approved

## 1. Goal

Build a compact, reproducible tool that identifies TCP/UDP flows observed with 1–3 packets in a designated 15-minute MAWI capture, then extracts enough 24-hour packet context to analyze those flows later without rescanning the original 24-hour PCAP set.

The tool is designed around two constraints:

1. heavy PCAP processing should be completed while a high-performance laboratory server is available;
2. the resulting dataset must be portable to lower-capacity machines and reusable for later 1-, 2-, and 3-packet analysis and future Scan-like redefinitions.

The core research dataset is observational. Scan-like, benign, malicious, anomaly, and other interpretive labels are not part of extraction.

## 2. Research definition

### 2.1 Target observation window

A user-selected 15-minute chunk is the target window. The initial experiment uses:

- day: `2026-04-08`
- target chunk: `202604081400`
- window: 14:00–14:15

The implementation must not hard-code this date or chunk.

### 2.2 Flow definition

Only TCP and UDP are flow-aggregated.

A flow key is a direction-independent bidirectional 5-tuple:

- endpoint A IP
- endpoint A port
- endpoint B IP
- endpoint B port
- transport protocol

The target 15-minute capture is aggregated with no inactivity timeout. Therefore, every validly decoded TCP/UDP packet in the target capture that belongs to the same normalized bidirectional 5-tuple contributes to the same observed flow, even when packets are separated by a long gap inside the 15-minute window.

The stored `src_*` / `dst_*` fields retain the direction of the first observed packet for that flow. They are observational fields and must not be interpreted automatically as client/server, initiator/responder, attacker/victim, or internal/external roles.

### 2.3 1–3 packet observed flows

A target flow belongs to the cohort when its packet count in the target 15-minute observation window is in the configured set. The initial configuration is `{1, 2, 3}`.

The research meaning is therefore:

> a flow observed with N validly decoded TCP/UDP packets in the designated 15-minute window

not:

> a communication that truly consists of only N packets over its complete lifetime.

This distinction must be preserved in code names, documentation, manifests, and later analysis.

### 2.4 Target interval

For each target flow:

- `target_start_time` is the timestamp of the first packet observed in the target 15-minute window;
- `target_end_time` is the timestamp of the last packet observed in the target 15-minute window.

For a 1-packet observed flow, these values are equal.

The interval is an observation-window interval, not a claim about the real beginning or end of the communication.

### 2.5 Packet decode policy (focused amendment, 2026-10-05)

Capture container corruption remains fatal. PCAP/PCAPNG/gzip corruption, record-boundary failures and truncated containers raise `CaptureError`; they invalidate the affected extraction and must never become packet skips. Independent chunk failure handling and parent-side raw-deletion prerequisites remain unchanged.

When a `CaptureRecord` is read successfully but its Ethernet/IP/TCP/UDP declarations do not safely provide the required TCP/UDP flow facts, `PacketDecodeError` is a per-packet network/transport decode failure: exclude that packet from flows, cohort counts and both observation streams, count its stable reason, and continue. Never guess a 5-tuple, force port-zero flow membership, repair an invalid Data Offset, zero-fill truncated bytes, or suppress arbitrary exceptions.

Target flow extraction and 24-hour observation extraction must apply this same skip-and-count policy. Existing `non_ip`, `non_tcp_udp`, `capture_truncated_undecodable` and `ip_fragment` exclusions remain counted. A skip is never silent. The 1/2/3 cohort means validly decoded TCP/UDP packet counts in the configured 15-minute window, not counts of all declared TCP/UDP packets or a complete communication lifetime. Retention of valid packets, direction, SYN/source selection, lengths and payload policy are unchanged.

The reported laboratory smoke on target `202604081400` stopped at packet index `5968733`, timestamp `1775624416.966622`, after `4763795` decoded packets and `1204937` counted skips (`29430` capture-truncated, `10328` fragments, `7923` non-IP, `1157256` non-TCP/UDP); accounting totals `5968732` preceding records. Its synthetic regression models Ethernet/IPv4 IHL 20, total length 72, protocol 6, DF-only `0x4000`, captured/original lengths 54/86, zero ports, TCP Data Offset 0 and flags 0. The minimum 20 TCP bytes are captured, so the reason is `malformed_tcp_header_length`, not `capture_truncated_undecodable`. No real MAWI bytes enter the repository, and this amendment's validation is synthetic only.

## 3. Context source identity

Each target flow receives a `context_source_ip` and a `context_source_basis`.

For TCP:

1. if a plain initial SYN (`SYN=1, ACK=0`) sender can be identified in the target 15-minute flow, use that IP;
2. otherwise use the source IP of the first observed packet.

For UDP:

- use the source IP of the first observed packet.

`context_source_basis` records the evidence used, for example:

- `initial_syn_sender`
- `first_observed_src`

This field exists so later analysis can distinguish confidently identified TCP initiators from fallback observational direction.

## 4. High-level architecture

The system has two major stages.

### 4.1 Heavy extraction stage

Run on the high-performance laboratory server:

1. acquire the target 15-minute PCAP;
2. extract bidirectional TCP/UDP flows;
3. write the full target-window flow table;
4. select the 1–3 packet observed cohort;
5. build read-only lookup indexes for target FlowKeys and candidate context-source IPs;
6. acquire the 96 fifteen-minute chunks that constitute the requested 24-hour day;
7. scan independent chunks in parallel;
8. write portable raw observation caches in Parquet;
9. validate each cache;
10. delete a raw PCAP only after successful cache validation.

### 4.2 Lightweight aggregation stage

Run from the portable dataset, potentially on another machine:

1. validate the portable dataset and all 96 chunk caches;
2. read Parquet observations without accessing MAWI or original PCAPs;
3. derive 24-hour context statistics;
4. publish separate but schema-identical CSV results for flows observed with 1, 2, and 3 packets;
5. support later analysis code, including future Scan-like definitions, without modifying the immutable observation cache.

## 5. Raw observation model

Raw observation artifacts preserve packet facts needed for later analysis. They do not store interpretations such as Scan-like, anomaly, successful connection, response classification, maliciousness, or benignness.

### 5.1 Target tuple observations

For every 15-minute chunk, save every validly decoded TCP/UDP packet whose normalized bidirectional 5-tuple matches a target cohort flow.

Recommended columns:

- `target_flow_id`
- `packet_index`
- `timestamp`
- `ip_version`
- `protocol`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `captured_frame_length`
- `original_frame_length`
- `ip_total_length`
- `transport_payload_length`
- `tcp_flags_raw`

`target_flow_id` links to the target cohort.

The cache does not precompute forward/reverse direction, before/after classification, gap values, or Scan-like labels. Those are derived later from the target cohort and packet facts.

### 5.2 Source context observations

Source-context packets are stored once per observed packet within each chunk, not duplicated once per target flow.

Recommended columns:

- `packet_index`
- `timestamp`
- `ip_version`
- `protocol`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `captured_frame_length`
- `original_frame_length`
- `ip_total_length`
- `transport_payload_length`
- `tcp_flags_raw`

Retention policy:

For TCP, retain a packet when:

- a candidate `context_source_ip` is either the packet source or destination; and
- at least one of SYN, RST, or FIN is set. This includes SYN/ACK packets because SYN is set.

ACK-only packets and ordinary data packets are not retained solely for source context.

For UDP, retain a packet when:

- the packet source IP is a candidate `context_source_ip`.

All matching outbound UDP packets are retained because UDP has no TCP-style connection-control flags.

### 5.3 Payload policy

Application payload bytes are never persisted in the portable observation cache.

The cache may retain decoded length facts such as `transport_payload_length`, but not HTTP bodies, DNS payload contents, or other application data.

### 5.4 TCP flags

`tcp_flags_raw` is the canonical stored fact. Human-friendly booleans or labels such as `is_syn`, `is_rst`, or `SYN_ACK` are derived during later analysis when useful.

## 6. Cohort and flow artifacts

The target-window flow table is persisted as CSV for provenance and later inspection.

The cohort is stored in one `target_cohort.csv`, not separate 1-, 2-, and 3-packet cohort files.

Recommended cohort columns include:

- `target_flow_id`
- `observed_packet_count`
- `ip_version`
- `protocol`
- `src_ip`
- `src_port`
- `dst_ip`
- `dst_port`
- `target_start_time`
- `target_end_time`
- `target_duration`
- `initial_syn_sender_ip`
- `initial_syn_sender_port`
- `initial_syn_receiver_ip`
- `initial_syn_receiver_port`
- `context_source_ip`
- `context_source_basis`

The cohort is the single source of truth for 1-, 2-, and 3-packet membership. Later analysis filters on `observed_packet_count`.

## 7. Artifact formats

Use:

- CSV for the target flow table, target cohort, and final analysis results;
- Parquet for packet-level raw observation caches;
- JSON for manifests and provenance.

SQLite or TablePlus-specific artifacts are not part of the product.

Parquet is chosen for the large reusable observation layer because it is compact, columnar, portable, and efficient to reread on another machine.

## 8. Portable dataset layout

The extraction output is a self-contained portable dataset. Manifests must use dataset-relative artifact paths rather than machine-specific absolute paths.

Illustrative layout:

```text
portable_dataset/
├── dataset_manifest.json
├── provenance/
│   ├── flows.csv
│   └── flow_manifest.json
├── cohort/
│   ├── target_cohort.csv
│   └── cohort_manifest.json
└── observations/
    ├── 202604080000/
    │   ├── target_packets.parquet
    │   ├── source_context_packets.parquet
    │   └── manifest.json
    ├── 202604080015/
    │   └── ...
    └── 202604082345/
        └── ...
```

A copied dataset must remain valid when moved from the laboratory Ubuntu server to another machine.

## 9. Provenance and identity

Each durable artifact must be identity-checked before reuse.

At minimum, manifests record enough information to establish:

- requested day;
- target chunk;
- configured target packet counts;
- flow definition;
- inactivity timeout (`null` for the target-window flow extraction in the initial design);
- context-source policy;
- raw source chunk identity;
- source URL or source identifier where available;
- source SHA-256;
- source size;
- schema version;
- cohort identity;
- tool/code identity;
- artifact relative path;
- artifact SHA-256;
- row count;
- status.

The top-level `dataset_manifest.json` records the expected 96 chunks, their completion state, and dataset-wide identity.

Local absolute paths are not part of durable dataset identity.

`provenance/flow_manifest.json` stores the whole target capture's `skipped_packet_counts`; every `observations/<chunk>/manifest.json` stores the whole chunk scan's map, including exclusions unrelated to cohort tuples or candidate sources. Keys are stable allowlisted snake_case codes, values are nonnegative integers (booleans, floats and coercions are rejected), and serialization is sorted/canonical. Empty maps and omitted zero-count reasons are allowed. Human-readable error messages remain diagnostics, never durable reason identity.

Allowed decode-failure codes are `packet_header_exceeds_declared_length`, `incomplete_packet_header`, `ethernet_ip_version_mismatch`, `malformed_ipv4_length`, `ipv4_length_exceeds_original_frame_length`, `ipv6_length_exceeds_original_frame_length`, `malformed_ipv6_authentication_header_length`, `malformed_tcp_header_length` and `malformed_udp_length`, in addition to the four existing exclusions in §2.5. Validators reject missing/invalid maps, unknown codes and old semantic identities on reuse and portable aggregation. Aggregation also requires the target chunk's skip map to agree with target flow provenance for the same raw source. These are descriptive extraction provenance, not result classifications or additional context CSV metrics. Structural validation cannot reconstruct scan counts without raw captures or authenticate coordinated edits to otherwise valid manifests.

This amendment uses `flow-manifest-v2`, `chunk-manifest-v2` and tool extraction identity `v2` (package version remains `0.1.0`). The dataset's `observation_schemas.chunk_manifest` becomes `chunk-manifest-v2`. Old extraction-v1 evidence must fail explicitly rather than be relabeled or silently reused. `dataset-manifest-v1`, `cohort-manifest-v1`, `flows-v1`, `cohort-v1`, `target-packets-v1`, `source-context-packets-v1` and all result CSV columns remain unchanged because their structures/columns are unchanged.

## 10. Download, spool, and parallel execution

### 10.1 Bounded producer-consumer pipeline

The system must not require all 96 raw PCAPs to fit on local storage at once.

Use a bounded pipeline:

- a small download concurrency, initially 1–2;
- a bounded raw-PCAP spool;
- `ProcessPoolExecutor` for independent chunk scans;
- a user-configurable scan worker count.

Download work and CPU/scan work should overlap so workers do not wait unnecessarily for network I/O.

The 96 tasks do not imply 96 simultaneous workers.

### 10.2 Worker ownership

One scan worker owns one chunk task at a time.

A worker may:

- read its assigned raw PCAP;
- read its initialized lookup indexes;
- write only to a unique staging directory for its assigned chunk.

A worker must not:

- update the top-level dataset manifest;
- modify another chunk directory;
- delete raw PCAPs;
- write shared progress state.

### 10.3 Worker initialization

Target FlowKey and candidate source-IP indexes should be constructed once per worker process and reused across multiple chunk tasks handled by that worker.

The first implementation uses straightforward Python lookup structures such as `set`. More complex memory-sharing strategies are deferred unless measurement demonstrates a need.

### 10.4 Staging and publication

Chunk artifacts are written under a unique staging directory.

Before publication, verify at least:

- Parquet files are readable;
- schema is exact;
- row counts are non-negative and consistent;
- checksums are computed;
- chunk identity matches;
- cohort identity matches.

Only after successful validation is the staging directory atomically renamed to the final chunk directory.

An official chunk directory therefore represents a fully published cache, not a partially written result.

### 10.5 Parent-side validation and deletion

A worker success result is not sufficient to delete a raw PCAP.

The parent process independently validates the completed chunk cache. Only after parent validation succeeds may the corresponding raw PCAP and transient download metadata be removed.

### 10.6 Resume behavior

Rerunning the same extraction command should automatically reuse compatible completed caches.

For each expected chunk:

- valid completed cache: validate and reuse, no download or rescan;
- valid already-downloaded raw PCAP with matching transient metadata: reuse and scan;
- missing chunk: download and scan;
- identity-mismatched or malformed cache: fail explicitly rather than silently overwrite it.

A dedicated `--resume` flag is not required for normal reuse.

### 10.7 Failure policy

The default behavior is not global fail-fast.

If one chunk fails to download or scan, the system continues processing independent chunks when safe. The run ends incomplete and reports failed chunks. A later rerun attempts only work that is not already valid.

A scan failure is not automatically retried repeatedly in the same run. Network downloads may use a small bounded retry policy.

## 11. 24-hour aggregation

Aggregation operates only on the portable dataset. It must not require:

- Internet access;
- MAWI access;
- raw PCAP files;
- the laboratory server.

### 11.1 Target tuple context

For every target flow, derive at least:

- `same_tuple_packet_count_24h`
- `same_tuple_before_count`
- `same_tuple_target_interval_count`
- `same_tuple_after_count`
- `previous_same_tuple_timestamp`
- `previous_same_tuple_gap_seconds`
- `next_same_tuple_timestamp`
- `next_same_tuple_gap_seconds`

Target-relative neighborhood counters should support initially:

- 1 second
- 10 seconds
- 60 seconds
- 300 seconds

For a multi-packet observed flow:

- a before-N-second count is relative to `target_start_time`;
- an after-N-second count is relative to `target_end_time`.

This gives 1-, 2-, and 3-packet flows one consistent interval-based definition.

### 11.2 Source context statistics

Derived source-level features remain descriptive rather than interpretive.

Potential initial TCP features include:

- TCP control-packet count;
- SYN count;
- SYN/ACK count;
- RST count;
- FIN count;
- unique destination IP count;
- unique destination port count;
- unique destination IP/port pair count;
- the same categories over selected target-relative windows such as 60 and 300 seconds.

Potential UDP features include:

- outbound UDP packet count;
- unique destination IP count;
- unique destination port count;
- unique destination IP/port pair count;
- corresponding target-relative window values where useful.

No `scan_like`, `malicious`, `benign`, or anomaly label is produced by this stage.

### 11.3 Result separation

Publish separate result directories for flows observed with 1, 2, and 3 packets, with identical CSV schemas.

Illustrative layout:

```text
results/
└── <dataset-id>/
    ├── packet_count_1/context.csv
    ├── packet_count_2/context.csv
    └── packet_count_3/context.csv
```

The separation is for staged analysis convenience. Cohort and raw observation caches remain shared.

### 11.4 Memory behavior

Aggregation must not require concatenating all 96 Parquet files into one in-memory DataFrame.

The design must support bounded processing, such as chunk-wise aggregation and, if needed, temporary disk-backed state. The exact disk-backed implementation is an implementation choice and must be selected only after measuring complexity and resource needs.

## 12. CLI

Use one command-line application with separate heavy and light stages.

Initial interface:

```bash
uv run mawi-context extract \
  --day 2026-04-08 \
  --target-chunk 202604081400 \
  --packet-counts 1 2 3 \
  --workers 16
```

and:

```bash
uv run mawi-context aggregate \
  --dataset /path/to/portable_dataset
```

The initial public CLI should stay small. Advanced download concurrency and prefetch/spool controls remain internal defaults until measurement shows users need to tune them.

The source acquisition implementation must validate how the requested 24-hour MAWI source maps to 96 chunks before real-data execution. Source URL construction is an acquisition concern and must not leak into aggregation.

## 13. Repository structure

Repository name: `mawi-context-analysis`

Proposed structure:

```text
mawi-context-analysis/
├── README.md
├── AGENTS.md
├── pyproject.toml
├── src/
│   └── mawi_context/
│       ├── cli.py
│       ├── capture.py
│       ├── flow.py
│       ├── cohort.py
│       ├── downloader.py
│       ├── observations.py
│       ├── extraction.py
│       ├── aggregation.py
│       ├── manifests.py
│       └── hashing.py
├── tests/
│   ├── unit/
│   └── integration/
├── notebooks/
├── docs/
│   └── superpowers/
│       ├── specs/
│       └── plans/
├── data/
└── results/
```

This repository deliberately omits Aguri, prefix selection, existing Broad/Strict Scan-like removal logic, and unrelated experiment machinery from `mawi-global-analysis`.

## 14. README.md role

The root `README.md` should follow the useful entry-point style of `mawi-global-analysis`, but describe only this repository.

It should cover:

- research goal;
- concise data-flow diagram;
- the meaning of 1–3 packet observed flows;
- separation between extraction and aggregation;
- setup with `uv`;
- basic `extract` and `aggregate` commands;
- portable dataset concept;
- directory guide;
- warning that Scan-like interpretation is deliberately outside raw extraction.

## 15. AGENTS.md role

The root `AGENTS.md` is the entry point for AI coding agents.

It must state repository-wide research and safety rules, including:

- work on `main` unless the human requests another workflow;
- do not create branches/worktrees unless explicitly requested;
- preserve unrelated human changes;
- do not commit, push, rebase, merge, tag, or otherwise rewrite Git history unless requested;
- leave changes uncommitted for human review by default;
- do not change the bidirectional 5-tuple definition casually;
- do not reinterpret `src`/`dst` as semantic roles;
- preserve the 15-minute observational definition of 1–3 packet flows;
- do not insert Scan-like or anomaly labels into raw observation extraction;
- treat portable Parquet caches as immutable research artifacts;
- do not bypass manifest/checksum/provenance validation;
- workers may write only their assigned chunk staging area;
- do not delete a raw PCAP before validated durable cache publication;
- keep aggregation independent from raw PCAPs, Internet access, and MAWI availability;
- treat research-semantics, cache-identity, schema, or provenance changes as design changes rather than routine refactors;
- run tests appropriate to the change and distinguish fixtures from real-data validation;
- report changed files, verification commands/results, known issues, and exactly one suggested commit-message line at completion.

The repository does not need to copy all documentation structure from `mawi-global-analysis`; `README.md`, `AGENTS.md`, the approved design spec, and implementation plans are sufficient initially.

## 16. Dependencies

Keep the first implementation intentionally small.

Expected core dependencies:

- Python 3.12
- `dpkt`
- `pandas`
- `pyarrow`

Use the Python standard library for process parallelism, primarily `concurrent.futures.ProcessPoolExecutor`.

Do not introduce Ray, Dask, Spark, or another distributed framework unless measurements later demonstrate a clear need.

## 17. Performance requirements

Analysis latency is a product requirement, not merely an implementation detail.

Benchmark at least scan-worker counts:

- 1
- 4
- 8
- 16
- 32

Record at least:

- total wall-clock time;
- chunks per hour;
- CPU utilization;
- peak RSS;
- storage read throughput;
- I/O wait;
- download wait/bottleneck evidence;
- failed chunks.

Select a recommended laboratory-server worker count from measurement, not from CPU-core count alone.

The first implementation should not add NUMA pinning, custom shared-memory indexes, or similar tuning before benchmarks establish a real bottleneck.

## 18. Implementation phases

The implementation plan should decompose work into testable steps, but the architectural sequence is:

1. target 15-minute flow extraction and 1–3 packet cohort;
2. correct single-chunk observation extraction;
3. portable manifests, cache identity, staging, validation, and reuse;
4. bounded acquisition, 96-chunk process parallelism, parent validation, deletion, and restart;
5. portable-dataset-only 24-hour aggregation and separate 1/2/3 result CSVs;
6. real-data benchmark and recommended worker count.

Parallelism must be introduced only after single-chunk semantics are test-covered.

## 19. Non-goals for the initial implementation

The initial repository does not implement:

- Scan-like classification or removal;
- anomaly detection;
- prefix selection or prefix-level comparison;
- Aguri processing;
- application payload archival;
- TablePlus or SQLite viewing helpers;
- full TCP session reconstruction;
- flow reconstruction over the entire 24-hour trace;
- within-PCAP parallel flow extraction;
- NUMA affinity tuning;
- distributed cluster execution;
- arbitrary user-defined extraction filters.

Future Scan-like definitions should consume the portable observational dataset rather than modify heavy extraction semantics whenever the retained facts are sufficient.

## 20. Acceptance criteria

The initial system is acceptable when all of the following are true:

1. the target 15-minute PCAP can be reproducibly converted into the full flow table and a single cohort containing observed packet counts 1, 2, and 3;
2. target FlowKey matching is direction-independent and preserves first-observed direction separately;
3. context-source selection follows the approved TCP/UDP policy and records its basis;
4. one 15-minute context chunk can be extracted into the two approved Parquet artifacts with validated manifests;
5. multiple independent chunks can be processed concurrently without workers writing shared durable state;
6. raw PCAPs are never deleted before independent parent-side cache validation succeeds;
7. a stopped extraction can be rerun without rescanning already-valid chunks;
8. a complete portable dataset contains 96 validated chunks and can be copied to another directory or machine without absolute-path breakage;
9. aggregation succeeds using only the portable dataset and produces schema-identical 1-, 2-, and 3-packet context CSVs;
10. changing later aggregation logic does not require rereading original PCAPs;
11. extraction never assigns Scan-like or anomaly labels;
12. benchmark results identify a practical worker count for the laboratory server.

## 21. Design boundary inherited from the reference repository

`mawi-global-analysis` is a reference for proven packet parsing, bidirectional flow-key semantics, first-observed direction, initial-SYN metadata, strict capture reading, durable provenance, and safe checkpoint-before-delete patterns.

The new repository is not a fork in research meaning. It intentionally removes the prefix/Aguri/Scan-like-removal pipeline and centers on portable packet-context extraction for 1–3 packet observed flows.

Where code is adapted from the reference repository, tests must establish semantic equivalence for the reused behavior rather than assuming copied code remains correct.