# MAWI Context Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `mawi-context-analysis`, a compact tool that extracts a portable 24-hour packet-context dataset for flows observed with 1–3 packets in a chosen 15-minute MAWI window, then re-aggregates that dataset without original PCAPs.

**Architecture:** The heavy `extract` stage builds the target-window flow/cohort once, then overlaps bounded MAWI chunk acquisition with independent `ProcessPoolExecutor` scans; workers publish only per-chunk Parquet caches, while the parent owns shared manifests and raw-PCAP deletion. The light `aggregate` stage consumes only the copied portable dataset, uses bounded disk-backed temporary state, and emits schema-identical CSVs for observed packet counts 1, 2, and 3.

**Tech Stack:** Python 3.12, `dpkt`, `pandas`, `pyarrow`, stdlib `concurrent.futures`, stdlib `sqlite3`, `pytest`, `uv`.

**Spec:** `docs/superpowers/specs/2026-10-04-mawi-context-analysis-design.md`

## Global Constraints

- Repository name: `mawi-context-analysis`.
- Python version: 3.12.
- Core dependencies: `dpkt`, `pandas`, `pyarrow`; use stdlib process parallelism and do not add Ray, Dask, or Spark.
- Flow identity is a direction-independent bidirectional TCP/UDP 5-tuple; `src_*` / `dst_*` retain first-observed direction only.
- Target-window flow extraction uses no inactivity timeout.
- Initial target cohort is configured as observed packet counts `{1, 2, 3}` in one selected 15-minute window; this is an observational label, not full-lifetime flow size.
- TCP `context_source_ip` uses the initial plain-SYN sender when observed, otherwise first-observed `src_ip`; UDP uses first-observed `src_ip`.
- Raw extraction never assigns Scan-like, anomaly, malicious, or benign labels.
- Target-tuple and source-context raw observations are Parquet; target flow/cohort and final results are CSV; provenance is JSON.
- Durable manifests use dataset-relative artifact paths; absolute local paths are not part of portable dataset identity.
- TCP source context retains candidate-source-related packets with SYN, RST, or FIN set; UDP source context retains outbound packets from candidate source IPs.
- Application payload bytes are never persisted.
- Workers write only their assigned chunk staging directory; parent process alone owns dataset-wide state and raw-PCAP deletion.
- A raw PCAP may be deleted only after independent parent-side validation of a durable published chunk cache.
- Default behavior continues independent chunks after a chunk failure and leaves the dataset incomplete; reruns reuse compatible completed work automatically.
- Aggregation must work with no Internet, MAWI access, raw PCAP, or laboratory server and must not concatenate all 96 Parquet files into one in-memory DataFrame.
- The initial implementation does not add NUMA pinning, shared-memory indexes, within-PCAP parallelism, Scan-like removal, Aguri, prefix analysis, or application payload archival.
- Default extract paths are `data/portable/<target_chunk>/packet-counts-<sorted-counts>/` for the portable dataset and `data/spool/<target_chunk>/packet-counts-<sorted-counts>/` for transient raw downloads; aggregation defaults to `results/<target_chunk>/`.
- Git history is human-owned: leave implementation changes uncommitted unless the human explicitly asks for commits; the commit steps below are checkpoints for an execution mode in which the human has authorized commits.

## Review Focus

- A target chunk outside the requested day, malformed packet-count set, or non-15-minute chunk ID must fail before download or artifact creation.
- Truncated/malformed capture input must follow the strict-reader contract rather than silently fabricating a 5-tuple or length value.
- An existing final chunk directory with a different cohort/source/schema/code identity must fail explicitly and must never be silently overwritten.
- A worker crash or invalid staged Parquet must leave the raw PCAP intact and must never create a valid-looking final chunk directory.
- Copying a complete portable dataset to a different filesystem root must preserve validation and aggregation because durable artifact references are relative.

---

## File Structure

The implementation should create these focused modules rather than one large pipeline file:

- `src/mawi_context/capture.py` — strict PCAP/PCAPNG record streaming and packet metadata.
- `src/mawi_context/flow.py` — normalized bidirectional FlowKey and target-window flow aggregation.
- `src/mawi_context/cohort.py` — 1–3 observed-packet cohort selection, context-source policy, lookup indexes.
- `src/mawi_context/hashing.py` — SHA-256 and stable JSON identity helpers.
- `src/mawi_context/manifests.py` — atomic JSON writes, portable relative-path records, validation primitives.
- `src/mawi_context/observations.py` — single-chunk packet filtering and streaming Parquet publication.
- `src/mawi_context/chunks.py` — day/chunk planning and MAWI DITL URL rendering.
- `src/mawi_context/downloader.py` — bounded-retry raw acquisition and transient ownership records.
- `src/mawi_context/extraction.py` — parent-side extraction orchestration, process workers, cache reuse, safe deletion.
- `src/mawi_context/aggregation.py` — portable-dataset-only disk-backed 24-hour context aggregation.
- `src/mawi_context/cli.py` — small `extract` / `aggregate` command surface.

### Task 1: Bootstrap the repository contract and CLI surface

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `README.md`
- Create: `AGENTS.md`
- Create: `src/mawi_context/__init__.py`
- Create: `src/mawi_context/cli.py`
- Create: `tests/unit/test_cli.py`

**Interfaces:**
- Produces: `mawi-context = mawi_context.cli:main` console entry point.
- Produces: `build_parser() -> argparse.ArgumentParser`.
- Produces: `main(argv: Sequence[str] | None = None) -> int`, with late imports of `extraction.run_extract_cli` and `aggregation.run_aggregate_cli` so `--help` works before later tasks exist.

- [ ] **Step 1: Write CLI contract tests**

Add tests asserting: `extract` requires `--day`, `--target-chunk`, `--packet-counts`, and `--workers`; `aggregate` requires `--dataset`; `--workers <= 0`, non-positive packet counts, and duplicate packet counts are rejected by CLI parsing. Calendar/day-to-target semantic validation is owned by Task 6 so Task 1 stays independent.

- [ ] **Step 2: Run the CLI tests and confirm failure**

Run: `uv run pytest tests/unit/test_cli.py -v`
Expected: FAIL because the package/CLI does not exist.

- [ ] **Step 3: Add package metadata, CLI parser, README, and AGENTS contract**

`pyproject.toml` pins Python `>=3.12,<3.13`, adds `dpkt`, `pandas`, `pyarrow`, and pytest as a dev dependency. `README.md` documents the observational 1–3 packet definition, heavy/light stages, portable dataset, and basic commands. `AGENTS.md` copies the useful workflow rules from the reference repo but replaces its research semantics with this spec’s flow/cohort/cache rules.

- [ ] **Step 4: Verify parser/help and docs**

Run: `uv sync && uv run pytest tests/unit/test_cli.py -v && uv run mawi-context --help`
Expected: tests PASS and help lists `extract` and `aggregate`.

- [ ] **Step 5: Commit checkpoint if authorized**

```bash
git add pyproject.toml .gitignore README.md AGENTS.md src/mawi_context tests/unit/test_cli.py
git commit -m "chore: bootstrap mawi context analysis"
```

### Task 2: Implement strict capture reading and target-window flow extraction

**Files:**
- Create: `src/mawi_context/capture.py`
- Create: `src/mawi_context/flow.py`
- Create: `tests/helpers/pcap_factory.py`
- Create: `tests/unit/test_capture.py`
- Create: `tests/unit/test_flow.py`

**Interfaces:**
- Produces: `CaptureRecord(packet_index: int, timestamp: float, frame: bytes, captured_length: int, original_length: int)`.
- Produces: `iter_capture_records(path: Path) -> Iterator[CaptureRecord]`.
- Produces: `Endpoint(ip: str, port: int)` and `FlowKey.from_packet(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: int) -> FlowKey`.
- Produces: `FlowParseResult(frame: pd.DataFrame, skipped_packet_counts: dict[str, int])`.
- Produces: `parse_target_flows(path: Path) -> FlowParseResult` with no inactivity timeout and exact `FLOW_COLUMNS` constant.

- [ ] **Step 1: Write fixture and strict-reader tests**

Create tiny Ethernet PCAP fixtures in code and assert record order, timestamps, captured/original lengths, gzip support, unsupported datalink rejection, and explicit failure on truncated/malformed capture input.

- [ ] **Step 2: Run strict-reader tests and confirm failure**

Run: `uv run pytest tests/unit/test_capture.py -v`
Expected: FAIL because `capture.py` is absent.

- [ ] **Step 3: Adapt only the strict reader semantics needed from `mawi-global-analysis`**

Implement `iter_capture_records()` for PCAP/PCAPNG Ethernet captures; retain captured/original length separately and never infer wire payload from truncated bytes.

- [ ] **Step 4: Write flow tests**

Assert reverse-direction packets share one FlowKey, a long gap inside the 15-minute file does not split a flow, first-observed direction remains in `src_*`/`dst_*`, initial plain-SYN metadata is retained, TCP/UDP only are aggregated, and packet/frame/IP/payload counters are deterministic.

- [ ] **Step 5: Implement `FlowKey` and `parse_target_flows()`**

Use one active accumulator per normalized FlowKey for the entire target capture; expose a DataFrame with stable sequential `flow_id` values in first-observation order.

- [ ] **Step 6: Verify capture/flow behavior**

Run: `uv run pytest tests/unit/test_capture.py tests/unit/test_flow.py -v`
Expected: PASS.

- [ ] **Step 7: Commit checkpoint if authorized**

```bash
git add src/mawi_context/capture.py src/mawi_context/flow.py tests/helpers tests/unit/test_capture.py tests/unit/test_flow.py
git commit -m "feat: add canonical target flow extraction"
```

### Task 3: Build the shared 1–3 observed-packet cohort and lookup indexes

**Files:**
- Create: `src/mawi_context/cohort.py`
- Create: `tests/unit/test_cohort.py`

**Interfaces:**
- Consumes: `FlowParseResult.frame` and `FlowKey` from Task 2.
- Produces: `select_target_cohort(flows: pd.DataFrame, packet_counts: tuple[int, ...]) -> pd.DataFrame` with exact `COHORT_COLUMNS`.
- Produces: `ContextIndexes(target_flow_by_key: dict[FlowKey, int], candidate_source_ips: frozenset[str])`.
- Produces: `build_context_indexes(cohort: pd.DataFrame) -> ContextIndexes`.

- [ ] **Step 1: Write cohort selection and source-identity tests**

Assert one shared cohort contains only configured observed packet counts; `target_flow_id` is the source flow ID; 1-packet rows have equal start/end; TCP uses initial plain-SYN sender when available; TCP fallback and UDP use first-observed source; `context_source_basis` records `initial_syn_sender` vs `first_observed_src`.

- [ ] **Step 2: Run the cohort tests and confirm failure**

Run: `uv run pytest tests/unit/test_cohort.py -v`
Expected: FAIL because `cohort.py` is absent.

- [ ] **Step 3: Implement cohort and index construction**

Reject empty/duplicate/non-positive `packet_counts`; keep 1/2/3 membership in `observed_packet_count`; build one target FlowKey→ID mapping and one deduplicated candidate-source set.

- [ ] **Step 4: Verify cohort/index behavior**

Run: `uv run pytest tests/unit/test_cohort.py -v`
Expected: PASS.

- [ ] **Step 5: Commit checkpoint if authorized**

```bash
git add src/mawi_context/cohort.py tests/unit/test_cohort.py
git commit -m "feat: add observed packet cohort selection"
```

### Task 4: Add portable identity, manifests, and dataset-relative validation

**Files:**
- Create: `src/mawi_context/hashing.py`
- Create: `src/mawi_context/manifests.py`
- Create: `tests/unit/test_manifests.py`

**Interfaces:**
- Produces: `sha256_file(path: Path) -> str` and `stable_json_hash(value: object) -> str`.
- Produces: `write_json_atomically(path: Path, value: Mapping[str, object]) -> None`.
- Produces: `cohort_identity(cohort: pd.DataFrame) -> str` hashing the exact cohort facts that control packet retention.
- Produces: `artifact_record(dataset_root: Path, artifact_path: Path, *, row_count: int, schema_version: str) -> dict[str, object]` using only POSIX-style dataset-relative paths.
- Produces: `resolve_artifact_path(dataset_root: Path, relative_path: str) -> Path`, rejecting absolute paths and `..` escape.
- Produces: `load_json_object(path: Path) -> dict[str, object]`.

- [ ] **Step 1: Write identity/portability tests**

Assert stable hashes, atomic JSON replacement, absolute/escaping artifact paths are rejected, cohort content changes identity, and a manifest created under root A resolves correctly after the whole dataset tree is copied to root B.

- [ ] **Step 2: Run manifest tests and confirm failure**

Run: `uv run pytest tests/unit/test_manifests.py -v`
Expected: FAIL because helpers do not exist.

- [ ] **Step 3: Implement hashing and portable manifest primitives**

Do not record absolute artifact paths in durable identity; leave machine-local spool paths only in transient downloader metadata created later.

- [ ] **Step 4: Verify portability primitives**

Run: `uv run pytest tests/unit/test_manifests.py -v`
Expected: PASS.

- [ ] **Step 5: Commit checkpoint if authorized**

```bash
git add src/mawi_context/hashing.py src/mawi_context/manifests.py tests/unit/test_manifests.py
git commit -m "feat: add portable provenance primitives"
```

### Task 5: Extract one chunk into validated Parquet observation caches

**Files:**
- Create: `src/mawi_context/observations.py`
- Create: `tests/unit/test_observations.py`
- Create: `tests/integration/test_chunk_publication.py`

**Interfaces:**
- Consumes: `ContextIndexes`, `iter_capture_records()`, manifest helpers.
- Produces: exact PyArrow schemas `TARGET_PACKET_SCHEMA` and `SOURCE_CONTEXT_SCHEMA` matching the approved columns.
- Produces: `RawSourceIdentity(chunk_id: str, source_url: str, sha256: str, size_bytes: int)`.
- Produces: `extract_chunk_observations(capture_path: Path, indexes: ContextIndexes, dataset_root: Path, chunk_id: str, source: RawSourceIdentity, *, cohort_identity_value: str) -> dict[str, object]`.
- Produces: `load_validated_chunk(dataset_root: Path, chunk_id: str, *, expected_cohort_identity: str) -> dict[str, object]`.

- [ ] **Step 1: Write packet-retention tests**

Using tiny PCAPs, assert: every target-tuple TCP/UDP packet is retained with `target_flow_id`; reverse direction matches the same target; TCP source-context retains SYN/SYN-ACK/RST/FIN when the candidate IP is either endpoint but excludes ACK-only/data-only packets; UDP source-context retains only outbound packets from candidate source IPs; one observed source-context packet is written once even when several target flows share that source IP; no payload bytes are stored.

- [ ] **Step 2: Run observation tests and confirm failure**

Run: `uv run pytest tests/unit/test_observations.py -v`
Expected: FAIL because `observations.py` is absent.

- [ ] **Step 3: Implement streaming Parquet extraction**

Use `pyarrow.parquet.ParquetWriter` with bounded row buffers; decode each capture record once and route the observation to zero, one, or both output streams according to the approved policies.

- [ ] **Step 4: Write publication/failure tests**

Assert a successful chunk is staged then atomically renamed; exact schema/row count/checksum/cohort/source identities validate; malformed source input or injected write failure leaves no final chunk directory; an existing final directory with mismatched identity raises rather than overwrites.

- [ ] **Step 5: Implement publication and independent reload validation**

A final `observations/<chunk_id>/` directory must contain exactly `target_packets.parquet`, `source_context_packets.parquet`, and `manifest.json`; official final directories are immutable once published.

- [ ] **Step 6: Verify single-chunk extraction**

Run: `uv run pytest tests/unit/test_observations.py tests/integration/test_chunk_publication.py -v`
Expected: PASS.

- [ ] **Step 7: Commit checkpoint if authorized**

```bash
git add src/mawi_context/observations.py tests/unit/test_observations.py tests/integration/test_chunk_publication.py
git commit -m "feat: add durable chunk observation extraction"
```

### Task 6: Add MAWI chunk planning, bounded acquisition, and parallel extraction orchestration

**Files:**
- Create: `src/mawi_context/chunks.py`
- Create: `src/mawi_context/downloader.py`
- Create: `src/mawi_context/extraction.py`
- Create: `tests/unit/test_chunks.py`
- Create: `tests/unit/test_downloader.py`
- Create: `tests/unit/test_extraction_scheduler.py`
- Create: `tests/integration/test_extract_resume.py`
- Modify: `src/mawi_context/cli.py`

**Interfaces:**
- Produces: `normalized_day(value: str) -> str`, `expected_chunk_ids(day: str) -> tuple[str, ...]`, and `validate_target_chunk(day: str, chunk_id: str) -> str`.
- Produces: `render_ditl_chunk_url(day: str, chunk_id: str) -> str`; for the initial 2026 dataset it must render `https://mawi.nezu.wide.ad.jp/mawi/ditl/ditl2026/202604081400.pcap.gz` for chunk `202604081400`.
- Produces: `download_chunk(chunk_id: str, source_url: str, spool_root: Path, *, timeout: float = 60.0, retries: int = 3, backoff_seconds: float = 1.0) -> dict[str, object]` with `.part` + transient `.download.json` ownership evidence.
- Produces: `ExtractOptions(day: str, target_chunk: str, packet_counts: tuple[int, ...], workers: int, dataset_root: Path, spool_root: Path)`.
- Produces: `run_extract(options: ExtractOptions, *, source_url_resolver: Callable[[str, str], str] = render_ditl_chunk_url) -> Path`.
- Produces: `run_extract_cli(args: argparse.Namespace) -> int`, which validates day/target semantics, derives the default portable/spool roots, calls `run_extract()`, and returns `0` only for a complete successful dataset.
- Produces: module-level process initializer `_initialize_scan_worker(cohort_csv: str)` and picklable `_scan_chunk_worker(task: ScanChunkTask) -> ScanChunkResult` so each process builds cohort indexes once and reuses them.

- [ ] **Step 1: Write day/chunk/source tests**

Assert exactly 96 quarter-hour IDs, target/day mismatch rejection, non-quarter-hour rejection, and the verified 2026 DITL URL rendering above.

- [ ] **Step 2: Write downloader safety tests**

With a local HTTP server/fake opener, assert bounded retries, `.part` cleanup, Content-Length validation, transient ownership checksum/size/source identity, and reuse only when ownership evidence matches.

- [ ] **Step 3: Run chunk/downloader tests and confirm failure**

Run: `uv run pytest tests/unit/test_chunks.py tests/unit/test_downloader.py -v`
Expected: FAIL because acquisition modules are absent.

- [ ] **Step 4: Implement chunk planning and safe single-file download**

Keep download ownership metadata transient and machine-local; it is not copied into portable dataset identity except for source URL/hash/size facts recorded in published chunk manifests.

- [ ] **Step 5: Write scheduler tests before adding processes**

Test a pure parent-side scheduler with fakes: at most 2 downloads are in flight; at most `workers` scans are in flight; ready scans start while later downloads continue; one chunk failure does not prevent independent later chunks; valid completed caches are reused; invalid final caches fail explicitly; already-owned raw files are reused; no delete callback occurs before parent validation succeeds.

- [ ] **Step 6: Implement bounded parent scheduler plus process worker boundary**

Use a small `ThreadPoolExecutor(max_workers=2)` for downloads and `ProcessPoolExecutor(max_workers=options.workers)` for scans. Submit only bounded work, keep top-level dataset progress in the parent, and never let workers delete raw captures or mutate dataset-wide manifests.

- [ ] **Step 7: Write resume/crash integration tests**

Create a tiny synthetic 4-chunk plan via dependency injection and assert: cross-chunk scans overlap with two workers; a simulated worker failure leaves its raw capture and no final cache; successful siblings remain reusable; rerun scans only incomplete chunks; a complete synthetic plan publishes dataset status `success` only when every expected chunk validates.

- [ ] **Step 8: Implement target-first extraction and durable dataset state**

`run_extract()` must acquire/process the target chunk first to create `provenance/flows.csv`, `provenance/flow_manifest.json`, `cohort/target_cohort.csv`, `cohort/cohort_manifest.json`, and cohort identity; then process the full chunk plan. `dataset_manifest.json` records `status` (`incomplete` or `success`), day, target chunk, sorted packet counts, cohort identity, expected 96 chunk IDs, per-chunk status/error/source identity, schema/tool identity, and only dataset-relative durable artifact paths. The target raw file is reused for its context scan and deleted only after its chunk cache has passed parent validation.

- [ ] **Step 9: Wire `mawi-context extract` and verify orchestration**

Run: `uv run pytest tests/unit/test_chunks.py tests/unit/test_downloader.py tests/unit/test_extraction_scheduler.py tests/integration/test_extract_resume.py -v`
Expected: PASS.

- [ ] **Step 10: Commit checkpoint if authorized**

```bash
git add src/mawi_context/chunks.py src/mawi_context/downloader.py src/mawi_context/extraction.py src/mawi_context/cli.py tests/unit/test_chunks.py tests/unit/test_downloader.py tests/unit/test_extraction_scheduler.py tests/integration/test_extract_resume.py
git commit -m "feat: add bounded parallel context extraction"
```

### Task 7: Implement portable-dataset-only 24-hour aggregation

**Files:**
- Create: `src/mawi_context/aggregation.py`
- Create: `tests/unit/test_aggregation.py`
- Create: `tests/integration/test_portable_aggregation.py`
- Modify: `src/mawi_context/cli.py`

**Interfaces:**
- Consumes: complete validated portable dataset only.
- Produces: `AggregateOptions(dataset_root: Path, output_root: Path | None = None)`.
- Produces: `run_aggregate(options: AggregateOptions) -> Path`.
- Produces: `run_aggregate_cli(args: argparse.Namespace) -> int`, which uses `results/<target_chunk>/` as the default output root and returns nonzero on validation/aggregation failure.
- Produces: schema constant `CONTEXT_RESULT_COLUMNS`, identical for packet-count 1/2/3 outputs.
- Temporary implementation detail: stdlib SQLite database under the chosen results directory, populated chunk-by-chunk from `pyarrow.parquet.ParquetFile.iter_batches`; delete on successful publication and retain on failure for diagnosis.
- `CONTEXT_RESULT_COLUMNS` starts with cohort identity fields (`target_flow_id`, `observed_packet_count`, 5-tuple, `target_start_time`, `target_end_time`, `target_duration`, `context_source_ip`, `context_source_basis`), then target-tuple 24-hour/before/interval/after/previous/next and ±1/10/60/300-second fields.
- Initial TCP source fields are observational and direction-specific relative to `context_source_ip`: total retained TCP-control packets; outbound plain-SYN count; inbound SYN/ACK count; outbound/inbound RST counts; outbound/inbound FIN counts; outbound unique destination IP/port/IP-port counts, each for 24h and for inclusive 60s/300s windows `[target_start_time-N, target_end_time+N]` where applicable. Initial UDP source fields are outbound packet and unique destination IP/port/IP-port counts for 24h and the same inclusive 60s/300s windows. No interpretation field is allowed.

- [ ] **Step 1: Write target-tuple aggregation tests**

Pin `same_tuple_packet_count_24h`, before/target-interval/after counts, previous/next timestamps and gaps, and ±1/10/60/300-second interval-relative counters for 1-, 2-, and 3-packet target intervals.

- [ ] **Step 2: Write descriptive source-context tests**

Pin total retained TCP control count plus outbound plain-SYN, inbound SYN/ACK, outbound/inbound RST, outbound/inbound FIN, outbound unique destination IP/port/pair counts, their 60/300-second target-relative values, and UDP outbound totals/unique destination values. Assert no Scan-like/anomaly classification column exists.

- [ ] **Step 3: Run aggregation tests and confirm failure**

Run: `uv run pytest tests/unit/test_aggregation.py -v`
Expected: FAIL because `aggregation.py` is absent.

- [ ] **Step 4: Implement bounded SQLite-backed aggregation**

Validate all expected chunk manifests before ingest. Stream each Parquet file in bounded batches, index target observations by normalized FlowKey/timestamp and source observations by candidate source/timestamp, derive descriptive statistics, and write final rows in stable `target_flow_id` order.

- [ ] **Step 5: Write portability integration test**

Build a complete tiny portable dataset, copy the directory to a new root, delete the original fixture/raw inputs, then run aggregation from the copied root and assert three directories `packet_count_1`, `packet_count_2`, `packet_count_3` contain schema-identical `context.csv` files with the expected rows.

- [ ] **Step 6: Wire `mawi-context aggregate` and verify PCAP/network independence**

Run: `uv run pytest tests/unit/test_aggregation.py tests/integration/test_portable_aggregation.py -v`
Expected: PASS without network access and without any raw capture path present.

- [ ] **Step 7: Commit checkpoint if authorized**

```bash
git add src/mawi_context/aggregation.py src/mawi_context/cli.py tests/unit/test_aggregation.py tests/integration/test_portable_aggregation.py
git commit -m "feat: add portable 24 hour context aggregation"
```

### Task 8: End-to-end verification, documentation, and laboratory benchmark procedure

**Files:**
- Create: `tests/integration/test_end_to_end.py`
- Create: `docs/benchmark.md`
- Modify: `README.md`
- Modify: `AGENTS.md` only if implementation introduced a research contract that is not already stated.

**Interfaces:**
- Consumes: complete `extract` and `aggregate` CLI from Tasks 1–7.
- Produces: documented real-data benchmark procedure for worker counts `1, 4, 8, 16, 32` and a place to record the selected recommendation.

- [ ] **Step 1: Add a synthetic end-to-end acceptance test**

Run target flow extraction → cohort → multi-chunk extraction → portable copy → aggregate on tiny generated PCAPs. Assert no Scan-like labels occur, all durable paths are relative, valid caches are reused on rerun, and 1/2/3 result schemas match.

- [ ] **Step 2: Run the complete automated suite**

Run: `uv run pytest -q`
Expected: all tests PASS.

- [ ] **Step 3: Add benchmark runbook**

Document a controlled laboratory run using the same day/target/cohort for workers `1`, `4`, `8`, `16`, `32`. Record wall time, chunks/hour, CPU utilization, peak RSS, NVMe read throughput, I/O wait, download wait evidence, and failures using `/usr/bin/time -v`, `pidstat`, `iostat`, and `vmstat` (or equivalent available tools). Pre-stage/reuse download state consistently so worker-count comparisons measure scan throughput rather than different network conditions.

- [ ] **Step 4: Perform source/acquisition smoke validation before the full 24-hour run**

On the laboratory server, download and fully extract at least the target chunk plus one non-target 2026-04-08 chunk using the official DITL mapping; verify source checksums/manifests, Parquet schemas, parent validation, and raw deletion before launching all 96 chunks.

- [ ] **Step 5: Run real-data worker benchmarks and update README**

Run the 2026-04-08 extraction benchmark at `--workers 1`, `4`, `8`, `16`, and `32`; select the recommended worker count from measured wall time/resource pressure, not CPU-core count. Record the recommendation and measurement date in `README.md` or `docs/benchmark.md`.

- [ ] **Step 6: Final research-contract review**

Compare generated `README.md`, `AGENTS.md`, manifests, schemas, and CLI behavior against the approved spec. Confirm extraction contains no Scan-like interpretation and aggregation can execute from a copied portable dataset without Internet/raw PCAPs.

- [ ] **Step 7: Commit checkpoint if authorized**

```bash
git add README.md AGENTS.md docs/benchmark.md tests/integration/test_end_to_end.py
git commit -m "test: verify portable context analysis workflow"
```

### Task 8 real-data validation note — 2026-10-05

The human-reported laboratory smoke on `202604081400` stopped at packet `5968733` with malformed TCP Data Offset 0 despite a captured minimum TCP header (54 captured / 86 original bytes). Approved design §2.5 and §9 now define per-packet skip-and-count with durable v2 decode/provenance identity; capture container corruption remains fatal. This focused amendment is verified only with synthetic regression fixtures. No real MAWI download, smoke rerun or benchmark is performed here. Task 8B still requires laboratory validation of the amended extractor on the retained target raw and a non-target chunk, then the full-day run and measured worker benchmarks; historical checkboxes remain unchanged.
