# Classic PCAP Snaplen Tolerance Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this focused repair inline. The human authorizes local implementation and tests on main, with no commits or production execution.

**Goal:** Recover readable Classic PCAP snaplen overruns while preserving v2 evidence and PCAPNG behavior.

**Architecture:** Separate Classic PCAP length checks from PCAPNG checks. Accept bounded overruns without changing record facts. Retain semantic identities and document exact parser revisions in an external recovery audit bundle.

**Tech Stack:** Python 3.12, pytest, existing synthetic PCAP factories and Parquet validation.

**Spec:** `docs/superpowers/specs/2026-10-04-mawi-context-analysis-design.md`, §§2.6 and 9.1.

## Global Constraints

- Use existing `main`; no branch/worktree, commit/push, or production extraction.
- Preserve all observation schemas, decode/skip semantics, cohort policies and validation.
- Preserve prior accepted records; PCAPNG snaplen validation stays strict.
- Bound newly admitted Classic overruns to 16 MiB before body allocation.
- Never alter the laboratory baseline, 94 caches, existing provenance or ownership metadata.

## Review Focus

- A normal record following an overrun preserves boundaries, indexes and timestamps.
- A large overrun is rejected before a body read; old large-snaplen acceptance remains.
- A partial overrun body/header or bad gzip remains fatal.
- Successful strict-reader v2 caches and cohort remain byte-identical on repair resume.
- Only the two failed fixture chunks are scanned; source checks and parent reload still precede raw deletion.

### Task 1: Repair and verify Classic length validation

**Files:**
- Modify: `src/mawi_context/capture.py`, `tests/unit/test_capture.py`, `tests/integration/test_extract_resume.py`.
- Modify: approved design and `README.md`.
- Create: `docs/classic-pcap-recovery.md`.

**Interfaces:**
- Preserve `iter_capture_records(path: Path) -> Iterator[CaptureRecord]` and existing record fields.
- Preserve `run_extract()` and all durable identity/schema interfaces.

- [x] Add parameterized regressions for lengths 182/1208 and 118/1272 at snaplen 96, both byte orders, micro/nanosecond timestamps and gzip; compare full records to independent literal facts. Remove the obsolete Classic overrun-fatal expectation.
- [x] Add malformed length/header/timestamp/truncation and strict PCAPNG overrun guards, including Packet Blocks and Enhanced Packet Blocks. Exercise the 16 MiB extension boundary and reject huge claims before reading the body.
- [x] Add a synthetic 96-chunk strict-reader run with 94 successes and two snaplen failures, then resume with the tolerant reader. Verify only failed chunks scan, no download, unchanged provenance/cache bytes, valid skip maps and parent validation before deletion. Check target flow decoding of the overrun fixture too.
- [x] Run `uv run pytest tests/unit/test_capture.py tests/integration/test_extract_resume.py -q`; observe overrun acceptance/recovery failures against the old implementation.
- [x] Separate Classic/PCAPNG validation and implement bounded Classic tolerance only.
- [x] Rerun the focused tests, then `uv run pytest -q`; require no failures.
- [x] Document compatibility reasoning, revision-audit limitation, read-only preflight, confirmation-gated recovery, failure recovery and deletion conditions. Link from README.
- [x] Review the diff against the specification and report fixture evidence and any remaining real-data work; leave everything uncommitted.

## Decisions

- Keep v2: successful old-input records are unchanged; no prior failed overrun produced valid evidence. Exact parser code provenance is recorded outside existing exact-key manifests. If historical code evidence is unavailable, report that limitation before production recovery.
- Limit only newly admitted overruns: a global allocation cap would shrink the old accepted-input domain and undermine the compatibility proof. This leaves preexisting large-snaplen behavior outside this focused repair.
- The explicit request authorizes implementation, so no additional plan approval gate is imposed. Production recovery remains confirmation-gated as requested.

## Execution Evidence

- RED: `UV_CACHE_DIR=/tmp/mawi-snaplen-uv-cache uv run --offline --no-sync pytest tests/unit/test_capture.py tests/integration/test_extract_resume.py -q` → 29 failed / 117 passed against the old snaplen check.
- GREEN: same command → 146 passed.
- Full suite: `UV_CACHE_DIR=/tmp/mawi-snaplen-uv-cache uv run --offline --no-sync pytest -q` → 672 passed.
- Independently reviewed the uncommitted diff and documents: no actionable findings; reviewer reran focused tests → 146 passed.
- Executed both recovery-document Python blocks against a separate tiny synthetic 96-chunk dataset under `/tmp`: preflight passed for 94/2 state, rejected raw ownership and Parquet checksum damage, final check validated all96 and preserved 286 old artifact hashes; no validator writes/downloads.
- `git diff --check` passed; branch remains `main`; no commits/push, raw MAWI processing or laboratory access.

## Review Rulings and Remaining Work

- Keep v2 and external reader-revision evidence as specified in §9.1. Exact historical parser revision is only reproducible if prior execution evidence survives; missing evidence must be explicitly recorded as unknown before recovery.
- The allocation limit intentionally guards newly admitted overruns only. Preexisting huge-snaplen allocation behavior remains a documented limitation, preserving the old accepted domain.
- Reviewer declined to assess actual laboratory artifact integrity / real-data recovery and historical code-evidence completeness: these are deferred to the documented pre-production checks, not represented as locally verified.
- Production resume/publication/raw deletion still requires the human's explicit approval of the concrete runbook. No repository implementation work remains.
