# AGENTS.md

This is the entry point for AI coding agents working in `mawi-context-analysis`.

## Reading order

Before changing the repository, read in this order:

1. This file.
2. `docs/superpowers/specs/2026-10-04-mawi-context-analysis-design.md`.
3. `docs/superpowers/plans/2026-10-04-mawi-context-analysis.md` when implementing the approved plan.
4. The relevant code and tests.
5. `ShuntaSakai/mawi-global-analysis` only as a reference for reusable packet parsing, flow-key, provenance, and safe checkpoint patterns.

The approved design defines the research semantics. Do not let copied or historical implementation details from `mawi-global-analysis` override this repository's design.

## Git workflow

- Work in the currently checked-out `main` working tree unless the human explicitly requests another workflow.
- Before editing, verify that the active branch is `main`.
- Do not create or switch branches, or create Git worktrees, unless explicitly requested by the human.
- Preserve existing human changes. Do not stash, reset, restore, checkout, overwrite, or discard unrelated work.
- The human owns Git history. Unless explicitly requested, do not run `git add`, commit, amend, merge, rebase, push, tag, or open a pull request.
- Leave completed implementation changes uncommitted for human review by default.

## Research semantics

- Flow identity is a direction-independent bidirectional TCP/UDP 5-tuple.
- `src_*` / `dst_*` preserve the first-observed packet direction only. Never reinterpret them automatically as client/server, initiator/responder, attacker/victim, or internal/external roles.
- Target-window flow extraction uses no inactivity timeout unless the approved design is explicitly revised.
- A 1-, 2-, or 3-packet target flow means a flow observed with that packet count in the configured 15-minute observation window. It is not a claim about the communication's complete lifetime.
- Preserve `target_start_time` / `target_end_time` as the first/last packet observed inside the target window, not as true session boundaries.
- TCP `context_source_ip` uses an observed initial plain-SYN sender when available; otherwise it falls back to first-observed `src_ip`. UDP uses first-observed `src_ip`. Preserve `context_source_basis`.
- Raw extraction must not assign Scan-like, anomaly, malicious, benign, successful-connection, or similar interpretive labels.
- Do not import Aguri, prefix-selection, Broad/Strict Scan-like removal, or unrelated experiment machinery from `mawi-global-analysis`.

## Packet decode contract

- Capture container corruption (`CaptureError`: PCAP/PCAPNG/gzip, record boundaries or truncated containers) remains fatal; never skip it.
- Only `_SkipPacket` and per-packet `PacketDecodeError` are skip-and-count, identically in target flows and 24-hour observations. Never infer or repair malformed flow facts.
- Target/cohort counts include only validly decoded TCP/UDP packets in the configured window.
- Persist every exclusion in `skipped_packet_counts` in the target flow and each chunk manifest: allowlisted stable reason codes, nonnegative integers (not booleans), canonical sorted maps; validate strictly on reuse and aggregation.
- Decode/provenance semantics use extraction v2, flow-manifest-v2 and chunk-manifest-v2. Reject old identities; CSV/Parquet column schemas remain unchanged.

## Observation-cache contract

- Target-tuple observations retain every TCP/UDP packet matching a cohort FlowKey.
- TCP source context retains candidate-source-related packets with SYN, RST, or FIN set; this includes SYN/ACK because SYN is set.
- UDP source context retains outbound packets whose source IP is a candidate `context_source_ip`.
- Store `tcp_flags_raw` as the canonical TCP flag fact. Derive labels later.
- Never persist application payload bytes in the portable dataset.
- Raw packet observations are durable Parquet research artifacts shared by 1-, 2-, and 3-packet analysis.
- Durable manifests use dataset-relative paths. Do not make portable identity depend on machine-specific absolute paths.
- Treat published chunk directories and their Parquet artifacts as immutable. Identity mismatches must fail explicitly rather than overwrite existing evidence.
- Do not bypass checksum, schema, row-count, cohort-identity, source-identity, or provenance validation for convenience.

## Parallel execution and deletion safety

- Parallelism is across independent 15-minute chunks. Do not parallelize inside a PCAP in the initial implementation.
- A worker may read its assigned raw PCAP and shared read-only cohort indexes, and may write only to its own unique chunk staging directory.
- Workers must not update dataset-wide manifests, delete raw captures, or modify another chunk's artifacts.
- The parent process owns dataset-wide scheduling, progress state, publication validation, and raw-PCAP deletion.
- A worker success result is not sufficient evidence to delete a raw PCAP.
- Never delete a raw PCAP before the completed chunk cache has been independently reloaded and validated by the parent process.
- A failed worker or invalid staged artifact must leave the corresponding raw PCAP available for diagnosis/retry.
- Completed compatible caches should be reused automatically on rerun. Malformed or identity-mismatched caches must fail explicitly.

## Aggregation boundary

- Aggregation consumes only the portable dataset.
- Aggregation must remain independent of Internet access, MAWI availability, and original raw PCAP files.
- Do not require concatenating all 96 Parquet files into a single in-memory DataFrame.
- Final 1-, 2-, and 3-packet result CSVs must use the same schema.
- Later Scan-like definitions belong downstream of the immutable observation dataset whenever retained facts are sufficient.

## Design-change boundary

Treat changes to any of the following as research/design changes rather than routine refactors:

- bidirectional flow identity or timeout semantics;
- target cohort membership or observational meaning;
- context-source selection;
- packet-retention policy;
- Parquet/CSV schemas;
- cache or dataset identity;
- provenance or validation rules;
- raw-deletion prerequisites;
- aggregation feature semantics.

Do not make such changes silently. Update the approved design/specification or ask the human when the current spec does not authorize the change.

## Verification

- Follow TDD for the approved implementation plan: add the test, confirm it fails for the intended reason, implement the minimum change, then rerun the relevant tests.
- Run verification appropriate to the changed behavior.
- Distinguish synthetic fixture/integration validation from real-data MAWI validation.
- Do not claim real-data validation unless the specified real capture was actually processed and the evidence was checked.
- For concurrency changes, test failure, resume, cache-reuse, and parent/worker ownership behavior, not only the happy path.

## Completion report

At the end of a repository change, report:

- files added, modified, and deleted;
- verification commands and results;
- whether validation used fixtures or real MAWI data;
- known deviations, unresolved risks, or remaining work.

Always end with exactly one suggested commit-message line:

`Suggested commit message: <message>`

Do not create the commit unless the human asks.
