# Build a memory-efficient ClamAV-compatible scanner in Rust

Barnacle will implement its own signature compiler, matcher, and scan pipeline. Stock clamd provides reference results. FreshClam can continue to supply verified databases. Depot can use its existing Unix socket client once Barnacle implements the required commands.

See the [implementation tasks and release criteria](clamd-roadmap.md) for the single-binary replacement.

## Deployment to match

The infra checkout specifies Debian 13, one vCPU, and 2 GB of RAM on butters. Depot shares the host with rail. The role estimates clamd used about 1.1 GiB during an October incident. Measure the current baseline before choosing a memory budget. [Droplet definition](../../infra/envs/prod/droplet_butters.tf) · [ClamAV role](../../infra/ansible/roles/clamav/tasks/main.yml)

Infra already uses serial database reloads and disables FreshClam's extra test load. Clamd has a 1400M soft threshold and a 1536M hard limit. FreshClam has a separate 256M limit. The stream and file limits are 250 MiB. The aggregate scan limit is 500 MiB. Capture all effective options, including package defaults. [Daemon template](../../infra/ansible/roles/clamav/templates/clamd.conf.j2)

Depot sends `zPING` and `zINSTREAM` to `/run/clamav/clamd.ctl`. A detection quarantines the upload and records its signature. An error rejects a one-shot upload and leaves a resumable upload pending. Preserve those outcomes, signature visibility, deadlines, and cancellation. [Depot client](../../depot/internal/scan/clamd.go) · [Upload completion](../../depot/internal/upload/upload.go)

## 1. Establish a reproducible reference

Pin the Debian engine revision, verified database generation, configuration, and fixtures. Build a differential runner on an isolated Linux VM sized like butters. Record verdict, reported signature, and errors for every input. Replay workloads separately so the engines do not compete for RAM.

Inventory active database families, functionality levels, file handlers, and enabled heuristics. Track each feature and its reference fixtures. Record preparation time, warm idle memory, peak scan and update memory, CPU per GiB, throughput, p95 latency, disk reads, and major faults. Measure the cgroup, including file-backed cache. Also measure host headroom while simulating rail and depot load.

## 2. Prove partial residency with whole-file hashes

Build a Rust compiler for the deployed whole-file hash formats. Generate an immutable sorted index keyed by algorithm, digest, and size constraints. Preserve wildcard sizes, signature names, and deterministic match ordering. Store a small directory of offsets in RAM. Compare positional disk reads and read-only memory mapping against an equivalent in-memory Rust index.

Use the same full hash dataset for all variants. Measure cold starts, repeated uploads, mixed scans, and random lookups under memory pressure. Report matched or unmatched for this matcher only. A negative lookup cannot authorize delivery.

**First decision.** Capture the stock hash-only reference and freeze the memory threshold before testing either Rust index. Continue if a disk-backed index passes the memory, throughput, latency, and reference checks in the [hash baseline protocol](hash-baseline.md). Estimate its contribution to whole-engine savings using the stock allocation profile. [Hash signature formats](https://docs.clamav.net/manual/Signatures/HashSignatures.html)

**Outcome.** On 2026-11-18, both disk-backed indexes saved about 39 MiB of warm idle memory. That missed the frozen 57 MiB threshold, so the experiment stopped for this generation. [Measured results](hash-benchmark-results.md)

## 3. Extend partial loading across the scan pipeline

| Component | Rust implementation and parity test |
| --- | --- |
| Content matching | Implement extended patterns, offsets, logical expressions, and their regex semantics. Compile immutable tables and compare individual matches against upstream fixtures. |
| Rule selection | Keep global rules eligible. Load type-specific groups when engine-recognized objects require them. Pin groups during evaluation and bound cache residency under concurrency. |
| Containers and normalization | Walk embedded objects, unpack supported formats, and reproduce text normalization. Repeat rule selection at each layer. A ZIP containing a PDF exercises both container and document handling. |
| Engine-dependent detections | Implement applicable bytecode instructions and host APIs, metadata, allowlists, enabled heuristics, and detection precedence. Test signature names as well as verdicts. |
| Resource limits | Match stock behavior at file, extraction, recursion, and timeout boundaries. Bound temporary files, buffers, and worker concurrency on the target VM. |

Every deferred group needs an activation rule covering nested, normalized, and reclassified content. Keep groups with unknown applicability eligible for evaluation. A permanently omitted rule family makes the engine incomplete. While coverage is partial, run Barnacle offline and report unsupported cases explicitly. Stock clamd remains authoritative for depot.

[ClamAV signatures](https://docs.clamav.net/manual/Signatures.html) · [Logical signature context](https://docs.clamav.net/manual/Signatures/LogicalSignatures.html) · [Bytecode signatures](https://docs.clamav.net/manual/Signatures/BytecodeSignatures.html)

## 4. Handle updates and depot integration

Build indexes from one verified database snapshot. Record input digests, functionality levels, compiler version, and index format. Validate before atomic activation. Pin one generation per scan. Reject unsupported generations, retain the last validated generation, and expose update failures and age. Exercise corrupt indexes, interrupted builds, and rollbacks. Measure peak memory and disk space with scans active during updates. Evaluate off-host compilation if local builds exceed the memory budget.

Implement the socket commands used by depot and provide an update notification path for FreshClam. Check compatibility with the infra role's readiness probe. Return readiness only after validated indexes are available. Run one-shot, grant, dashboard, and resumable uploads against the Rust service in staging. Rehearse restoring the Debian units before proposing a rollout.

## Acceptance and effort

Use clean files, harmless detection fixtures, upstream regression tests, nested containers, normalized inputs, multiple matches, and boundary cases. Compare across multiple database generations. Require documented coverage for every active feature and zero unexplained verdict, signature, or error differences. Fixture agreement alone cannot establish full engine parity.

The proposed full-daemon memory target is 30% lower warm scanner memory. Require at least stock throughput and p95 latency at or below stock. Require no additional upload timeouts or higher host memory peak during updates. Repeat with cold storage caches and a mixed workload long enough to exercise every frequently used group.

Budget roughly one engineer-week for the baseline and inventory, then one to three weeks for the hash experiment. Full engine compatibility is a multi-person, multi-month undertaking with ongoing feed and parser maintenance. Re-estimate from the feature inventory and measured prototype. The hash milestone alone cannot support a production date.
