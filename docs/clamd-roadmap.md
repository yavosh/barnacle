# Replace clamd with one Barnacle executable

Ship one Rust executable that starts with the existing daemon configuration and scans existing ClamAV databases. The same executable builds and validates its indexes. Keep signatures and generated indexes as external, updatable data. Existing FreshClam installations can continue to supply updates. Production scanning must work without a stock clamd process or a system installation of libclamav.

Use Debian 13 clamd 1.4.3+dfsg-1 as the first compatibility target. Record each supported engine version, configuration, database generation, and platform. The first integration client is Depot. Release compatibility also requires unmodified upstream clients and the reference daemon's other supported commands.

## Release criteria

| Requirement | Evidence required for release |
| --- | --- |
| Drop-in operation | Start the same unit with the existing configuration, socket paths, permissions, and client binaries. Compare commands, replies, error handling, signals, and reloads. |
| Detection parity | Run upstream regression tests and harmless fixtures against both daemons. Require zero unexplained differences in verdicts, winning signature names, errors, and limit behavior. Every enabled rule family and scan stage needs coverage. |
| Lower memory | Start with a proposed target of **30% lower warm idle memory** at both concurrency levels. Include file-backed pages. Require scan and live-update peaks no higher than stock. |
| Preserve speed | The complete daemon must match or exceed stock throughput with p95 latency at or below stock. Test cold and warm runs at one and four outstanding requests. Repeat noisy comparisons until the result is clear. Record timeouts and startup separately. |

The reference guest has one vCPU, 2 GiB RAM, and no swap. Five stock runs at concurrency four gave a median warm idle footprint of **1,133.6 MiB**. On this workload, a 30% reduction means at most **793.5 MiB**. This measurement includes anonymous memory, file-backed pages, and other cgroup charges. It does not identify which signatures or data structures own those bytes.

## Implementation tasks

| Order | Task | Complete when |
| --- | --- | --- |
| 1 | Freeze the compatibility matrix and oracle. Use the pinned package, effective options, official databases, and representative local signatures. [Issue #6](https://github.com/yavosh/barnacle/issues/6) | A repeatable runner records verdicts, exact names, errors, limits, and client replies. Each database format, parser, command, and option has a coverage entry. |
| 2 | Attribute stock memory. Sample startup, warm idle, active scans, and live reload. Separate anonymous and file-backed pages. Use allocation profiles or controlled database-family runs to identify compiled structures. [Issue #7](https://github.com/yavosh/barnacle/issues/7) | Publish ranked memory consumers with measured bytes, attribution limits, and the next candidate. Use the full feed for acceptance runs. |
| 3 | Close the whole-file hash experiment. Compare identical memory, positional-read, and mmap indexes. [Issue #1](https://github.com/yavosh/barnacle/issues/1) | Publish the five-run medians and the decision against the frozen 57 MiB gate. Keep the verified matcher as a correctness reference. |
| 4 | Build the single-binary daemon and client test harness. Start with the existing Unix socket, `PING`, `INSTREAM`, and Unix `FILDES`. Add TCP, path scans, sessions, lifecycle, and the remaining matrix entries. [Issue #8](https://github.com/yavosh/barnacle/issues/8) | Unmodified Depot and `clamdscan` can drive the daemon. Compare replies with stock. Until the scan pipeline is complete, incomplete scans return an explicit error. |
| 5 | Compile body patterns. Preserve global rules, target types, offsets, chunk boundaries, and competing matches. Expose match positions and counts. [Issue #2](https://github.com/yavosh/barnacle/issues/2) | Per-pattern results match stock. For a large measured memory consumer, benchmark a compact resident table against a mapped representation on the same full rule set. |
| 6 | Implement object extraction and normalization. Preserve parent context, file type, scan limits, and nested object ordering. [Issue #9](https://github.com/yavosh/barnacle/issues/9) | A harmless signature inside a nested archive or normalized document produces the same result as stock. Re-evaluate eligible rules for every object. |
| 7 | Evaluate logical signatures from content matches and object context. Cover counts, conditions, offsets, and regex semantics. [Issue #3](https://github.com/yavosh/barnacle/issues/3) | Positive, negative, and competing fixtures reproduce stock results across raw, nested, and normalized inputs. Depends on tasks 5 and 6. |
| 8 | Close the remaining detection gaps from the matrix. Implement [bytecode and heuristics, issue #4](https://github.com/yavosh/barnacle/issues/4). Cover metadata, section hashes, local formats, allowlists, ignores, and final match precedence. [Issue #10](https://github.com/yavosh/barnacle/issues/10) | Every enabled feature has parity evidence across multiple verified generations. An unsupported active feature prevents activation. |
| 9 | Integrate verified CVD and CLD updates into the executable. Build immutable generations, validate them, and atomically activate each one. [Issue #11](https://github.com/yavosh/barnacle/issues/11) | Concurrent scans keep their original generation. A rejected or interrupted update preserves the last good one. Measure disk and memory peaks under active traffic. |
| 10 | Qualify the packaged binary end to end. Replay the same mixed workload against each daemon on a fresh guest. Run Depot upload flows in staging. [Issue #12](https://github.com/yavosh/barnacle/issues/12) | All release criteria pass. Quarantine, signature recording, one-shot rejection, and resumable retry match stock. Rehearse rollback before switching traffic. |

## What to do next

Finish the current hash issue first. Then work through the compatibility matrix, stock memory profile, and daemon interface in order. Use the memory profile to choose the next index experiment. Keep frequently accessed tables resident when paging them costs throughput. Count every mapped page charged to the scanner. Preserve all eligible signatures in every release candidate.

Implement one issue at a time. For each PR, run the repository checks, compare the relevant behavior with a working stock clamd, and obtain independent review. Merge through the PR only after its acceptance criteria and required checks pass. Keep the umbrella [issue #5](https://github.com/yavosh/barnacle/issues/5) open until the full daemon qualifies.

The hash experiment has its own preregistered speed tolerances. The stricter release criteria above apply to the complete daemon. Compare both services through the same external client and transport with identical cache settings. Include clean files, harmless detections, nested objects, repeated inputs, and a mixed workload larger than the working set.

The upstream documentation lists the socket commands and database families used to build the compatibility matrix. Confirm behavior against the pinned daemon. [ClamD protocol](https://docs.clamav.net/manual/Usage/ClamdProtocol.html) · [ClamAV signature formats](https://docs.clamav.net/manual/Signatures.html)
