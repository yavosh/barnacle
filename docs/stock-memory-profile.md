# Profile clamd memory on the reference guest

Logical signatures had the largest measured memory cost. Omitting them reduced ready anonymous memory by 690.4 MiB. Mapping the PE section hash table saved about 179 MiB, but warm digest throughput at concurrency one fell 5.73%.

The reference is Debian arm64 `clamav-daemon` 1.4.3+dfsg-1 on one vCPU and 2 GiB RAM without swap. The scanner cgroup has a 1,400 MiB soft limit and a 1,536 MiB hard limit. Clean-file caching is enabled. The verified database snapshots are main 63, daily 28187, and bytecode 339. [Archive digests](whole-file-hashes.md#reproduce-the-pinned-generation) · [Reference daemon configuration](hash-benchmark-run.md#prepare-the-disk-image)

## Stock with the complete signed feed

At four concurrent requests, stock used **1,127.8 MiB** at warm idle. Anonymous pages accounted for 986.8 MiB and file-backed pages for 132.8 MiB. At concurrency one, warm idle was 1,114.0 MiB. The table shows medians of three independent boots at concurrency four. All memory and disk-read figures are MiB.

| Stage | Current | Anonymous | File-backed | Lifetime peak | Cumulative disk reads | Cumulative major faults |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Ready | 1,077.5 | 955.6 | 119.5 | 1,077.7 | 119.2 | 79 |
| Cold scans, largest sampled current | 1,127.1 | 997.8 | 125.6 | 1,127.2 | 119.5 | 81 |
| Warm idle | 1,127.8 | 986.8 | 132.8 | 1,131.1 | 119.5 | 81 |
| Reload pass, largest sampled current | 1,162.8 | 1,009.2 | 133.9 | 1,164.3 | 119.5 | 81 |
| Reload request to activation, largest sampled current | 1,144.0 | 989.2 | 133.2 | 1,144.1 | 119.5 | 81 |
| Activation observed | 1,144.0 | 989.2 | 133.2 | 1,144.1 | 119.5 | 81 |

| Requests in flight | Pass | Files/s | p95 (ms) |
| ---: | --- | ---: | ---: |
| 1 | Cold | 205.0 | 11.28 |
| 1 | Warm | 1,390.5 | 1.32 |
| 1 | During reload | 75.5 | 13.04 |
| 4 | Cold | 205.2 | 47.97 |
| 4 | Warm | 1,502.8 | 6.03 |
| 4 | During reload | 76.6 | 48.82 |

All 73,728 timed uploads returned clean. Median readiness took 3.80 s at concurrency four. Stock activated the reloaded generation after 33.20 s. In every trial, the scan workload was still running when the driver observed activation. The reload used the same verified generation. [Stage readings](benchmarks/stock-profile-stages.csv) · [Pass timings](benchmarks/stock-profile-passes.csv) · [VM reproduction](profile-vm.md)

## Measurement method

Start each trial in a fresh guest. Launch clamd inside the scanner cgroup so that loading the database charges that cgroup. The Rust driver lives in a separate cgroup. It checks the file corpus before timing. The 4,096 requests replay the same objects and order as the [whole-file experiment](hash-baseline.md). The packed corpus contains 352,325,632 bytes with SHA-256 `ceb040d353d99e018381733c3331f2cffe2f4f8489e400865823d562aaad199d`.

The full-feed trials use the signed archives and the stock daemon's full scan pipeline. Record readiness after the first successful `PING`. Replay a cold pass and a warm pass. Read warm idle memory ten seconds after the warm pass. Request a serial database reload during a third pass. Check daemon activation and scan a harmless file after reload.

`memory.current` measures total cgroup memory. `anon` and `file` come from `memory.stat`. Other memory charges account for the difference. `memory.peak`, storage reads, and major page faults are cumulative since cgroup creation. The sampled active high point is the largest observed `memory.current` during each pass. It can miss brief peaks between samples. Cold measurements include a loaded engine and a fresh scan-result cache.

## How to interpret a family comparison

Compare the diagnostic configuration with every family present against an otherwise identical configuration omitting one family. Each difference measures the marginal cost of loading that family alongside the others. Subtract anonymous and file-backed bytes separately. The results include shared compiled tables, allocator overhead, and changes in allocation behavior. Adding the marginal costs does not reconstruct the total.

The diagnostic runs use extracted main and daily members so individual families can be omitted. They retain the signed bytecode archive, configuration, file types, ignore entries, and allowlists. Extracted names can acquire an unofficial suffix, and input caching and load order can change. Use the full signed-feed trials for actual scanner memory and speed.

## Storage candidate

The storage experiment uses PE section hashes. A section lookup has a well-defined input, the bytes and length of a PE section, and a named result that stock clamd can verify. Logical signatures also require compiled pattern and expression evaluators. Fetching their source text would measure a different operation.

Both candidate backends use the same full section table. The payload trace times hashing and lookups on harmless section-sized buffers. The digest trace times lookups for known keys and modified digests. Full-file parsing and the rest of clamd's pipeline are outside those timings. Compare the two backends within each trace, pass, and concurrency level.

Before collecting candidate timings, we chose to report the observed memory saving, throughput ratio, and p95 ratio for every workload. A claim of unchanged speed requires throughput at least as high and p95 at most as high across all measured conditions. Mixed results stay visible. Three repetitions describe this guest and generation. The complete daemon has a separate release test. [Candidate inputs and reproduction](section-storage-run.md)

## Ranked family costs

The table subtracts each omission profile's median ready memory from the all-family median. The range shows the three paired anonymous differences. Every value is in MiB.

| Family omitted | Anonymous saving | Paired anonymous range | File-backed saving | Total saving |
| --- | ---: | ---: | ---: | ---: |
| Logical signatures | 690.4 | 688.0–691.1 | 88.4 | 780.3 |
| PE section hashes | 177.7 | 176.4–178.3 | 159.7 | 338.2 |
| Whole-file hashes | 52.8 | 51.6–53.8 | 36.4 | 89.4 |
| Body patterns | 39.2 | 37.9–41.4 | 23.6 | 62.9 |
| Container metadata, icons, and URL rules | 10.7 | 9.5–12.0 | 0.1 | 10.8 |

All extracted families together used 998.5 MiB of anonymous memory at readiness. The fixed base used 10.4 MiB. Logical signatures account for the largest measured difference. When building the [logical matcher](https://github.com/yavosh/barnacle/issues/3), measure pattern tables, expression programs, and per-scan state separately. The readiness measurement includes shared initialization costs. It cannot attribute bytes to individual compiled tables or measure scratch space allocated during a scan.

## PE section storage results

Mapping the 179.27 MiB section table saved **177.38–179.27 MiB** of warm idle memory. The mapped backend missed the unchanged-speed criterion. At one outstanding warm digest lookup, throughput fell 5.73% and p95 rose 8.40%. Keep this result as an engineering tradeoff when implementing [section detection](https://github.com/yavosh/barnacle/issues/10). A complete daemon comparison is required before adopting this layout.

| Trace | In flight | Pass | Idle saved (MiB) | Resident requests/s | Mapped requests/s | Resident p95 (µs) | Mapped p95 (µs) |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: |
| Payload | 1 | Cold | 179.27 | 6,465 | 6,627 | 474.458 | 457.375 |
| Payload | 1 | Warm | 179.27 | 6,645 | 6,650 | 455.042 | 453.042 |
| Payload | 4 | Cold | 179.27 | 6,622 | 6,629 | 474.666 | 472.333 |
| Payload | 4 | Warm | 179.27 | 6,647 | 6,617 | 471.375 | 476.166 |
| Digest | 1 | Cold | 177.38 | 2,240,202 | 2,141,728 | 0.542 | 0.583 |
| Digest | 1 | Warm | 177.38 | 2,426,540 | 2,287,479 | 0.500 | 0.542 |
| Digest | 4 | Cold | 178.39 | 2,212,018 | 2,159,436 | 0.542 | 0.542 |
| Digest | 4 | Warm | 178.39 | 2,348,263 | 2,347,274 | 0.541 | 0.541 |

Idle memory was measured once per trial, ten seconds after its warm pass. Both backends agreed on all 98,304 payload requests and 1,572,864 digest queries. The Rust regression test and stock clamd also returned the same winning signature for a harmless PE section with competing rules. [Raw candidate measurements](benchmarks/section-profile-samples.csv)
