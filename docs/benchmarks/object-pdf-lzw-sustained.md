# Sustained PDF attachment scans

On the 1.5 MiB ledger attachment, Barnacle processed 244 scans/s with four clients and an MD5 rule.
Stock clamd processed 187 scans/s. Their peak cgroup memory was 9.09 MiB and 17.85 MiB respectively.
The earlier Barnacle build processed 152 scans/s with 8.91 MiB peak cgroup memory on the same workload.

The decoder stores four trailing bytes per dictionary entry and follows one link per four output bytes.
The validated hash index records an exact-size range and a wildcard flag for each hash algorithm.
Barnacle hashes each extracted object with every algorithm whose signatures could match its size.
It preserves the configured hash precedence, the exact lookup inside each range, and outer-file MD5 reporting.

## Results

Each cell gives the median of three fresh-daemon batches. Each client sent 32 requests with the scan cache disabled.
The driver verified all 4,320 replies in the final comparison and calculated p95 from individual request times.
Each batch had one pinned ARM64 CPU, 2 GiB RAM and no swap. The cgroup peak includes the driver and charged file-backed pages.
Baseline used commit `1b8e4c5`. Stock used Debian clamd `1.4.3+dfsg-1`. [Raw observations](object-pdf-lzw-sustained.csv)

| Database | Clients | Scanner | Scans/s | p95 ms | Daemon peak MiB | Cgroup peak MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| MD5 | 1 | Baseline | 148.30 | 7.39 | 5.95 | 3.96 |
| MD5 | 1 | Barnacle | 240.30 | 4.35 | 6.00 | 4.17 |
| MD5 | 1 | Stock | 179.88 | 6.08 | 16.14 | 8.51 |
| MD5 | 4 | Baseline | 152.30 | 32.46 | 11.15 | 8.91 |
| MD5 | 4 | Barnacle | 243.82 | 22.56 | 10.34 | 9.09 |
| MD5 | 4 | Stock | 187.16 | 30.00 | 21.02 | 17.85 |
| SHA-256 | 1 | Baseline | 150.53 | 7.10 | 5.93 | 3.85 |
| SHA-256 | 1 | Barnacle | 350.07 | 3.13 | 6.00 | 3.59 |
| SHA-256 | 1 | Stock | 170.36 | 6.15 | 16.33 | 9.05 |
| SHA-256 | 4 | Baseline | 146.30 | 32.26 | 11.07 | 9.16 |
| SHA-256 | 4 | Barnacle | 351.01 | 21.00 | 7.86 | 7.15 |
| SHA-256 | 4 | Stock | 166.84 | 32.55 | 21.67 | 18.83 |
| Mixed | 1 | Baseline | 150.04 | 7.02 | 5.95 | 3.79 |
| Mixed | 1 | Barnacle | 192.04 | 5.73 | 6.00 | 3.99 |
| Mixed | 1 | Stock | 157.34 | 7.01 | 16.26 | 8.47 |
| Mixed | 4 | Baseline | 150.20 | 33.05 | 11.07 | 9.00 |
| Mixed | 4 | Barnacle | 196.54 | 27.20 | 10.84 | 9.02 |
| Mixed | 4 | Stock | 157.82 | 33.98 | 21.96 | 19.38 |

The MD5 and SHA-256 databases each contain one exact rule for the decoded attachment.
The mixed database adds a wildcard MD5 miss and an exact SHA-1 miss before the SHA-256 hit.
These measurements cover one PDF and three local database configurations. Official feed qualification remains open.

The raw CSV also includes two decoder trials with the original hash matching path.
Each trial verified 1,440 requests. Four-byte and eight-byte suffixes had similar isolated traversal times on this ledger.
The four-byte representation uses 40 KiB for 4,096 entries on ARM64. The eight-byte version used 56 KiB.

## Reproduction

Generate the PDF with the Rust fixture and build the release-mode daemon and driver. [Fixture and environment](object-pdf-excel.md#reproduction)
Make three copies of the input, each with its own sibling `db` directory.
Keep the generated MD5 rule in the first directory. Put this line in `reference.hsb` in the SHA-256 directory.

```text
8d6d20af98b425560e8b301be8653c7c1770c659bcc4f0585dbaefafa7765f45:1572864:Workspace.Reference
```

For the mixed directory, retain the SHA-256 rule. Add the following line to the same HSB file.

```text
666f1626ad51c99c10ae69aceaf2b4dd00914c19:1572864:Workspace.MissSha1
```

Add the following rule in a separate `md5.hdb` file.

```text
13ec785fb00ee21b7b32182c90066972:*:Workspace.Miss:73
```

Use the same container limits and mounts as the single-request benchmark.
Inside each fresh container, run this command for each database, daemon, and client count.

```sh
/probe run "/fixtures/$database/input" "$clients" "$daemon" 32
```

Run three rounds and rotate the three daemon launch orders. Use one and four clients.
The final Barnacle ELF SHA-256 was `39aca855fa3be090f8221e8d85b7c07aa2097793a24edcfdbaaa9feca493fae0`.
