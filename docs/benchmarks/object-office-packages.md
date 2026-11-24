# Office package scan performance

Both daemons scanned the same three Office packages and detected the same embedded PNG in all 23,040 requests.
On the XLSX with four clients, Barnacle processed 4,836 scans/s and stock clamd processed 1,468 scans/s.
Each batch used one pinned Linux ARM64 CPU, 2 GiB of RAM, no swap, and a fresh daemon.
The database contained one MD5 rule. [Fixture provenance](../../tests/fixtures/ooxml/README.md)

Each value is the median of three batches. Each client submitted 256 requests with the scan cache disabled.
The Rust driver recorded each request's latency and checked every reply. Cgroup peak memory includes the driver and charged file-backed pages.
The raw observations include the daemon's separate peak RSS. [Raw measurements](object-office-packages.csv)

| Format | Clients | Barnacle scans/s | Barnacle p95 ms | Barnacle peak MiB | Stock scans/s | Stock p95 ms | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| DOCX | 1 | 3277 | 0.32 | 3.86 | 1188 | 0.92 | 4.82 |
| DOCX | 4 | 3390 | 2.28 | 3.92 | 1094 | 7.36 | 5.66 |
| PPTX | 1 | 7007 | 0.16 | 3.35 | 2032 | 0.52 | 4.91 |
| PPTX | 4 | 7200 | 0.96 | 4.05 | 2044 | 4.23 | 5.88 |
| XLSX | 1 | 4744 | 0.23 | 4.13 | 1470 | 0.73 | 4.95 |
| XLSX | 4 | 4836 | 1.47 | 3.86 | 1468 | 6.04 | 5.87 |

## Reproduction

Build the release daemon and `archive_workspace` example. For each package, create a directory containing `input` and `db/picture.hdb`.
Copy the corresponding package to `input`. Use this rule in all three databases.

```text
b8bde3e503a52c3239ab107b1ff268b6:4556:Workspace.Reference
```

Use the documented container limits and mounts. Run each daemon separately with one and four clients.
Alternate daemon order across three rounds. [Container command](object-pdf-excel.md#reproduction)

```sh
/probe run "/fixtures/$format/input" "$clients" "$daemon" 256
```

Stock used Debian clamd `1.4.3+dfsg-1`. The table uses commit `209ccc4`, with executable SHA-256 `e5192be40a214e2aecb5269018669a59ed477408f12a0b9aa4044774230ec6a7`.
The CSV also records an earlier run of 23,040 requests, with executable SHA-256 `469e916eaa7c57107b03dbd2c282d60a5ef4e6e442ab1b6ebb97381fa82dd64a`.
