# Packed PDF catalog

A 48,161-byte PDF contains a physical receipt and a 1,048,617-byte catalog inside a compressed object stream.
One exact MD5 rule selects the receipt. A separate run selects the catalog using a second database.
Each run used one ARM64 CPU, 2 GiB RAM, and disabled scan caching.

## Signature-dependent text normalization

With only a whole-file signature loaded, commit `7717297` skips plain-text normalization on the expanded PDF carrier.
The receipt and catalog runs each saved 1,048,880 written bytes per scan.

| Workload | Clients | Earlier scans/s | New scans/s | Stock scans/s | Earlier p95 ms | New p95 ms | Stock p95 ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Physical receipt | 1 | 426 | 512 | 272 | 2.84 | 2.01 | 3.96 |
| Deferred catalog | 4 | 284 | 307 | 174 | 22.02 | 23.31 | 32.36 |
| Generic text rule | 1 | 517 | 488 | 212 | 2.10 | 2.39 | 5.37 |

Each median covers three rotated fresh-container runs with 256 warm requests and one initial request per run.
The earlier binary used commit `5f732c7`. All 6,939 replies matched the selected signature.
The generic control uses the mixed-case inventory and a target-0 body rule matching `warehouse order number verified`.
Its normalized view remains eligible. The two Barnacle builds wrote the same bytes per request on this control.
[Raw measurements](object-script-eligibility.csv) · [Inventory fixture](object-script-views.md#fixtures)

## Retained carrier with bulk ASCII normalization

All 24,960 requests across the carrier retention and bulk normalization experiments returned the expected signature.
On four clients the physical receipt reached 454 scans/s at 8.88 MiB. The preceding build reached 347 scans/s at 8.79 MiB.
Barnacle scans printable ASCII blocks for consecutive spaces. When normalization preserves their length, it lowercases them in the caller's buffer.
This improves the later text scan of the expanded carrier. The scanner still checks the catalog and receipt in stock order.

| Object selected | Clients | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Receipt | 1 | 437 | 280 | 2.52 | 3.81 | 4.19 | 8.48 |
| Receipt | 4 | 454 | 284 | 18.83 | 21.35 | 8.88 | 18.65 |
| Catalog | 1 | 290 | 182 | 3.52 | 5.58 | 4.20 | 8.18 |
| Catalog | 4 | 288 | 180 | 22.71 | 30.65 | 8.72 | 18.70 |

Each value is the median of three rotated batches. Each client submitted 64 requests to a fresh daemon.
The raw data identify commit `9544ac5` as `bulk`, the preceding commit `5a3ba8c` as `retained`, and commit `0d39dc1` as `tokenizer`.
Stock used Debian clamd 1.4.3. Peaks include the driver and file-backed pages. [Normalization measurements](object-pdf-catalog-normalization.csv)

## Initial carrier retention

Barnacle commit `0d39dc1` wrote selected catalog bytes into a second spool. Commit `16d8a1c` retains the decoded carrier.
The four-client receipt workload used 3.29 MiB less peak cgroup memory with retention. Throughput fell from 339 to 320 scans/s.
Stock clamd 1.4.3 processed 283 scans/s on that workload and had the lowest p95 latency.

Each cell shows the median of six batches on CPU 0, with 64 requests per client and a fresh daemon per batch.
Cgroup peaks include the driver and charged file-backed pages. The raw data also include three earlier rounds on CPU 2. [Raw measurements](object-pdf-catalog.csv)

| Object selected | Clients | Scanner | Scans/s | p95 ms | Peak MiB |
| --- | ---: | --- | ---: | ---: | ---: |
| Receipt | 1 | Barnacle, second spool | 342 | 2.96 | 4.75 |
| Receipt | 1 | Barnacle, retained carrier | 321 | 3.26 | 4.04 |
| Receipt | 1 | Stock | 287 | 3.56 | 8.23 |
| Receipt | 4 | Barnacle, second spool | 339 | 24.50 | 13.85 |
| Receipt | 4 | Barnacle, retained carrier | 320 | 23.85 | 10.56 |
| Receipt | 4 | Stock | 283 | 21.34 | 18.82 |
| Catalog | 1 | Barnacle, second spool | 239 | 4.23 | 4.94 |
| Catalog | 1 | Barnacle, retained carrier | 229 | 4.57 | 3.73 |
| Catalog | 1 | Stock | 184 | 5.61 | 8.09 |
| Catalog | 4 | Barnacle, second spool | 236 | 23.86 | 13.60 |
| Catalog | 4 | Barnacle, retained carrier | 225 | 25.46 | 10.44 |
| Catalog | 4 | Stock | 177 | 32.50 | 18.67 |

## Reproduce

Generate both one-rule inputs in a disposable copy of the checkout.

```sh
scratch=$(mktemp -d)
mkdir "$scratch/src"
cp -R Cargo.lock Cargo.toml src tests examples "$scratch/src/"
cat docs/benchmarks/object-pdf-catalog-fixture.rs >> "$scratch/src/tests/object_pdf_streams.rs"
BARNACLE_BENCH_FIXTURES="$scratch/fixtures" cargo test --manifest-path "$scratch/src/Cargo.toml" \
  --release --locked --test object_pdf_streams generate_catalog_workload -- --ignored
```

The generated `packed/input` and `catalog/input` have SHA-256 `4eabdc6d8b338ef60a72acee3be4f667421ef5856ba096f3347df35f64d73089`.
Build the Linux release binaries for the listed revisions. Mount the fixtures, driver, and daemon read-only in the pinned Debian container.
Use a fresh container for each row and rotate the scanner order. Keep the host file cache warm.

```sh
archive_workspace run /fixtures/packed/input 4 /usr/sbin/clamd 64
archive_workspace run /fixtures/packed/input 4 /barnacle 64
```
