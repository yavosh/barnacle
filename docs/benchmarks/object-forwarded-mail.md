# Forwarded email scan performance

Four clients submitted a forwarded message containing a 440,568-byte Base64 ledger, a uuencoded note, and a contact.
With CRLF line endings Barnacle processed 305 scans/s. The earlier build processed 239 scans/s and stock clamd processed 166 scans/s.
The scanner decodes complete Base64 groups directly into the caller's buffer. The streaming path handles short reads, whitespace, and padding.

All 11,520 requests returned the ledger signature. The 8-bit and quoted-printable controls contained the same CSV as a direct attachment.
Each batch used one pinned ARM64 CPU, 2 GiB RAM, no swap, a fresh daemon, and one exact MD5 rule. Scanning caches were disabled.

Each cell is the median of three batches with 64 requests per client. Peak memory is the cgroup peak in MiB, including the driver and charged file-backed pages.
The raw results include daemon peak RSS and p95 for all three builds. [Raw observations](object-forwarded-mail.csv)

| Workload | Clients | Earlier scans/s | Barnacle scans/s | Barnacle p95 ms | Barnacle peak MiB | Stock scans/s | Stock p95 ms | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Forward, LF | 1 | 241 | 313 | 3.38 | 4.20 | 171 | 6.31 | 11.03 |
| Forward, LF | 4 | 240 | 306 | 19.77 | 9.26 | 168 | 32.18 | 26.97 |
| Forward, CRLF | 1 | 243 | 306 | 3.36 | 4.15 | 170 | 6.35 | 10.98 |
| Forward, CRLF | 4 | 239 | 305 | 22.25 | 9.15 | 166 | 33.12 | 27.00 |
| 8-bit | 1 | 530 | 530 | 2.03 | 4.15 | 249 | 4.23 | 9.38 |
| 8-bit | 4 | 529 | 523 | 15.31 | 5.88 | 249 | 24.33 | 21.15 |
| Quoted-printable | 1 | 532 | 527 | 2.14 | 3.92 | 248 | 4.23 | 9.18 |
| Quoted-printable | 4 | 529 | 533 | 15.44 | 5.82 | 250 | 24.11 | 21.03 |

The earlier build used commit `c07d709`. The measured optimized executable had SHA-256 `b5e932578e6154c22899ec63986628adf941628ecd1acbefcae25938bca38939`.
Stock used Debian clamd `1.4.3+dfsg-1`.

## Reproduction

Append the Rust workload generator to the forwarded-mail tests in a scratch copy of the repository. [Workload generator](object-mail-fixture.rs)

```sh
scratch=$(mktemp -d)
mkdir -p "$scratch/source" "$scratch/fixtures"
cp -R Cargo.toml Cargo.lock src tests examples "$scratch/source/"
cat docs/benchmarks/object-mail-fixture.rs >> "$scratch/source/tests/object_mail_forward.rs"
(cd "$scratch/source" && BARNACLE_BENCH_FIXTURES="$scratch/fixtures" cargo test --release --locked --test object_mail_forward generate_mail_workloads -- --ignored)
```

Build the release daemon and `archive_workspace` driver. Use the same container limits and read-only mounts for each scanner.
Run each workload with one and four clients. Rotate the three daemon launch orders across three rounds. [Container command](object-pdf-excel.md#reproduction)

```sh
/probe run "/fixtures/$workload/input" "$clients" "$daemon" 64
```
