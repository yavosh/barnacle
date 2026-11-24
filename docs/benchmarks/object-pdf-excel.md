# PDF LZW attachments and Excel pictures

The initial implementation used 8.77 MiB of cgroup memory for four simultaneous PDF scans. Stock clamd used 17.98 MiB.
Barnacle processed 145.41 PDF scans/s and stock processed 171.67 scans/s. Stock was faster in all six paired PDF batches.
The follow-up experiment measured sustained scans after changing LZW expansion and hash selection. [Sustained results](object-pdf-lzw-sustained.md)

| Document | Clients | Daemon | Scans/s | p95 ms | Daemon peak MiB | Cgroup peak MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| PDF | 1 | Barnacle | 115.61 | 8.60 | 5.95 | 3.85 |
| PDF | 1 | Stock | 155.87 | 6.37 | 15.14 | 8.36 |
| PDF | 4 | Barnacle | 145.41 | 27.43 | 9.25 | 8.77 |
| PDF | 4 | Stock | 171.67 | 23.19 | 20.08 | 17.98 |
| XLS | 1 | Barnacle | 5986.52 | 0.12 | 4.34 | 3.56 |
| XLS | 1 | Stock | 812.18 | 1.17 | 15.11 | 4.54 |
| XLS | 4 | Barnacle | 11362.28 | 0.26 | 4.41 | 3.77 |
| XLS | 4 | Stock | 1726.21 | 2.26 | 15.23 | 4.86 |

Each cell shows the median of three batches. Each client issued one timed INSTREAM request per batch.
The XLS batches took under 4 ms. Their throughput reflects short concurrent bursts.
The reported p95 is the slowest request in each one- or four-request batch. [Raw measurements](object-pdf-excel.csv)

## Documents and signatures

The 171,046-byte PDF 1.5 document contains one page and one referenced LZW attachment.
Its 170,361-byte stream expands to 32,768 ASCII receipt lines totaling 1,572,864 bytes.
The encoder uses 9- through 12-bit dictionary codes with the default early code-width change.
The local database contains one exact MD5 signature for the decoded ledger, `f7013db2d953c09ada566fef204861b8`.

The 8,192-byte Excel file contains a 6,396-byte BIFF8 Workbook stream from the checked-in macro-free workbook.
The generator writes that stream into a new compound file with fixed timestamps.
Its one local signature matches the embedded 4,556-byte PNG, `b8bde3e503a52c3239ab107b1ff268b6`. [Source workbook](../../tests/fixtures/xls/dots.xls)

Each batch started a fresh daemon with caching disabled in a network-isolated ARM64 Linux container.
The container received one pinned CPU, 2 GiB of memory, and no swap.
The driver verified `Workspace.Reference.UNOFFICIAL FOUND` on all 60 requests.
The RSS peak uses Linux VmHWM. The cgroup peak includes the driver and file-backed pages charged to the container.
Pages shared from another cgroup can contribute to RSS without a corresponding memory charge.
The reference was Debian clamd 1.4.3+dfsg-1. The Barnacle release ELF had SHA-256 `0a3c42d801fc42bc60ceb4872fa89eaea38325ed8223d9f1aed8a418a467d975`.

## Reproduction

Run these commands from the repository root in the Linux build environment.
Append the [workload generator](object-pdf-excel-fixtures.rs) to a scratch copy of the PDF tests to reuse their encoding and container helpers.

```sh
scratch=$(mktemp -d)
chmod 755 "$scratch"
mkdir -p "$scratch/source" "$scratch/fixtures"
cp -R Cargo.lock Cargo.toml src tests examples "$scratch/source/"
cat docs/benchmarks/object-pdf-excel-fixtures.rs >> "$scratch/source/tests/object_pdf_lzw.rs"
export CARGO_TARGET_DIR="$scratch/target"
(cd "$scratch/source" && BARNACLE_BENCH_FIXTURES="$scratch/fixtures" cargo test --release --locked --test object_pdf_lzw generate_pdf_excel_workloads -- --ignored)
cargo build --release --locked --bin barnacle --example archive_workspace
```

Check both generated inputs with SHA-256. The PDF digest is `55b697077aff29d1a19ea43c7b9f888624efa67fa253032addcb3caf70962d70`.
The XLS digest is `6f3891eded61abe52edb780925356048a53d8a1ed46c7ce4145f58085c1e2db4`.

```sh
probe() {
  docker run --rm --network none --user nobody --cpuset-cpus 0 --cpus 1 --memory 2g --memory-swap 2g \
    -v "$CARGO_TARGET_DIR/release/examples/archive_workspace:/probe:ro" \
    -v "$CARGO_TARGET_DIR/release/barnacle:/barnacle:ro" -v "$scratch/fixtures:/fixtures:ro" \
    barnacle-issue6-oracle:local /probe run "/fixtures/$1/input" "$2" "$3"
}
for round in 1 2 3; do
  for workload in pdf xls; do
    for clients in 1 4; do
      if { test "$round" = 2 && test "$clients" = 1; } || { test "$round" != 2 && test "$clients" = 4; }; then
        probe "$workload" "$clients" /usr/sbin/clamd
        probe "$workload" "$clients" /barnacle
      else
        probe "$workload" "$clients" /barnacle
        probe "$workload" "$clients" /usr/sbin/clamd
      fi
    done
  done
done
```
