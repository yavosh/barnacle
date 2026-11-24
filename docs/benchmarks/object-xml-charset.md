# HWPML attachment character encoding

Barnacle scanned a Windows-1252 HWPML ledger at 60.33 scans/s with four clients. Stock clamd processed 33.34 scans/s.
Peak cgroup memory was 30.3 MiB for Barnacle and 79.6 MiB for stock.
Barnacle's UTF-8 control reached 71.91 scans/s and used 19.7 MiB.

## Results

Each cell gives the median of three batches. The daemon order alternated across the three batches for each configuration.

| Source encoding | Clients | Daemon | Scans/s | p95 ms | Daemon peak MiB | Cgroup peak MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| Windows-1252 | 1 | Barnacle | 54.81 | 18.2 | 9.8 | 12.7 |
| Windows-1252 | 1 | Stock | 31.39 | 31.8 | 26.0 | 27.3 |
| Windows-1252 | 4 | Barnacle | 60.33 | 66.2 | 27.3 | 30.3 |
| Windows-1252 | 4 | Stock | 33.34 | 119.8 | 60.9 | 79.6 |
| UTF-8 | 1 | Barnacle | 66.44 | 15.0 | 7.1 | 10.4 |
| UTF-8 | 1 | Stock | 39.38 | 25.3 | 26.3 | 28.0 |
| UTF-8 | 4 | Barnacle | 71.91 | 55.5 | 16.3 | 19.7 |
| UTF-8 | 4 | Stock | 41.93 | 95.3 | 62.0 | 81.9 |

The benchmark used one pinned ARM64 CPU, 2 GiB of memory, and no swap.
Each batch started a fresh daemon and cgroup. Each client sent one INSTREAM request after startup, with caching disabled.
The p95 uses the slowest request in these one- and four-request batches.
The cgroup peak includes startup, file-backed pages, and the driver. Daemon peak comes from Linux VmHWM.

Each document contains the same 65,536 ledger rows in an HWPML BINDATA attachment.
Both documents start with EF BB BF, the prefix stock expects for this type.
The Windows-1252 and UTF-8 XML documents contain 2,883,736 and 3,080,337 bytes, respectively.
The Windows-1252 document uses single-byte euro signs and accented letters.
Both scanners had one local signature for the 3,080,192-byte UTF-8 attachment.
The final comparison includes XML character validation, bounded parser read-ahead, and ordered handling of conversion errors.
Both daemons returned the expected signature in all 60 final requests.
The CSV includes the original 100 requests and all 24 final batches in execution order. [Raw measurements](object-xml-charset.csv)

## Build identification

| CSV comparison | Barnacle release ELF SHA-256 | Barnacle ELF bytes | Batches |
| --- | --- | ---: | ---: |
| `initial` | `c4178638435a2c0c71de8622f014ba72ca73f826607376b1b27c3fd537e2f332` | 5,751,424 | 40 |
| `final` | `d8b93b44e81e633b3687f90b6f77f6af688f05be0afdcd28f34c57a3a606ed4a` | 5,748,576 | 24 |

The initial four-client Windows-1252 median was 64.26 scans/s for Barnacle and 34.60 scans/s for stock.
Those earlier medians use rounds 3–5, which alternated daemon order. Each comparison ran at a different time.
A separate ARM64 release experiment measured the initial charset reader at 5,738,448 bytes against a 5,533,416-byte baseline (3.71% larger).

## Reproduction

Build the driver and daemon on ARM64 Linux. The reference image contains Debian clamd 1.4.3+dfsg-1.

```sh
cargo build --release --locked --bin barnacle --example archive_workspace
scratch=$(mktemp -d)
chmod 755 "$scratch"
rustc --edition 2024 tests/fixtures/xml/charset_bench.rs -o "$scratch/generate"
"$scratch/generate" "$scratch"
md5sum "$scratch/ledger.utf8" | awk '{print $1 ":3080192:Workspace.Reference"}' > "$scratch/db/reference.hdb"
```

Run each batch in a fresh cgroup. Use both encodings at one and four clients with each daemon.

```sh
probe() {
  docker run --rm --network none --user nobody --cpuset-cpus 0 --cpus 1 --memory 2g --memory-swap 2g \
    -v "$PWD/target/release/examples/archive_workspace:/probe:ro" \
    -v "$PWD/target/release/barnacle:/barnacle:ro" -v "$scratch:/fixtures:ro" \
    barnacle-issue6-oracle:local /probe run "/fixtures/$1.xml" "$2" "$3"
}
for round in 1 2 3; do
  for encoding in windows-1252 utf-8; do
    for clients in 1 4; do
      if { test "$round" = 2 && test "$clients" = 1; } || { test "$round" != 2 && test "$clients" = 4; }; then
        probe "$encoding" "$clients" /usr/sbin/clamd
        probe "$encoding" "$clients" /barnacle
      else
        probe "$encoding" "$clients" /barnacle
        probe "$encoding" "$clients" /usr/sbin/clamd
      fi
    done
  done
done
```
