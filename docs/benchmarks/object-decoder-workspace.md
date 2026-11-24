# Archive decoder workspace

The Rust probe creates ordinary XZ and 7z documents with harmless whole-file signatures.
The direct mode runs Barnacle object traversal with a marker callback.
The daemon mode sends the same files over INSTREAM and checks the signature in every response.

Each sample ran in a fresh ARM64 Linux cgroup with one CPU, 2 GiB of memory, and swap disabled.
Workers shared the compressed input and started together.
The CSV records one run per row. Elapsed time covers the worker batch.
Process peak comes from Linux VmHWM. Cgroup peak includes file-backed pages and the driver.
In daemon mode, process peak covers the daemon only. Cgroup peak also includes startup.
Timing rows describe individual batches. The CPU-pinned XZ control contains three batches per implementation.

## Reproduction

Build the release binaries and prepare the corpus on Linux. Keep the fixtures outside the checkout.

```sh
cargo build --locked --release --bin barnacle --example archive_workspace
target/release/examples/archive_workspace prepare /tmp/barnacle-workspace
```

Run each measurement in its own fresh cgroup. For example, these commands use the same isolated local reference image.
The image contains Debian clamav-daemon 1.4.3+dfsg-1.

```sh
probe() {
  fixture=$1
  shift
  docker run --rm --network none --user nobody --cpus 1 --memory 2g --memory-swap 2g \
    -v "$PWD/target/release/examples/archive_workspace:/probe:ro" \
    -v "$PWD/target/release/barnacle:/barnacle:ro" \
    -v /tmp/barnacle-workspace:/fixtures:ro \
    barnacle-issue6-oracle:local /probe run "/fixtures/$fixture" "$@"
}
probe model64.7z 10
probe model64.7z 10 /usr/sbin/clamd
probe model64.7z 10 /barnacle
probe ledger64.7z 10 /usr/sbin/clamd
probe ledger64.7z 10 /barnacle
probe nested8.7z 4
```

For the CPU-pinned controls, add `--cpuset-cpus 0` to the same command.

The tiny inputs contain a 43-byte marker. The larger inputs expand to 16 MiB.
XZ declares a 64 MiB dictionary. The plain 7z inputs use a 16 MiB LZMA2 dictionary.
Each nested solid block contains an 8 MiB ordinary report, its child archive, and a small tail.
The PPMd depth series uses one member per layer and a 16 MiB model.
The ten-worker PPMd tests use a 16 MiB repeated report and a ledger containing 32,768 distinct order lines.
Both declare a 64 MiB PPMd model. The ledger adds a third whole-file signature to the original two-rule database.

## PPMd model admission

Five interleaved trials compared each daemon on a single pinned CPU. Every batch contained ten simultaneous INSTREAM requests.
The table reports median cgroup peak, throughput, and within-batch p95 request latency.

| Document | Daemon | Peak MiB | Requests/s | p95 ms |
| --- | --- | ---: | ---: | ---: |
| Repeated report | Debian clamd | 395.6 | 6.06 | 1,649 |
| Repeated report | Barnacle before model admission | 560.6 | 9.56 | 1,046 |
| Repeated report | Barnacle with model admission | 92.2 | 10.10 | 988 |
| Order ledger | Debian clamd | 50.4 | 41.77 | 239 |
| Order ledger | Barnacle before model admission | 461.9 | 39.76 | 251 |
| Order ledger | Barnacle with model admission | 70.6 | 41.01 | 239 |

Model admission improved Barnacle's median throughput and memory use on both documents.
Stock still used 20.2 MiB less on the ledger. Individual batch times varied across trials.
The CSV preserves the preliminary one-, three-, and seven-model comparisons.
One preliminary stock run failed with a permission error before producing metrics. All 30 final batches returned the expected signature.

## Earlier traversal measurements

| Workload | Original traversal | General decoder admission |
| --- | ---: | ---: |
| Eight nested solid archives, four workers | 478.8 MiB, 399 ms | 98.7 MiB, 315 ms |
| Eight nested PPMd archives, four workers | 452.7 MiB, 16 ms | 65.9 MiB, 7 ms |
| One 64 MiB PPMd model per worker, ten workers | 774.5 MiB, 2,271 ms before admission | 550.2 MiB, 2,018 ms |
| 16 MiB XZ report, four workers pinned to one CPU | 130.0 MiB, 148 ms median | 128.7 MiB, 143 ms median |

Memory values use cgroup peaks. The medians for XZ use three separate process runs.

| Daemon workload pinned to one CPU | Debian clamd | Barnacle before model admission |
| --- | ---: | ---: |
| Eight nested solid archives, four workers | 326.0 MiB, 1,018 ms | 98.8 MiB, 709 ms |
| 64 MiB PPMd model, ten workers | 399.4 MiB, 1,314 ms | 560.7 MiB, 1,038 ms |
| Signature after nine 8 MiB reports in one solid block, one worker | 107.2 MiB, 296 ms | 84.2 MiB, 215 ms |


## Decoder behavior

The locked LZMA implementation grows its history as bytes are produced. The minimum allocation is 64 KiB.
PPMd allocates its model independently of output size. The model size affects decoding and cannot be reduced losslessly.

The original traversal kept a 7z block decoder alive while scanning its children.
The final-member-release measurement dropped the dictionary before visiting a block's last nonempty member.
The solid-spool measurement released the dictionary before any nested scan.
The admission measurement also releases large sibling snapshots separately and coordinates simultaneous XZ and 7z decoder allocations.

Admission accounts for declared PPMd models and estimates LZ history from the available output.
XZ first reserves up to one quarter of the budget and enforces that bound on each block.
A larger model triggers one replay under the stock ceiling. The earlier decoder releases its reservation first.
The process-wide target is 512 MiB. An individually supported request above that target runs alone.
PPMd also has a 64 MiB aggregate model target. A larger model runs at its declared size.
A waiting PPMd request acquires its model reservation before reserving general decoder memory. Other codecs can keep using the general pool.
Metadata parsing with an encoded 7z header also runs alone.
The charge covers active archive decoders. Scanner indexes, retained metadata, snapshots, and file cache consume additional memory.

A solid batch stages up to 64 MiB of eligible sibling data, or one larger eligible member.
Additional batches replay the shared compressed prefix.
Files of at least 4 MiB use separate private snapshots. Scanning releases each completed sibling.
Private snapshots exceeding 64 KiB spill to disk. Cancellation is checked during decoding and admission waits.

The Rust archive comparisons cover early competing members, a nested first winner, and a deadline before a later matching file.
Run the same comparison in the pinned reference container.

```sh
cargo test --locked --test object_archives -- --include-ignored --test-threads=1
cargo test --locked --lib a_cancelled_waiter_releases_its_place
```

The complete samples and intermediate implementations appear in [object-decoder-workspace.csv](object-decoder-workspace.csv).
