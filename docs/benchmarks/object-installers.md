# Installer resource measurements

The workload scans a 1,041,088-byte order ledger inside an inert PE document.
Debian makensis 3.11-1 compressed the same ledger with each codec.
The Rust fixture builder retains the resource archive and replaces the executable image with a read-only data section.
A single whole-file signature identifies the original ledger.

The release driver issued INSTREAM requests on one pinned ARM64 CPU with 2 GiB and swap disabled.
Each batch started a fresh daemon and cgroup. The cgroup peak includes startup, file-backed pages, and the driver.
Four-client results use the median of three interleaved runs. Single-client results use one run.

| NSIS bzip2 batch | Daemon | Peak MiB | Scans/s | p95 ms |
| --- | --- | ---: | ---: | ---: |
| One client | Barnacle | 12.1 | 51.85 | 19.2 |
| One client | Debian clamd 1.4.3+dfsg-1 | 27.7 | 61.21 | 16.2 |
| Four clients | Barnacle | 26.3 | 75.42 | 52.9 |
| Four clients | Debian clamd 1.4.3+dfsg-1 | 25.5 | 77.05 | 51.8 |

The final four-client zlib control peaked at 6.9 MiB with NSIS bzip2 linked and 6.8 MiB with its dispatch disabled.
One stock run stopped before producing counters. Its replacement returned the expected signature.
The initial and final runs are recorded in [object-installers.csv](object-installers.csv).

## Release size

All builds used the same frozen source, lockfile, and Linux release target.
The comparison disabled only the named parser entry points in private copies.

| Parser configuration | ELF file bytes | GNU size text bytes | GNU size data bytes |
| --- | ---: | ---: | ---: |
| Installer dispatch disabled | 5,509,792 | 3,601,326 | 282,608 |
| Installers with NSIS bzip2 dispatch disabled | 5,526,824 | 3,626,534 | 283,392 |
| All installer readers enabled | 5,535,216 | 3,647,378 | 283,928 |

The complete readers add 25,424 file bytes and 47,372 loaded text/data bytes.
The bzip2 path accounts for 8,392 file bytes and 21,380 loaded text/data bytes.

## Coverage

NSIS block and solid archives use the installed scanner's member order.
The header has its own raw matching stage. Subsequent files receive ordinary recursive scans.
The tests use separate signature sets to check both the first and the second package members.
They cover header-only matches, synthetic parent metadata, outer hashes, scan depth, file count, and the total byte budget.

MSI-style InstallShield resources preserve the decoded member names.
Older ordinary InstallShield overlay records retain their PE parent.
Their ordinary members precede deferred cabinet files. A separate legacy cabinet directory still requires the reference scanner.

The NSIS bzip2 reader uses the Apache-2.0 nsis 0.6.1 crate.
Its public decoder bounds output during decoding. It can check cancellation only between calls.
Barnacle therefore limits each call to 256 KiB of packed data and 4 MiB of output.
A solid stream can still yield a match from a complete earlier member within that window.
Remaining unsupported data produces an incomplete scan.

## Reproduction

Build the driver and fixture utility on Linux. Use an empty scratch directory.

```sh
cargo build --release --locked --bin barnacle --example archive_workspace
rustc --edition 2024 tests/fixtures/installers/bench.rs -o /tmp/installer-fixture
/tmp/installer-fixture prepare /tmp/installer-bench
(
  cd /tmp/installer-bench || exit 1
  for codec in zlib bzip2 lzma; do
    makensis -V1 -DOUTPUT="$PWD/$codec-blocks.pkg" -DCODEC="$codec" -DOPTIONS= notes.nsi || exit 1
  done
  md5sum first.txt | awk '{print $1 ":1041088:Workspace.Reference"}' > db/reference.hdb
)
/tmp/installer-fixture resources /tmp/installer-bench
```

Use the container command from [the archive workspace benchmark](object-decoder-workspace.md).
Mount `/tmp/installer-bench` at `/fixtures` and add `--cpuset-cpus 0`.
Run each driver call in a fresh cgroup.

```sh
probe bzip2.sample 4 /usr/sbin/clamd
probe bzip2.sample 4 /barnacle
probe zlib.sample 4 /barnacle
```
