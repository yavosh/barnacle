# XAR inventory scan performance

Apple xar archived a warehouse inventory as an XML subdocument and a 49-byte receipt as a heap member.
The scanner had to process the inventory before matching the receipt's MD5. All 6,720 checked requests returned the receipt signature.

With four clients and 4,096 namespaced rows, Barnacle processed 570 scans/s at 3.93 MiB peak. Stock processed 232 scans/s at 29.48 MiB.
On the plain inventory, Barnacle improved from 598 to 639 scans/s. Its p95 increased from 18.55 to 19.86 ms.

| Inventory | Clients | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Namespaced, 4 rows | 1 | 22,901 | 10,747 | 0.05 | 0.10 | 3.98 | 4.96 |
| Namespaced, 4 rows | 4 | 24,585 | 11,361 | 0.27 | 0.74 | 3.94 | 5.11 |
| Namespaced, 4,096 rows | 1 | 572 | 236 | 1.88 | 4.42 | 3.66 | 10.70 |
| Namespaced, 4,096 rows | 4 | 570 | 232 | 19.32 | 23.99 | 3.93 | 29.48 |
| Plain, 4,096 rows | 1 | 640 | 245 | 1.67 | 4.16 | 3.98 | 10.51 |
| Plain, 4,096 rows | 4 | 639 | 235 | 19.86 | 24.37 | 4.11 | 29.14 |

The table shows medians of three rotated batches. Each client sent 64 requests with daemon caching disabled.
Each fresh ARM64 container had one pinned CPU, 2 GiB RAM, and no swap. The host file cache stayed warm.
Peak cgroup memory includes the driver and charged file-backed pages.
The CSV labels Barnacle `9206060` as `new`, the earlier build `16d8a1c` as `old`, and Debian clamd `1.4.3+dfsg-1` as `stock`.
The earlier build returned incomplete coverage on the namespaced archive, so only the plain archive contributed timing comparisons for that build. [Raw measurements](object-xar-inventory.csv)

## Reproduce

Generate the three input archives in a disposable directory on macOS.

```sh
scratch=$(mktemp -d)
rustc docs/benchmarks/object-xar-inventory.rs -o "$scratch/generate"
cp tests/fixtures/xar/receipt.txt "$scratch/"
(
  cd "$scratch"
  ./generate
  mkdir db
  md5 -q receipt.txt | awk '{print $1 ":49:Workspace.Reference"}' > db/receipt.hdb
  for name in small large plain; do
    xar --prop-include=name --prop-include=type --prop-include=data \
      -n stockroom -s "$name.xml" -cf "$name.xar" receipt.txt
  done
)
```

Mount the directory read-only at `/fixtures` in the pinned Linux container.
Run the Rust `archive_workspace` example with one or four clients for each daemon.

```sh
archive_workspace run /fixtures/large.xar 4 /barnacle 64
archive_workspace run /fixtures/large.xar 4 /usr/sbin/clamd 64
```
