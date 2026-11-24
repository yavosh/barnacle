# Unicode HTML normalization

With four concurrent UTF-16BE requests, Barnacle processed 586 scans/s and stock clamd processed 568 scans/s.
With one request, Barnacle processed 398 scans/s and stock processed 436 scans/s.
At four clients, Barnacle's median daemon peak was 4.82 MiB and stock's was 14.09 MiB.

Each value is the median of three short batches. Batch p95 latencies ranged from 1.35 to 12.85 ms.
The throughput ranges overlap for both UTF-16BE comparisons. These batches do not establish a sustained throughput advantage. [Raw measurements](object-unicode-html.csv)

| Encoding | Clients | Daemon | Scans/s | p95 ms | Daemon peak MiB | Cgroup peak MiB |
| --- | ---: | --- | ---: | ---: | ---: | ---: |
| UTF-16BE | 1 | Barnacle | 397.82 | 2.45 | 4.48 | 3.65 |
| UTF-16BE | 1 | Stock | 435.73 | 2.23 | 13.78 | 5.76 |
| UTF-16BE | 4 | Barnacle | 586.37 | 6.70 | 4.82 | 3.55 |
| UTF-16BE | 4 | Stock | 568.48 | 6.93 | 14.09 | 6.36 |
| UTF-8 | 1 | Barnacle | 641.44 | 1.49 | 4.44 | 3.62 |
| UTF-8 | 1 | Stock | 272.23 | 3.54 | 13.48 | 5.58 |
| UTF-8 | 4 | Barnacle | 459.18 | 8.55 | 5.69 | 4.48 |
| UTF-8 | 4 | Stock | 440.98 | 8.92 | 14.19 | 7.16 |

## Workload

Both inputs contained the same 2,500 multilingual paragraphs. The UTF-16BE document included a byte order mark and occupied 200,054 bytes.
The UTF-8 control occupied 132,526 bytes. Each database contained one exact hash of stock's normalized markup.
The driver checked the expected signature on all 60 INSTREAM replies. Stock clamd was Debian arm64 1.4.3+dfsg-1.
The Barnacle release ELF had SHA-256 `a6dae08e347ae90aa601d3bd0118cac2e88cafa0cc5cc5591ada708e13c7b9a7`.

Each batch used a fresh daemon and cgroup on one pinned ARM64 CPU, with 2 GiB of memory and no swap.
The driver disabled the scan cache and sent one request per client after startup.
With one or four requests, the reported p95 is the slowest request in that batch.
Daemon peak comes from Linux VmHWM. Cgroup peak counts memory charged to the container, including the driver and file-backed pages.
Shared pages can contribute to daemon RSS while being charged to a different cgroup.

## Reproduction

Build the Linux binaries and create both documents and signature databases.

```sh
cargo build --release --locked --bin barnacle --example archive_workspace
scratch=$(mktemp -d)
chmod 755 "$scratch"
mkdir -p "$scratch/utf-8/db" "$scratch/utf-16be/db"
row="<p>Résumé Αθήνα 東京. Café sur l'île. </p>"
awk -v row="$row" 'BEGIN { printf "<html><body>"; for (i=0;i<2500;i++) printf "%s",row; printf "</body></html>" }' > "$scratch/utf-8/page.html"
{ printf '\376\377'; iconv -f UTF-8 -t UTF-16BE "$scratch/utf-8/page.html"; } > "$scratch/utf-16be/page.html"
printf '%s\n' '63255a85a194df801a7b615507e7a094:117521:Workspace.Reference' > "$scratch/utf-16be/db/reference.hdb"
printf '%s\n' 'ae7a1bf6658c5a7fb2817622285ad539:132526:Workspace.Reference' > "$scratch/utf-8/db/reference.hdb"
```

Run each batch on an idle CPU. The daemon order alternates across rounds.

```sh
probe() {
  docker run --rm --network none --user nobody --cpuset-cpus 0 --cpus 1 --memory 2g --memory-swap 2g \
    -v "$PWD/target/release/examples/archive_workspace:/probe:ro" \
    -v "$PWD/target/release/barnacle:/barnacle:ro" -v "$scratch:/fixtures:ro" \
    barnacle-issue6-oracle:local /probe run "/fixtures/$1/page.html" "$2" "$3"
}
for round in 1 2 3; do
  for encoding in utf-16be utf-8; do
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
