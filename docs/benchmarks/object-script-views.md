# Normalized text storage and scan limits

Barnacle borrows the input when its prefix already contains the full normalized view.
For mapped views, it checks normalized size before file count and recursion. It creates scratch storage only for admitted changes.

On four clients, a near-end body match on the 1 MiB lowercase inventory improved from 840 to 949 scans/s.
Peak cgroup memory fell from 8.41 to 6.27 MiB. The daemon wrote 1,048,593 fewer bytes per scan.
The mixed-case hash workload still required scratch. It reached 201 scans/s, compared with 203 previously.

| Four-client workload | Earlier scans/s | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Lowercase, body hit | 840 | 949 | 223 | 8.17 | 25.43 | 6.27 | 14.34 |
| Mixed case, normalized hash | 203 | 201 | 172 | 30.53 | 32.80 | 11.00 | 22.00 |
| Mixed case, file count exceeded | 273 | 278 | 290 | 19.96 | 27.89 | 6.80 | 18.20 |
| Mixed case, byte limit exceeded | 275 | 285 | 286 | 19.51 | 26.71 | 6.71 | 17.93 |
| Lowercase, file count exceeded | 865 | 1,156 | 307 | 6.65 | 26.81 | 6.39 | 17.71 |
| Lowercase, byte limit exceeded | 865 | 975 | 300 | 7.84 | 28.99 | 6.51 | 17.88 |

Each cell is the median of three rotated runs on a single pinned ARM64 CPU with 2 GiB RAM and no swap.
Each fresh daemon served one checked initial request, followed by 24 checked requests per client over its Unix socket with `INSTREAM`.
The driver recorded throughput and p95 for that second batch. It measured written bytes using the daemon's Linux `wchar` counter.
Peak cgroup memory includes the driver and file-backed pages. The host file cache stayed warm.
The data include one-client results. The engines are Barnacle `9544ac5` (old), `d2a0874` (new), and Debian clamd `1.4.3+dfsg-1` (stock). [Raw measurements](object-script-views.csv)

## Fixtures

Generate the two input files with Rust.

```rust
fn main() -> std::io::Result<()> {
    let marker = b"order number verified";
    let mut identity = b"blue paper inventory ".repeat(1_048_576 / 21);
    identity.extend(marker);
    let mut mixed = b"Blue paPer InVentOry ".repeat(1_048_576 / 21);
    mixed.extend(b"\r\n  Warehouse   \t");
    mixed.extend(marker);
    std::fs::write("identity", identity)?;
    std::fs::write("mixed", mixed)
}
```

The lowercase input is 1,048,593 bytes. Its target-7 body rule matches the marker at any offset.
For the limit workloads, anchor the same rule at `EOF-21` to request a mapped view.
The mixed input is 1,048,610 bytes. Its normalized view is 1,048,603 bytes.
Load these two local rules for the mixed input.

```text
Miss:7:EOF-6:7a717a717a71
a2efb212d722d0826770ebb37aa9c5b7:1048603:Text.Mapped
```

Use an NDB file for the offset rule and an HDB file for the hash.
For file-count workloads, set `AlertExceedsMax yes`, `MaxFiles 1`, `MaxRecursion 8`, and `MaxScanSize` to the sum of both lengths.
For byte-limit workloads, use `MaxFiles 0` and reduce that sum by one byte. Disable the daemon cache for every workload.
