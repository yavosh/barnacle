# Body signatures

Barnacle compiles the extended body signatures in the pinned ClamAV feed.
Stock clamd remains authoritative for complete upload verdicts. [Daemon behavior](daemon.md#scan-results)

## Reference inventory

The reference uses Debian ClamAV `1.4.3+dfsg-1`, functionality level 213, and default detection settings with PUA disabled.
The archive versions are main 63, daily 28187, and bytecode 339. [Archive digests and verification](whole-file-hashes.md#reproduce-the-pinned-generation)

| Source | Records | Outside functionality level | Ignored | Active |
| --- | ---: | ---: | ---: | ---: |
| main.ndb | 101,587 | 161 | 6 | 101,420 |
| daily.ndb | 324 | 0 | 0 | 324 |

Both Barnacle and the pinned stock scanner loaded **101,744 active records** from these sources.
The table counts each feature once per active record. One record can use several features.

| Pattern feature | main.ndb | daily.ndb |
| --- | ---: | ---: |
| Literal pattern | 90,457 | 174 |
| Masked bytes or nibbles | 3,242 | 45 |
| Alternatives | 800 | 7 |
| Brace gaps | 5,294 | 72 |
| Unbounded star gaps | 4,673 | 63 |
| Bracket ranges | 263 | 0 |
| Floating offsets | 517 | 6 |

Active rules use unrestricted, absolute, end-relative, entry-point, and section offsets.
The targets include generic bytes, PE, OLE2, HTML, mail, graphics, ELF, normalized text, Mach-O, PDF, Flash, and Java.
Run the inventory on the extracted database directory for exact counts by target and offset, and each source's SHA-256.
It reads the daily ignore lists before compiling the daily and main rules.

```sh
cargo run --release --locked --example body_inventory -- "$extracted_db"
```

The daemon benchmark uses the complete body database and a harmless local marker.
It reports cgroup memory, startup peaks, throughput, and p95 on one vCPU. [Measured results and workload](body-benchmark.md)

## Match one object

`BodyIndex::scan` emits a rule ID and a half-open byte range for each occurrence.
Callers can count occurrences by rule ID. Offsets are relative to the supplied object.
`BodyIndex::first_match` returns the winning name for that object.
Local names use the stock `.UNOFFICIAL` suffix. Unsupported active syntax reports the source file and line.

`ObjectContext::raw` identifies the outer object. Use `ObjectContext::typed` when a parser supplies a normalized or extracted object.
Every object needs its own context and offset calculations. [Object extraction work](https://github.com/yavosh/barnacle/issues/9)

## Compare with stock

Run the Rust tests inside the pinned Debian environment. The daemon comparisons use harmless local signatures and private Unix sockets.
They check signature names, offset boundaries, competing matches, read boundaries, and occurrence counts.
The archive test loads the verified generation and checks its active rule count. [Reference environment](compatibility/replay.md)

```sh
BARNACLE_CVD_DIR="$snapshot_dir" cargo test --release --locked --all-targets -- --include-ignored
```

The matcher uses the ClamAV body pattern and extended offset formats.
[Body signature format](https://docs.clamav.net/manual/Signatures/BodySignatureFormat.html) · [Extended signatures](https://docs.clamav.net/manual/Signatures/ExtendedSignatures.html)

## Local logical signatures

Local `.ldb` rules can combine extended patterns with Boolean expressions, occurrence counts, and distinct subsignature counts.
The loader applies functionality levels and ignore rules. Supported target attributes include `Target`, `FileSize`, and `Container`.
`Container:CL_TYPE_ANY` selects root objects. A named container selects children with that parent type.

The matcher supports ASCII case folding (`i`), wide bytes (`w`), ASCII with wide bytes (`a`), and fullword boundaries (`f`).
Case folding applies to literal letters. Wide patterns still measure offsets and brace gaps in bytes.
ASCII and wide variants share a logical subsignature ID. Two single-part variants at the same start count once.
Fullword checks run inside the pattern matcher. For multipart patterns, they check the outer edges.

On the tested raw objects, stock tries extended body rules, whole-file hashes, and then logical rules.
A target-specific logical rule wins over a generic rule. Within the selected target, the first matching record wins.
Logical rules receive each new object's context, including extracted children and normalized views.
In an unmapped script view, absolute offsets use normalized bytes and `FileSize` uses the source length.
Mapped script views use the normalized length and inherit the source's container.

The Rust tests compare exact named results on local rules with pinned Debian clamd 1.4.3+dfsg-1.
They cover overlap, duplicate subsignatures, count limits, compressed ZIP contents, normalized text, and competing matches.

```sh
cargo test --locked --test logical_signatures -- --include-ignored
```

Stock loads 312,303 logical records from `main.ldb` and `daily.ldb` with PUA disabled and the pinned ignore lists.
Of these, 1,186 use PCRE subsignatures, and 3,724 use group count expressions.
Unsupported active subsignatures and target attributes fail generation loading with a source location. These include PCRE and fuzzy hashes.
Official database scans still report incomplete coverage. [Issue #3](https://github.com/yavosh/barnacle/issues/3)
