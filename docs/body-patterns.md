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
The loader applies functionality levels and ignore rules. It supports `Target`, `FileSize`, `Container`, `EntryPoint`, and `NumberOfSections`.
Executable conditions use the parsed PE, ELF, or Mach-O layout. The entry point is a file offset.
`Container:CL_TYPE_ANY` selects root objects. A named container selects children with that parent type.

The matcher supports ASCII case folding (`i`), wide bytes (`w`), ASCII with wide bytes (`a`), and fullword boundaries (`f`).
Case folding applies to literal letters. Wide patterns still measure offsets and brace gaps in bytes.
ASCII and wide variants share a logical subsignature ID. Two single-part variants at the same start count once.
Fullword checks run inside the pattern matcher. For multipart patterns, they check the outer edges.

PCRE subsignatures run after the indexed patterns for the current scan object.
A trigger can use occurrence counts from earlier patterns and PCRE subsignatures.
Exact offsets rebase the regex subject. Shifted offsets bound the reported match start. The `e` flag bounds the subject itself.
Global matching advances after an empty match.

The daemon uses the pinned reference defaults for `PCREMatchLimit` (100,000), `PCRERecMatchLimit` (2,000), and `PCREMaxFileSize` (100 MiB).
Match and depth limits stop the current regex. The size limit skips PCRE on larger objects.
Barnacle caps PCRE backtracking heap use at 8 MiB per scan object and reports exhaustion as an error.
Most regex programs poll for cancellation while matching.
Programs that exceed PCRE2's compiled size limit with polling enabled retry compilation and poll before and after matching.

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

With PUA disabled, stock loads 312,303 logical records from the pinned `main.ldb` and `daily.ldb`.
The inventory applies the pinned functionality level and ignore lists.
It counts 1,459,845 extended patterns, 1,208 PCRE subsignatures, 111 image fuzzy hashes, and one byte comparison.
PCRE appears in 1,186 records. Group counts appear in 3,724 records.
Barnacle compiled all 1,186 PCRE-bearing records in one local index on macOS.
The test preserved offsets, triggers, and sibling patterns and replaced the rule names.

| Target attribute | Records |
| --- | ---: |
| `FileSize` | 1,298 |
| `Container` | 2,234 |
| `NumberOfSections` | 44 |
| `HandlerType` | 11 |
| `Intermediates` | 1 |
| `IconGroup1` | 52 |
| `IconGroup2` | 28 |

The feed includes generic, executable, document, graphics, mail, and normalized text targets.
Patterns use absolute, end-of-file, entry-point, section, and PE version-info offsets.
Unsupported active subsignatures, offsets, and target attributes fail loading with a source location.
A batch compile accepted 312,081 of 312,303 eligible records. The table counts the first rejection per record.

| First rejection | Records |
| --- | ---: |
| Image fuzzy hash | 111 |
| `IconGroup1` | 52 |
| `IconGroup2` | 28 |
| `HandlerType` | 11 |
| PE version-information offset | 10 |
| Single-branch alternative | 6 |
| Empty alternative branch | 2 |
| Byte comparison | 1 |
| `Intermediates` | 1 |

Official database scans still report incomplete coverage. [Issue #3](https://github.com/yavosh/barnacle/issues/3)

### Local benchmark

One Linux ARM64 CPU, 2 GiB, four INSTREAM clients, and the cache disabled.
Each of three runs issued 16,384 scans against a 64 KiB fixture and 1,025 local rules.
All replies named the same expected signature. The table shows medians from `59d09eb` and Debian clamd `1.4.3+dfsg-1`.

| Rules | Scanner | Scans/s | p95 | Peak cgroup memory |
| --- | --- | ---: | ---: | ---: |
| Exact body | Barnacle | 48,567 | 0.136 ms | 4.52 MiB |
| Exact body | Stock clamd | 5,486 | 1.464 ms | 6.68 MiB |
| Case-insensitive logical | Barnacle | 46,307 | 0.145 ms | 3.95 MiB |
| Case-insensitive logical | Stock clamd | 3,387 | 2.471 ms | 11.63 MiB |
| Triggered PCRE | Barnacle | 45,580 | 0.150 ms | 4.59 MiB |
| Triggered PCRE | Stock clamd | 2,984 | 2.867 ms | 11.75 MiB |

The exact-body build before modifiers (`89e7140`) reached 48,631 scans/s at 0.137 ms p95.
Full-feed memory and throughput remain unverified for logical rules. [Raw results](benchmarks/logical-local.csv)

### Supported pinned subset

Both daemons loaded the same 312,081 eligible logical records and one harmless local PCRE rule.
The workload omitted the 222 records listed above. Both daemons used logical signatures and the pinned ignore lists.
Each one-CPU, 2 GiB trial used four INSTREAM clients and issued 1,024 scans of a 64 KiB binary.
A padded fixture used repeated punctuation. A varied fixture replaced that padding with changing bytes.
Every reply named the local PCRE rule. The table shows medians of three trials.

| Fixture | Scanner | Scans/s | p95 | Peak cgroup memory |
| --- | --- | ---: | ---: | ---: |
| Padded | Barnacle before seed change (`10ef879`) | 854 | 18.003 ms | 497.21 MiB |
| Padded | Barnacle | 3,698 | 1.909 ms | 496.06 MiB |
| Padded | Stock clamd | 1,090 | 8.023 ms | 722.39 MiB |
| Varied | Barnacle before seed change (`10ef879`) | 1,897 | 3.698 ms | 497.42 MiB |
| Varied | Barnacle | 1,804 | 4.269 ms | 496.40 MiB |
| Varied | Stock clamd | 1,389 | 6.294 ms | 722.46 MiB |

The seed selector now prefers a byte change within the required literal.
This removed repeated candidate checks on the padded fixture. [Raw results](benchmarks/logical-supported-feed.csv)
