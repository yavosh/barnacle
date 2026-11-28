# Bytecode requirements for the pinned ClamAV feed

The reference is Debian 13 ClamAV 1.4.3+dfsg-1 at functionality level 213.
The [effective configuration](compatibility/clamd-options.txt) enables bytecode in Auto mode.
It uses `TrustSigned`, disables unsigned bytecode, and sets a 10,000 ms timeout.

## Signed archive

`sigtool --info` verified `bytecode.cvd` version 339.
The bytecode inventory reads only the [pinned archive](../src/bytecode.rs) from the recorded database generation.
It checks the SHA-256 before opening any tar member.

```sh
cargo run --locked --release --example bytecode_inventory -- /path/to/bytecode.cvd
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --lib matches_stock_archive_inventory -- --ignored
```

Stock `clambc --info` and `clambc --printbcir` provided independent hook and instruction counts.
Run those commands on each extracted CBC file with the pinned package.
Barnacle's inventory matches the stock instruction count and the exact opcode and host API sets.
Functionality-window eligibility here refers to the pinned engine level.

| Hook | Wire ID | Members | Engine-eligible |
| --- | ---: | ---: | ---: |
| Logical | 256 | 74 | 72 |
| PE unpacker | 257 | 6 | 6 |
| PDF | 258 | 2 | 2 |
| PE all | 259 | 2 | 2 |
| ELF unpacker | 261 | 1 | 0 |
| **Total** | | **85** | **82** |

All 10 format-6 members are eligible. Of 75 format-7 members, 72 are eligible.
Two logical modules expire at level 82. One ELF unpacker expires at level 119.
The eligible modules contain 115 functions and 15,034 instructions across 44 opcodes.
They declare 28 distinct host APIs. Output uses the one-based wire IDs.
Stock disassembly uses zero-based host API indices.

The opcode set includes arithmetic, comparisons, control flow, calls, and pointer and memory operations.
The host APIs include file reads, seeks, PE and PDF queries, extraction, and detection name reporting.
The inventory reports each opcode ID and API name with its ID.
It also checks the Rust compiler against every eligible module.
The compiler accepts 72 eligible modules, including 69 logical modules, both PDF hooks, and one `PE_ALL` hook.
The archive test loads those modules into one generation and verifies each hook count.
The inventory groups the remaining 10 eligible modules by the first compiler rejection.
Six use the PE unpacker hook. Three declare an unsupported host API. One needs pointer-to-integer conversion.
Signed-feed activation and verdict qualification remain open in [issue #4](https://github.com/yavosh/barnacle/issues/4).
[ClamAV bytecode format](https://docs.clamav.net/manual/Signatures/BytecodeSignatures.html) · [Stock hook definitions](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/bytecode_api.h#L63-L85)

## Harmless stock control

The upstream test CBC matches a plain-text marker at byte zero and calls `setvirusname`.
A one-byte prefix leaves the stream clean in each profile.
All profiles use a private stock clamd instance.

| Stock configuration | Marker verdict |
| --- | --- |
| Default, or explicit `BytecodeUnsigned no` | `stream: OK` |
| `Bytecode yes` and `BytecodeUnsigned yes`, with Auto or ForceInterpreter | `stream: BC.Clamav-Unit-Test-Signature FOUND` |
| `Bytecode no` and `BytecodeUnsigned yes` | `stream: OK` |

The fixture SHA-256 is `36d282680ef43be4eb5fc1aec95b6d262460c3a5ffb2563a280a35dbe64bc8b3`.
[Pinned upstream fixture](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/unit_tests/input/bytecode_sigs/Clamav-Unit-Test-Signature.cbc)

## Supported execution

The Rust interpreter executes logical bytecode with typed integer locals, arithmetic, comparisons, casts, branches, and loops.
Direct helper calls accept integers and byte pointers. Helpers can return integers.
Each call gets a fresh frame. A helper can write through a pointer to a live caller buffer.
Calls share the scan object's cursor and execution deadline. The interpreter bounds stack depth and storage.
The frame supports pointer arithmetic, loads, stores, byte swaps, and bounded memory operations.
Each invocation can allocate up to 1 MiB of heap payload across at most 4,096 allocations.
Separate bounded storage tracks which heap bytes are initialized. Memory copies use at most 4 KiB of scratch space.
The decoder accepts structured API declarations. General aggregate locals and struct field addressing remain unsupported.
Host calls can seek, read, search, report the engine level, and set a detection name.
Host calls can read decimal and hexadecimal integers and emit diagnostics when clamd debug logging is enabled.
Bytecode can read the object size, subsignature counts, and first offsets.
PE bytecode can read the entry offset and section count, fetch section records, and translate virtual addresses.
Programs that use first offsets currently require indexed pattern subsignatures.
An ASCII-target bytecode rule forces a normalized file map for script scanning.
An unmapped script scan matches normalized text. Its bytecode reads the owning file map.
[ClamAV 1.4.3 script scan](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/scanners.c#L2092-L2190)

The interpreter checks the bytecode timeout every 5,000 instructions, matching the pinned stock interpreter.
`BytecodeTimeout 0` uses the stock engine's 60-second fallback.
Scan cancellation applies at each instruction and during host searches.
Local CBC files require `BytecodeUnsigned yes` and `Bytecode yes`.
An eligible module with unsupported instructions, APIs, or metadata prevents activation.

The comparison covers exact names, offsets, match counts, scalar widths, search boundaries, and a 1 ms timeout.
Frame tests compare short reads, EOF, cursor position, nested archive members, and both script map modes.
Helper tests compare nested calls and shared cursor behavior. Host-call tests cover numeric reads and debug settings.
The heap and PE tests compare helper writes, short reads, in-memory search, and section lookup against stock.
The icon tests compare an icon-qualified logical trigger and the `matchicon` host call.
The trigger checks the PE icon before bytecode runs.
In pinned stock, the host call uses an empty resource table and returns zero for valid arguments.
Logical bytecode can write a child to a spool. The scan checks that child before reporting the bytecode's own name.
The tests cover output that survives a rejected write, VM abort, or script normalization.
Stock charges the output once at extraction and again when admitting the child, so both charges affect scan limits.
The tests also cover competing generic logical signatures.
When both rules match, stock evaluates the one loaded first from the database directory.
Barnacle returns its existing incomplete-scan error for misses while detection coverage remains partial.
[Comparison tests](../tests/bytecode_reference.rs)

```sh
BARNACLE_CBC_FIXTURE=/path/to/pinned/fixture.cbc cargo test --locked --test bytecode_reference -- --include-ignored
```

## Focused interpreter timing

The ARM64 Debian comparison used one CPU, 2 GiB RAM, and `ForceInterpreter`.
Each daemon warmed up with 64 requests. Five trials sent 1,000 sequential `INSTREAM` requests each.
The table reports the median trial throughput and p95 latency.

| Fixture | Build | Requests/s | p95 |
| --- | --- | ---: | ---: |
| 512-iteration scalar loop | Stock | 20,123 | 68 µs |
| 512-iteration scalar loop | Previous Barnacle | 18,531 | 65 µs |
| 512-iteration scalar loop | Current Barnacle | 18,004 | 68 µs |
| Read, seek, and byte swap | Stock | 18,259 | 69 µs |
| Read, seek, and byte swap | Current Barnacle | 80,664 | 16 µs |

The scalar comparison motivated a direct register path for programs without addressable locals.
Full-feed throughput, latency, and memory qualification remain open.

## Scan stages and built-in heuristics

For PE32, stock runs `PE_ALL` after overlay scanning and before import hashing and native heuristics.
It runs `PE_UNPACKER` after native unpackers. Both hooks receive the original PE and parsed metadata.
Stock runs PDF hooks before discovery, after discovery, after recursive child scans, and at PDF completion.
The completion phase requires remaining parser flags. The post-extraction phase sees the extracted bytes.
[Pinned PE scanner](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/pe.c) · [Pinned PDF scanner](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/pdf.c)

Barnacle runs supported `PE_ALL` programs after overlay scanning. A matching logical prefilter enables the hook for that PE object.
`PE_ALL` programs can read the entry RVA, PE header offset, optional header size, and optional header magic.
The comparison covers earlier raw and overlay findings, sibling archive members, PE32+, and the `ScanPE` and unsigned bytecode options.
On PE32+, the scan skips the overlay and hook phase. A `PE_ALL` break skips later PE checks.
One signed `PE_ALL` module loads in the archive test. The other requires unsupported host APIs. `PE_UNPACKER` is unsupported.

Both signed PDF hooks query the current phase and configuration functionality level, which is 213.
One queries document flags. The other uses discovery order, object offsets, and object spans.
Post-extraction calls retain the parent object table while reading extracted bytes.
[Pinned bytecode host APIs](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/bytecode_api.c)

Local unconditional PDF hooks run at all four phases under the daemon's bytecode policy.
The stock comparison checks prefixed offsets, object sizes, child precedence, and `BREAK`.
Conditional PDF hooks and unverified parser metadata remain unsupported.
Unsupported metadata produces an explicit error when a hook queries it.
An uncertain END phase leaves the scan incomplete. [PDF hook comparisons](../tests/bytecode_reference.rs)

The test invokes both verified modules directly at the PRE phase on an ordinary PDF.
The daemon smoke comparison uses the signed archive in stock clamd and the extracted PDF modules in both daemons.
All profiles report the escaped common-name alert and preserve their expected replies on ordinary documents and plain text.
The Barnacle profile loads local CBCs under `BytecodeUnsigned yes`. Signed-feed activation remains open.

```sh
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --test bytecode_reference stock_and_barnacle_run_verified_pdf_modules -- --ignored
```

The reference enables `HeuristicAlerts` and disables `HeuristicScanPrecedence`.
Default precedence lets later detections win over a deferred heuristic finding.
Use the effective daemon options and engine module flags together to determine which detectors run.
[Daemon options](compatibility/clamd-options.txt) · [Engine module flags](compatibility/engine-modules.txt)

| Enabled stock detector | Barnacle verification |
| --- | --- |
| PE Parite heuristic | Stock comparisons cover the exact verdict, option gates, raw signature priority, and `PE_ALL` breaks. The fixture uses inert data in a non-executable section. [Parite tests](../tests/bytecode_reference/parite.rs) |
| PE heuristics for Kriz, Magistr, and Polipos | Detection parity is open. PE signatures and object handling have separate coverage. |
| PDF obfuscated names | Stock comparisons cover physical and packed dictionaries, escaped Flate filters, and competing child signatures. |
| Mydoom log checksum | Stock comparisons cover binary and UTF-16BE inputs, checksums, minimum size, the early word screen, and precedence against a hash signature. [Log tests](../tests/object_mydoom.rs) |
| RIFF | Named finding parity is open. |
| XZ dictionary limit | A final decoder memory refusal reports `Heuristics.XZ.DicSizeLimit` and discards the decoded prefix. The stock test forces a refusal on an ordinary receipt. |
| URL phishing checks | Verified URL rule loading and detection are tracked in [issue #10](https://github.com/yavosh/barnacle/issues/10). |

The pinned profile disables the encrypted-document, partition-intersection, and scan-limit alerts.
Separate opt-in fixtures verify encrypted PDF and partition-intersection precedence against stock.
[PDF alert tests](../tests/object_pdf_security.rs) · [Partition alert tests](../tests/object_partition.rs)

The [XZ stock test](../tests/object_archives.rs) lowers the data limit of a private Debian clamd process after startup.
The receipt's 8 MiB dictionary then triggers the alert even with `HeuristicAlerts no`.
Restoring the limit lets stock scan the child and report its hash signature.
Barnacle's reduced-limit test covers retry, refusal, and both `HeuristicScanPrecedence` settings.
