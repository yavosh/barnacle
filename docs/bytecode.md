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
The compiler accepts all 82 eligible modules, including 72 logical modules, both PDF hooks, both `PE_ALL` hooks, and six `PE_UNPACKER` hooks.
The archive test loads those modules into one generation and verifies each hook count.
It also checks harmless PDF traversal with that generation using a test-only override of the official-feed gate.
The daemon loads CBC members from the exact verified bytecode archive when `Bytecode yes` is enabled.
It compiles the authenticated member bytes directly from memory.
Local CBC files still require `BytecodeUnsigned yes`.
`Bytecode no` skips CBC activation but still authenticates the pinned archive.
The existing CVD scan policy returns an incomplete verdict before executing any matcher, including these modules.
Full-feed verdict qualification depends on auxiliary coverage and match precedence. [Auxiliary coverage issue #10](https://github.com/yavosh/barnacle/issues/10)
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

### Signed EICAR logical rule

Stock clamd loads only verified `bytecode.cvd` v339 with `BytecodeUnsigned no` and `BytecodeMode ForceInterpreter`.
Barnacle loads its authenticated member `6327695.cbc` into the logical index as an official rule.
The comparison runs its logical prefilter and bytecode on the standard EICAR test string. [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)

Both report `Eicar-Signature` for the canonical 68 bytes and space padding to 128 bytes.
They also match a suffix containing space, tab, LF, CR, and Control-Z.
Changing the first byte, removing the last byte, appending a letter, and padding to 129 bytes all miss.
Stock reports clean on every input with `Bytecode no`.
The production Barnacle daemon still returns incomplete before matching a CVD generation. [Paired regression](../tests/bytecode_reference/eicar.rs)

```sh
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --test bytecode_reference verified_eicar_logical_rule -- --ignored
```

## Supported execution

The Rust interpreter executes logical bytecode with typed integer locals, arithmetic, comparisons, casts, branches, and loops.
Direct helper calls accept integers and byte pointers. Helpers can return integers.
Each call gets a fresh frame. A helper can write through a pointer to a live caller buffer.
Calls share the scan object's cursor and execution deadline. The interpreter bounds stack depth and storage.
The frame supports pointer arithmetic, loads, stores, byte swaps, and bounded memory operations.
Heap and module byte-array pointer conversions use the pinned interpreter's object IDs and offsets.
Typed copies can move module pointers through aligned pointer locals. Module data stays read-only.
Frame address conversion remains unsupported.
Each invocation can allocate up to 1 MiB of heap payload across at most 4,096 allocations.
Separate bounded storage tracks which heap bytes are initialized. Memory copies use at most 4 KiB of scratch space.
The decoder accepts structured API declarations. General aggregate locals and struct field addressing remain unsupported.
Host calls can seek, read, search, report the engine level, and set a detection name.
Host calls can read decimal and hexadecimal integers and emit diagnostics when clamd debug logging is enabled.
Bytecode can read the object size, subsignature counts, and first offsets.
PE bytecode can read the entry offset and section count, fetch section records, and translate virtual addresses.
The `get_environment` host call supplies the architecture byte used by the verified archive.
The paired controls verify the architecture value on Debian arm64 and the destination's copy boundaries.
Reads from copied fields that Barnacle does not model return an explicit unsupported error.
The `disasm_x86` host call decodes supported legacy 32-bit instructions at the current cursor.
The return value is the next absolute offset. The cursor stays in place.
Comparison with pinned stock covered 6,384 instruction records, including operand metadata and result length.
One verified module checks for `PUSHAD`. Paired daemon tests check the complete records and next offsets for `PUSHAD` and `PUSHA`.
Another verified module checks for `BSWAP`. Tests cover all eight registers and confirm that the operand-size prefix preserves the 32-bit register.
One verified module checks for `PUSH` with a 32-bit memory operand. Tests cover the `FF /6` memory and register forms.
Paired daemon tests cover invalid instructions, EOF, and which result bytes change on failure.
Unmodeled encodings return an explicit unsupported error. These include x87, indirect calls and jumps, and several two-byte groups.
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
PE hooks can read the entry RVA, PE header offset, optional header size and magic, and the PE32 `BaseOfData` field.
They can also read the PE resource directory RVA and size. All three stock directory tables return zero for an absent entry.
The comparison covers earlier raw and overlay findings, sibling archive members, PE32+, and the `ScanPE` and unsigned bytecode options.
On PE32+, the scan skips the overlay and hook phase. A `PE_ALL` break skips later PE checks.
Barnacle runs supported `PE_UNPACKER` hooks when native UPX does not unpack the PE.
An unpacker can run unconditionally or use a logical prefilter.
An unchanged harmless ledger PE32 selects one signed unpacker from the verified archive on Debian arm64.
Stock completes 3,291 interpreter instructions and returns cleanly without output. Neither signed `PE_ALL` module runs.
The Rust qualification selects the program through the actual logical index.
It requires exactly 3,290 VM checks, `Continue`, and no output.
Stock counts one synthetic entry call. Rust enters the function directly.
An inactive PE32 control selects no PE hooks.
The packed ledger selects no signed hook at its root. Stock runs the unpacker on the reconstructed child.
Barnacle selects one unpacker on the 69,632-byte child at depth one. Enabling it adds 3,290 checks.
Both Barnacle traversals visit only the packed file and its child and return a matcher miss.
The production official-feed gate stays in effect. Signed detection and extraction branches still need coverage.
Native macOS arm64 leaves the architecture field unmodeled. This runtime qualification is limited to Linux arm64.
[Signed unpacker controls](../tests/bytecode_reference/pe_unpacker.rs)

```sh
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --lib signed_pe_unpacker_receipt -- --ignored
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --lib signed_pe_unpacker_recursive_receipt -- --ignored
BARNACLE_CVD_DIR=/path/to/snapshot cargo test --locked --test bytecode_reference stock_signed_receipt_selection -- --ignored
```

The hook scans its written output before reporting its own name. A matching child takes precedence.
The paired tests cover hook breaks, clean native unpacking, and exact file and scan-size limits.
The `extract_new` host call scans the current output before the VM continues.
It returns 0 for an empty or clean output and 1 for an immediate finding.
It reports recursion, size, and file-count limits using the pinned engine's numeric codes.
The paired tests cover finding preservation, repeated extraction, and deferred heuristic alerts.
[PE unpacker tests](../tests/bytecode_reference/pe_unpacker.rs)

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
The daemon smoke comparison uses all three signed archives in both daemons, plus separate profiles with extracted PDF modules.
Local profiles report the escaped common-name alert and preserve their expected replies on ordinary documents and plain text.
Full-archive qualification remains open: Barnacle's CVD policy prevents matching and suppresses this stock heuristic verdict.
The daemon test asserts this existing policy with bytecode both enabled and disabled.
Signed profiles use `BytecodeUnsigned no`; local profiles use `BytecodeUnsigned yes`.

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
| PE Magistr heuristics | Paired tests cover A and B, truncated sections, and precedence against Parite. Rust metadata tests cover both `.dam` names. [Magistr tests](../tests/bytecode_reference/magistr.rs) |
| PE Polipos heuristic | Stock comparisons cover all three target prefixes, section selection, target limits, and detection order. The PE entry point returns immediately. [Polipos tests](../tests/bytecode_reference/polipos.rs) |
| PE Kriz heuristic | Stock comparisons cover DLLs, entry-point bounds, scan options, and precedence with Parite and Magistr. [Kriz tests](../tests/bytecode_reference/kriz.rs) |
| PDF obfuscated names | Stock comparisons cover physical and packed dictionaries, escaped Flate filters, and competing child signatures. |
| Mydoom log checksum | Stock comparisons cover binary and UTF-16BE inputs, checksums, minimum size, the early word screen, and precedence against a hash signature. [Log tests](../tests/object_mydoom.rs) |
| RIFF animated cursors | Payload-free header controls cover both byte orders, groups, padding, options, and body/hash priority. [RIFF tests](../tests/object_riff.rs) |
| XZ dictionary limit | A final decoder memory refusal reports `Heuristics.XZ.DicSizeLimit` and discards the decoded prefix. The stock test forces a refusal on an ordinary receipt. |
| URL phishing checks | Verified URL rule loading and detection are tracked in [issue #10](https://github.com/yavosh/barnacle/issues/10). |

When Parite and Magistr both match, pinned stock can report either name with default settings.
Barnacle consistently reports Magistr in that case. Immediate heuristic precedence reports Parite in both scanners.
[Pinned alert selection](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav_rust/src/evidence.rs#L116-L119)

The pinned profile disables the encrypted-document, partition-intersection, and scan-limit alerts.
Separate opt-in fixtures verify encrypted PDF and partition-intersection precedence against stock.
[PDF alert tests](../tests/object_pdf_security.rs) · [Partition alert tests](../tests/object_partition.rs)

The [XZ stock test](../tests/object_archives.rs) lowers the data limit of a private Debian clamd process after startup.
The receipt's 8 MiB dictionary then triggers the alert even with `HeuristicAlerts no`.
Restoring the limit lets stock scan the child and report its hash signature.
Barnacle's reduced-limit test covers retry, refusal, and both `HeuristicScanPrecedence` settings.
