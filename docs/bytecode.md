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
The compiler accepts 65 of the 72 logical modules in the signed archive.
The archive test loads their triggers together through the logical index.
The inventory groups the remaining 17 eligible modules by the first compiler rejection.
Ten require nonlogical hooks, five declare unsupported types, and two declare unsupported APIs.
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
Direct helper calls accept integer arguments and return values. Each call gets a fresh frame.
Calls share the scan object's cursor and execution deadline. The interpreter bounds stack depth and storage.
The frame supports pointer arithmetic, loads, stores, byte swaps, and bounded memory operations.
Host calls can seek, read, search, report the engine level, and set a detection name.
Host calls can read decimal and hexadecimal integers and emit diagnostics when clamd debug logging is enabled.
Bytecode can read the object size, subsignature counts, and first offsets.
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
It also covers competing generic logical signatures.
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
