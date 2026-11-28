# Object handling and scan limits

The reference uses Debian 13 arm64 and ClamAV `1.4.3+dfsg-1`. The scan order depends on the object type.
Stock clamd supplies complete upload verdicts during development. [Pinned configuration and engine inventory](compatibility-matrix.md)

## Reference handlers

The following groups reflect the pinned engine configuration. An enabled handler still requires a fixture comparison.
The raw engine inventory lists individual submodules, including disabled entries. [Engine modules](compatibility/engine-modules.txt)

| Stage | Formats or features in the reference | Comparison coverage |
| --- | --- | --- |
| Archives and compressed streams | ZIP, gzip, bzip2, XZ, TAR, CPIO, 7z, RAR, ARJ, CAB, SZDD, CHM, BinHex, EGG, LHA, ALZ and SIS | Rust fixtures cover all listed families, including stored and compressed legacy SIS members. The RAR comparison checks the reference installation without UnRAR. [Archive comparisons](../tests/object_archives.rs) |
| Disk images and partitions | ISO 9660, UDF, DMG, XAR, HFS+, MBR, GPT and APM | Tests cover optical images, XAR, DMG, three partition maps, and files inside HFS+ and HFSX. [ISO comparisons](../tests/object_iso.rs) · [DMG comparisons](../tests/object_dmg.rs) · [Partition comparisons](../tests/object_partition.rs) |
| Installers and embedded files | NSIS, AutoIt, InstallShield and embedded file recognition | Tests exercise NSIS, AutoIt EA05 and EA06, InstallShield, and embedded PE resources. [AutoIt comparisons](../tests/object_autoit.rs) · [Installer comparisons](../tests/object_installers.rs) · [Embedded comparisons](../tests/object_embedded.rs) |
| Documents | OLE2, OOXML, Word/Excel XML, HWP, OneNote, PDF, RTF and SWF | Tests cover ordinary PDF, Office, RTF and Flash documents, including competing child detections and scan limits. [PDF comparisons](../tests/object_pdf.rs) · [OLE comparisons](../tests/object_ole.rs) |
| Text and mail | HTML, UTF-16 HTML, script normalization, JavaScript, script encoding, mbox/MIME, TNEF and uuencoding | Rust fixtures exercise ordinary scripts, HTML, MIME, TNEF, uuencoded files, and data URLs. [Text comparisons](../tests/object_text.rs) |
| Executables and media | PE, ELF, Mach-O, universal Mach-O, Java, RIFF, GIF, PNG, JPEG and TIFF | Tests cover UPX NRV PE32, Mach-O slices, ELF sections, Java classes, WAVE audio, and five image formats. Other unpackers and image heuristics remain open. [UPX comparisons](../tests/object_upx.rs) · [Executable comparisons](../tests/object_macho.rs) · [Media comparisons](../tests/object_images.rs) |

The engine also enables password support for archives and format-specific detection heuristics.
The reference image lacks an installed UnRAR helper even though its engine configuration lists RAR.
The reference applies format settings and limits individually. [Effective clamd options](compatibility/clamd-options.txt)

`ScanXMLDOCS no` leaves ZIP member scanning enabled in packaged Word, Excel, PowerPoint, and HWP documents.
Both daemons detect the same member hash with this setting. [Office container comparisons](../tests/object_parents.rs)

In the authored Word and PowerPoint packages, the document XML signature wins over the picture and package hashes.
In the spreadsheet, stock classifies the stylesheet as HTML at the `<tableStyles` element.
Its 879-byte normalized markup wins over the worksheet, picture, and package hashes.
Disabling HTML scanning makes the worksheet win. Disabling archive scanning makes each package hash win.
[Office package comparisons](../tests/object_office_packages.rs) · [Fixture provenance](../tests/fixtures/ooxml/README.md) · [Throughput and memory](benchmarks/object-office-packages.md)

HWPX assets under `BinData/` can trigger a central-directory lookup for `Contents/content.hpf`.
Stock accepts a prefix in the first three local headers and requires the complete filename in the directory.
Both daemons preserve the resulting HWPX or ZIP parent type. [HWPX comparisons](../tests/object_parents.rs)

### Compiled AutoIt archives

The EA06 inventory guide emits a 168-byte script, 50-byte notice, and 151,552-byte ledger in that order.
Stock scans these objects before the raw A3X hash. The outer hash wins first when the same container appears inside a PE.
Each extracted object has an unnamed layer under `CL_TYPE_AUTOIT`.
`ScanArchive no` disables extraction. `ScanPE no` preserves extraction from an embedded container.

The standalone script requires 311 scan bytes for its token stream. Its rendered bytes consume 168 bytes of the cumulative budget.
A 50-byte remainder can exclude the script and still admit the notice.
The reference checks the whole embedded region against the remaining budget before visiting its resources.
Barnacle validates resources blocked by the recursion limit without retaining their decoded bytes.
Unsupported EA06 script tokens return incomplete coverage.
The exact child bytes, competing signatures, raw hash, parent context, and scan limits have paired Rust checks.
[Authored fixture](../tests/fixtures/autoit/README.md) · [Rust comparisons](../tests/object_autoit.rs)

Four clients scanned the same guide with one MD5 rule and caching disabled. The median covers three fresh containers per daemon and rule.
Each container used one pinned ARM64 CPU and 2 GiB of memory with swap disabled.
Each batch sent one initial request and 128 warm requests per client. All 6,156 replies matched the expected signature.
Cgroup peak memory includes the driver and charged file-backed pages. Stock was Debian clamd `1.4.3+dfsg-1`.

| Signature | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Notice | 20,459 | 9,187 | 0.32 | 0.88 | 3.91 | 5.06 |
| Ledger | 1,758 | 1,562 | 4.01 | 5.61 | 4.13 | 6.28 |

Use `guide.a3x` and select one rule per run. The notice rule is `af677c6a14892c998d7d7bd7cb1cba5b:50:Guide.Notice`.
The ledger rule is `b9c7aad25d0ecb2818a7adc4452c66ab:151552:Guide.Ledger`.
The Barnacle release executable had SHA-256 `9e1189b571503ce2c74b40bd1800836edf3570cb1b95be909b8c2df59159e5ea`.
[Raw AutoIt measurements](benchmarks/object-autoit.csv)

EA05 supplies stored or compressed resources in record order. Its script bytes are already plain text after extraction.
Stock checks the stored size and then the expanded size for compressed resources. Only the scanned bytes consume the cumulative budget.
If a file, recursion, or size limit blocks an EA05 resource, a matching outer hash can still win.
When a legacy record header or stored-length read ends early, stock can still match the outer file.
Stock applies the EA05 stored-length limit before reading the record timestamps.
[Legacy fixtures](../tests/fixtures/autoit/README.md#legacy-ea05-archives) · [Rust comparisons](../tests/object_autoit.rs)

The EA05 benchmark used `ledger-ea05.a3x` with the same rules and container settings as EA06.
All 6,156 replies matched the expected signature. The table reports medians from three fresh containers per daemon and rule.

| Signature | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Notice | 19,840 | 10,503 | 0.31 | 0.73 | 4.08 | 5.16 |
| Ledger | 1,761 | 1,641 | 3.98 | 5.40 | 4.12 | 6.16 |

The Barnacle release executable had SHA-256 `9b791be736df5d77edf3e7983730cf9986e4d44c997c3514758c33c188e70ff5`.
[Raw EA05 measurements](benchmarks/object-autoit-ea05.csv)

### ZIP Deflate64 members

Both daemons detect the first member of a 7-Zip archive containing an 81,000-byte ledger and a later text file.
The ledger hash wins over the archive hash. Stock metadata preserves both filenames in local-header order.
At file limits of 16,383 and 16,384 bytes, the scanned prefixes contain 8,192 and 16,384 bytes respectively.
The comparisons also cover nested ZIPs, streaming descriptors, a short final block, and count, recursion, and scan-size limits.
[Rust comparisons](../tests/object_zip_deflate64.rs) · [Fixture provenance](../tests/fixtures/zip/README.md)

Barnacle limits each decoder call to 8 KiB of input and output. It releases the fixed dictionary before scanning the child.
Stock records the ZIP directory file limit before scanning members. An empty stored entry consumes no directory slot.
An empty deflated entry consumes a slot because its compressed stream occupies bytes.
Member outputs through five bytes bypass scan-size, file-count, and recursion checks.
For larger outputs, the scan-size check precedes child file-count and recursion checks.
Barnacle scans stored members directly from the archive, including when their length exceeds the in-memory spool threshold.
If available scan bytes might run out during Deflate64 expansion, Barnacle counts past 64 KiB before using disk.
A member that fits can then be decoded again. Unconstrained members need one pass.
An invalid Deflate64 stream that the decoder rejects returns incomplete coverage. Encrypted entries and ZIP64 layouts remain outside these comparisons.
The Rust decoder uses the MIT license. [deflate64 0.1.12](https://docs.rs/crate/deflate64/0.1.12)

Four clients scanned the ledger ZIP at 4,489 scans/s with Barnacle `be9927b` and 3,541 scans/s with stock.
Median p95 latency was 1.52 ms and 2.47 ms respectively. Median peak cgroup memory was 3.74 MiB and 5.50 MiB.
All 15,360 requests across both concurrency levels returned the ledger signature.
Use the Office benchmark's container settings with 512 requests per client and `ledger-deflate64.zip` as the input.
The sole rule was `40e674895de36362c65153f79fa06d45:81000:Workspace.Reference`.
[Raw ZIP measurements](benchmarks/object-zip-deflate64.csv) · [Benchmark procedure](benchmarks/object-office-packages.md#reproduction)

### Small ZIP64 archives

Stock scans stored and deflated members in libarchive ZIP64 files with usable 32-bit directory fields.
The first eligible member wins over the archive. The ZIP parent carries each member’s basename.
Classic count and directory-size sentinels preserve scanning order, including when central records appear in reverse.
A sentinel in the classic directory offset suppresses all members, including with file-count and recursion alerts enabled.
The Apache fixtures exercise per-member sentinels. Stock skips those members and continues with later eligible entries.
The comparisons cover single-disk archives with a fixed ZIP64 trailer. Large offsets, split archives, and extended trailers remain unverified.
[Rust comparisons](../tests/object_zip64.rs) · [Writer settings](../tests/fixtures/zip64/README.md)

With local hash rules and encrypted-archive alerts disabled, stock skips a protected ZIP member and scans later readable members.
The protected entry counts toward the ZIP directory limit. Its plaintext consumes no scan bytes.
The comparisons cover an Info-ZIP archive with a protected packing note and a readable receipt.
[Info-ZIP fixture](../tests/fixtures/zip/README.md#mixed-encryption)

For a 1 MiB stored ledger, four clients reached 301 scans/s with Barnacle and 247 scans/s with stock.
Peak cgroup memory was 6.94 MiB and 22.28 MiB respectively. Borrowing the member saved 1,048,593 written bytes per scan.
The preceding Barnacle build reached 287 scans/s at 10.36 MiB. Each median covers three fresh containers, one CPU, and 2 GiB RAM.
The Rust driver sent one initial request and 40 warm requests per client. All responses matched the member hash.
Reproduce the archive with `zip -0 -X archive.zip ledger.txt` using the lowercase inventory fixture as `ledger.txt`.
Load the sole HDB rule `aa163d58f60d977b08d8c8e961d537e0:1048593:Inventory.Ledger` and disable daemon caching.
[Fixture generation](benchmarks/object-script-views.md#fixtures) · [Raw measurements](benchmarks/object-zip-stored.csv)

### Executable containers

Stock scans a universal Mach-O file's architecture slices in descriptor order before checking the whole-file hash.
Each slice has its own offsets and an unnamed layer under `CL_TYPE_MACHO_UNIBIN`.
The reference skipped the FAT64 and swapped-endian controls. [Apple-authored object files](../tests/fixtures/macho)

Both daemons match raw hashes and section-relative rules on ordinary ELF files with either `ScanELF` setting.
Both also match an outer PE hash before processing a nested PE resource.
`ScanPE no` disables nested PE extraction. `MaxEmbeddedPE` includes an exact-size resource, and zero disables the size cap.
[ELF comparisons](../tests/object_macho.rs) · [Embedded PE comparisons](../tests/object_embedded.rs)

Barnacle unpacks UPX 4.2.4 PE32 executables that use NRV2B, NRV2D, or NRV2E.
Before decoding, stock rounds the UPX0 and UPX1 virtual sizes up to 0x1000 and adds them.
It checks that sum against `MaxFileSize` and the remaining `MaxScanSize`. Barnacle applies the same check.
Barnacle rebuilds only the layout that the tests verify. It scans the rebuilt image as a child object.
In that layout, the file alignment is 0x200, and UPX1's raw pointer is a multiple of it.
UPX0 starts at RVA 0x1000, and the stream starts 0x15 bytes into UPX1.
The original sections are contiguous, so stock's sequential layout and the RVA layout agree.
Other layouts return incomplete coverage.
A whole-file hash of the packed file wins over the unpacked child. `ScanPE no` disables unpacking.
For a crafted NRV2D file, stock used an NRV2B decoding that ran past the declared stream size to an end marker.
Barnacle returns incomplete coverage when any other NRV decoder reaches an end marker in the rest of the file.
It also returns incomplete coverage when the declared decoder does not yield exactly the declared sizes.
The same applies when the last `PE\0\0` in the decompressed data is not a valid PE32 header.
For some of these files, stock builds a different image, scans the raw decompressed data, or decodes nothing.
Barnacle does not unpack LZMA streams, DLL stubs, PE32+ files, or other UPX versions.
Stock did not unpack the LZMA, DLL, or PE32+ fixtures either. [UPX comparisons](../tests/object_upx.rs)

The benchmark used the 23,552-byte `rich-nrv2b.exe` and one local hash for its 73,728-byte rebuilt child.
It used one pinned ARM64 CPU, 2 GiB of memory, no swap, and disabled scan caching.
The Rust driver checked every INSTREAM reply. Each median comes from three fresh containers per engine and phase.
One client sent the first request after daemon readiness. Four clients sent 256 requests each in the sustained run.

| Daemon | First request (ms) | Sustained scans/s | Sustained p95 (ms) | Sustained peak cgroup memory (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Barnacle | 0.46 | 4,105 | 1.83 | 3.54 |
| Debian clamd 1.4.3+dfsg-1 | 1.42 | 1,441 | 6.13 | 6.00 |

Cgroup memory includes the driver and any file-backed pages charged to the container.
The release executable SHA-256 was `107b9436619a39621ece90d5a0ef4eae84e1a5125ddcc29dc37b0b93b184065b`.
Use the archive benchmark procedure with `rich-nrv2b.exe` as the input.
Load `698e5c674981701552d61d76f56f6bff:73728:Workspace.Reference` as the only rule.
[Raw measurements](benchmarks/object-upx.csv) · [Benchmark procedure](benchmarks/object-decoder-workspace.md#reproduction)

A second benchmark added a 262,144-row inventory resource to the same GUI program.
The packed file is 2,417,664 bytes and the stock child is 14,458,880 bytes.
Five rounds used the same container settings. The sustained run sent 16 requests per client.
All 650 replies matched the same local hash rule. Stock's sustained p95 ranged from 230 to 1,611 ms.

| Daemon | First request (ms) | Sustained scans/s | Sustained p95 (ms) | Sustained peak cgroup memory (MiB) |
| --- | ---: | ---: | ---: | ---: |
| Barnacle | 34.90 | 29.58 | 141 | 70.64 |
| Debian clamd 1.4.3+dfsg-1 | 59.79 | 17.83 | 239 | 223.65 |

Generate the resource using the fixture sources, i686 MinGW GCC 16.2.0, and GNU windres 2.47.20260726.
Pack the result with Debian `upx-ucl` 4.2.4-1.1. [Debian package](https://packages.debian.org/trixie/arm64/upx-ucl)

```sh
fixture_dir=$(mktemp -d)
cp tests/fixtures/upx/rich.c tests/fixtures/upx/rich.rc "$fixture_dir"
cd "$fixture_dir"
awk 'BEGIN { for (i = 0; i < 262144; i++) printf "%06d,consignment,letter folders,shelf %03d,carton %03d\n", i, i % 251, i % 131 }' > inventory.csv
printf '\n%s\n' '2 RCDATA "inventory.csv"' >> rich.rc
i686-w64-mingw32-windres rich.rc -O coff -o rich.res
i686-w64-mingw32-gcc -O2 -s -mwindows -Wl,--no-insert-timestamp -o inventory.exe rich.c rich.res -ladvapi32 -luser32
upx-ucl -q -9 --nrv2b -o inventory-nrv2b.exe inventory.exe
```

Load `f1115e67ad8ce1425b5e945896ce4316:14458880:Workspace.Reference` as the only rule.
The packed fixture SHA-256 was `297ef42f6d4249288d1cab6f9f0a772a12eb8b95ea8841dae9de4749eb25edad`. [Raw measurements](benchmarks/object-upx-inventory.csv)

Stock also runs FSG, MEW, Upack, Petite, PESpin, yC, WWPack, ASPack, and NsPack unpackers after its PE heuristics and bytecode hooks.
Those stages belong to [#26](https://github.com/yavosh/barnacle/issues/26). Other UPX releases belong to [#24](https://github.com/yavosh/barnacle/issues/24). A packed executable without an earlier match returns incomplete coverage, never a clean result.
The UPX code follows the NRV bit-stream format and stock's observed output, not ClamAV source.
The rebuilt image keeps stock's fixed DOS header and stub, so unpacked-child hashes match stock. The licensing decision in [#17](https://github.com/yavosh/barnacle/issues/17) keeps these bytes. [Reference PE pipeline](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/pe.c)

A Java 17 interface matched its target-12 body signature both directly and inside a JAR.
A Java 11 class matched its whole-file hash in both locations. Stock treated the Java 21 control as generic data.
Both daemons selected its whole-file hash over a target-12 rule. [Java fixtures](../tests/fixtures/java)

Little-endian and big-endian WAVE files matched generic body and whole-file signatures both directly and inside ZIP files.
PNG, JPEG, TIFF, GIF, and BMP controls matched graphics signatures before whole-file hashes. [Media comparisons](../tests/object_images.rs)

### Unicode HTML

Both daemons matched hashes of normalized markup and plain text from little-endian and big-endian UTF-16 pages.
The comparisons cover multilingual text, a ZIP attachment, and a 2,500-paragraph page.
For little-endian pages, the HTML size limits apply to the converted bytes. Conversion also consumes one recursion level.
For big-endian pages with a byte order mark, the limits apply to the original bytes.
When limits compete, stock checks normalized output size before file count or recursion. Barnacle counts excluded views without storing their output.
The tests cover file count, scan size, recursion, and disabling HTML scans. [Unicode HTML comparisons](../tests/object_unicode_html.rs) · [Memory and throughput measurements](benchmarks/object-unicode-html.md)

### HTML character references and links

Barnacle reproduces the pinned markup and text hashes for ordinary company names, ampersands in prose, and URL query parameters.
The reference recognized 662 of the 2,125 semicolon-terminated WHATWG names. These include all 252 HTML 4 names.
Seven names use older numeric assignments. Barnacle stores the measured subset in a read-only 9,268-byte table.
[Table provenance and notices](../THIRD-PARTY-NOTICES.md) · [HTML 4 character references](https://www.w3.org/TR/html401/sgml/entities.html) · [WHATWG named references](https://html.spec.whatwg.org/entities.json)

The markup view preserves unknown names in lowercase. The text view omits references in prose and retains links from anchors and images.
URL comparisons cover literal ampersands, escaped separators, mixed-case query values, accented characters, and the 1,024-byte capture limit.
After a second space run, stock truncates the captured URL and retains subsequent reference spellings in markup.
Pending multibyte text can resume in the next attribute, even across tags.

Long attribute values span 8,191-byte input blocks. Tests compare both normalized views when whitespace or a reference crosses a block boundary.
Barnacle reads these values from the input and keeps the 1,024-byte URL capture limit.
Certain combinations of literal controls and tag delimiters in quoted attributes remain incomplete. Entity coverage outside the WHATWG list remains unverified.
[HTML character reference comparisons](../tests/object_html_entities.rs)

### Normalized script text

Each loaded generation enables plain-text normalization when it contains an active generic or ASCII body rule.
A relative ASCII rule also enables hash matching on the normalized view. The direct scanner API enables normalization by default.
The normalized view can borrow a prefix of the input when its bytes already match.
Mapped views check the normalized length before file count and recursion. An excluded view needs no temporary file.
If an admitted view differs, Barnacle writes the unchanged prefix and the remaining normalized bytes into one private spool.
The traversal checks cancellation every 8 KiB of input, including long whitespace runs. [Stock comparisons](../tests/object_text.rs) · [Timing and memory](benchmarks/object-script-views.md)

### Forwarded email

Barnacle and pinned clamd scan Base64 and quoted-printable `message/rfc822` multipart attachments as child mail objects.
A decoded `forward.eml` can match its receipt before a later contact card.
An oversized forward leaves the contact eligible. At the size boundary, the forwarded file can match its own hash.
A plain forward without a transfer marker or a uuencoded attachment is skipped, including one containing a raw PNG.
Stock recovers a uuencoded note as a direct child of the enclosing mail. A contact attachment wins before the note.
The note wins before a raw body signature or the mail hash. Stock assigns the note a private temporary filename.
Notes of five bytes or fewer are skipped before checking file count. Larger notes check decoded size before count and depth.
For an 8bit or binary forward with one note and a transfer marker, stock retains the `end` line.
It scans that revised forward immediately. A following contact remains eligible before the deferred note.
If the revised forward exceeds the byte budget, its saved file can stop directory traversal before a smaller note.
For a standalone printable mail with this one member, Barnacle preserves the outer scan after a note miss.
A matching note is indeterminate here. Stock returned the note on overlayfs and the size limit on tmpfs.
Multiple notes and mixed forwards with an absent or 7bit declaration remain incomplete after direct attachments miss.
The marker is a case-insensitive line prefix, `Content-Transfer-Encoding`, including in prose. A lowercase `7bit` anywhere on that line suppresses it. With a marker, 8bit or binary members are scanned immediately.
An absent or 7bit declaration defers the saved forward until after ordinary attachments.
Stock scans saved messages in private-directory order. Two competing receipts produced opposite winners on Linux overlayfs and tmpfs.
Barnacle scans each copy when all deferred forwards have identical bytes and omit the transfer declaration.
Different saved forwards and the extra recovery file from explicit 7bit remain incomplete after direct attachments miss.

A standalone `message/rfc822` uses the literal embedded headers. A Base64 body without headers produced no mail child.
A simple quoted-printable-wrapped text message retained its literal body. More complex standalone quoted-printable layouts remain incomplete.
Stock scans ordinary mbox attachments in message order before visiting the shared recovery directory.
Named Base64 PDF, PNG, CSV, XLSX and WAV attachments followed this order both standalone and inside multipart/mixed.
Unencoded named CSV joined the saved letters when standalone. Inside multipart/mixed, stock scanned it directly.
Unencoded plain bodies get private filenames. With competing signatures, overlayfs returned the first body and tmpfs returned the second.
Barnacle caches up to 16 borrowed body spans and revisits later messages as needed.
It scans each ordinary saved letter once when all fit, then reports a shared or unique winning signature.
Different winners or a budget that makes the winner depend on directory order produce incomplete coverage.
Empty bodies produce no saved file. Nonempty saved bodies of five bytes or fewer count toward the MIME limit but consume no scanned-file slot.
MaxFileSize applies to each letter and eligible script view. MaxScanSize covers their shared remaining byte allowance.
Explicit 7bit can create another recovery file. More complex mailbox layouts remain partial. [Mbox comparisons](../tests/object_mail_forward.rs)
[Forwarded mail comparisons](../tests/object_mail_forward.rs) · [Throughput and memory](benchmarks/object-forwarded-mail.md)

### Binary HWP documents

HWP5 stores document streams in an OLE compound file. A `FileHeader` stream starts with the HWP signature and contains compression flags.
An unrelated stream named `FileHeader` remains ordinary OLE data. [Hancom HWP5 format](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D_5.0_revision1.2.pdf)

Both daemons scan HWP5 streams before the document hash in compound-directory order.
Compressed paragraphs, document properties, and binary attachments use raw DEFLATE. Preview streams retain their original bytes.
Raw streams receive lowercase names. Inflated streams have no filename. Both retain `CL_TYPE_MSOLE2` as their parent.
An embedded `CL_TYPE_HWPOLE2` wrapper scans the compound file after its four-byte length, including when the length differs.
`ScanOLE2` controls HWP5 and wrapped OLE extraction. [Binary HWP comparisons](../tests/object_hwp.rs)

HWP3 uses a separate paragraph and attachment format. Stock scans the information records before the uncompressed document content and the whole-file hash.
The fixtures cover stored and compressed paragraphs, OLE data, images, hyperlink data, background images, and ZIP ancestry.
`ScanHWP3 no` preserves the outer hash, and `MaxRecHWP3 0` suppresses paragraph parsing.
Rich paragraph controls, protected documents, and HWP5 streams with competing Office macro passes still have incomplete coverage. [HWP3 comparisons](../tests/object_hwp/v3.rs)

### Word 2003 XML, Excel 2003 XML, and HWPML

The reference recognizes Word and Excel XML markers within the first 1,024 bytes.
Its HWPML marker includes the UTF-8 byte order mark.
Both daemons scan attachments in document order before the XML document hash.
The document supplies the parent type. Decoded attachments have no original filename.
Turning off `ScanXMLDOCS` preserves the document hash. [XML comparisons](../tests/object_xml.rs)

Word and Excel store binary data in Base64 text. The reference detects line-wrapped data and skips single-line data without a newline.
It skips CDATA and contents beneath Office style and font elements.
The tests cover numeric character references, nesting, and a 100,000-byte attachment.
The reference stops parsing after a text node exceeds 10,000,000 bytes. [Word 2003 XML reference](https://learn.microsoft.com/en-us/previous-versions/office/developer/office-2003/aa196310(v=office.11))

HWPML supports plain text, Base64, and raw DEFLATE attachments.
With a 12,000-byte file limit, both daemons detect a hash of the first 8,192 expanded bytes.
Barnacle streams expansion into a private spool. DTDs, names exceeding 1,024 bytes, and nesting beyond 256 levels produce incomplete coverage.
The HWPML marker can precede a document with a declared legacy encoding. [Hancom HWPML specification](https://cdn.hancom.com/link/docs/%ED%95%9C%EA%B8%80%EB%AC%B8%EC%84%9C%ED%8C%8C%EC%9D%BC%ED%98%95%EC%8B%9D3.0_HWPML_revision1.2.pdf)

Both daemons scan plain XML attachment text as UTF-8 and preserve the original bytes inside Base64 attachments.
Comparisons cover UTF-8, ASCII, ISO-8859-1, ISO-8859-2, Windows-1251, Windows-1252, Shift_JIS, CP932, EUC-KR, and CP949.
They verify encoding aliases, numeric references, and the distinction between Latin-1 controls and Windows punctuation.
The file-size limit uses the UTF-8 child length. The cumulative limit also includes the original XML byte count.
The text-node limit applies after conversion. Barnacle checks XML characters, references, and duplicate attributes before releasing an attachment.
It returns incomplete coverage for unsupported declarations or elements with more than 1,024 attributes. [Encoding comparisons](../tests/object_xml.rs)

Stock's XML reader pushes 512-byte input blocks. The final block can contain a conversion error after a matching attachment.
Both scanners preserved the same result across 4,980 such Windows-1252, ASCII, and CP932 controls.
A further 6,640 controls placed UTF-8 errors, undefined entities, invalid references, and control characters around block boundaries.
Barnacle withheld 254 stock attachment matches and produced no extra matches across the 11,620 controls.
In a Windows-1252 Workbook, the attachment starts at byte 430 and an invalid character reference starts at byte 515.
Both daemons detect the attachment before the whole-document signature. The ampersand ends one input block, and the reference continues in the next.
Stock can also detect the raw document hash after an earlier metadata error.
Barnacle returns incomplete coverage when the earlier matching stage remains uncertain. [Rust controls](../tests/object_xml.rs) · [Pinned libxml2 reader](https://github.com/GNOME/libxml2/blob/v2.9.14/xmlreader.c)

Barnacle reuses ASCII-compatible input when its bytes need no conversion.
For the supported encodings, each conversion spool uses at most three bytes per admitted input byte.
With scan limits enabled, concurrent conversion spools within one scan use at most three times its cumulative scan-byte limit.
Four concurrent Windows-1252 ledger scans peaked at 30.3 MiB for Barnacle and 79.6 MiB for stock.
The UTF-8 control and throughput measurements use the same attachment hash. [Benchmark results](benchmarks/object-xml-charset.md)

### ISO 9660 disk images

The tests cover cooked sectors and raw CD sectors of 2,352 and 2,448 bytes.
The samples use 512-, 1,024-, and 2,048-byte logical blocks. They include member data spanning sectors.
Stock scans the outer image before its files. Within each volume, it follows directory order and descends into subdirectories.
Barnacle borrows contiguous file bytes and skips framing bytes when reading raw sectors.
The xorriso controls combine ISO files with an appended EFI partition and either MBR or GPT.
The MBR image matches its outer hash before its partitions. The GPT image can match a partition before the outer hash.
Both images visit ISO files after their partition checks. The files keep the ISO 9660 parent type and their directory names.
A tight byte budget can exclude the large partition and still admit both small ISO files.
Stock revisits GPT partitions at the protective MBR marker. It also visits the second ISO descriptor set in the GPT hybrid.
With only the recovery label signature, the MBR fixture reports `MaxFiles` at nine files and the GPT fixture at sixteen.
The alert clears when the budget increases by one file.
The comparisons also cover a data-only MBR image and a plain ISO with text in its system area.
[Rust comparisons](../tests/object_iso.rs) · [Fixture generation](../tests/fixtures/iso-hybrid/README.md)

Four clients scanned the two authored images with only the notice hash loaded.
Each trial used a fresh Linux container with one CPU, 2 GiB RAM, and daemon caching disabled.
The driver sent one initial request, then 128 requests per client. Every request found the notice.
The table gives medians of three trials. The peak includes the scanner and driver cgroup.

| Image | Barnacle scans/s | Stock scans/s | Barnacle p95 ms | Stock p95 ms | Barnacle peak MiB | Stock peak MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| MBR hybrid | 308.52 | 180.87 | 15.58 | 31.31 | 9.42 | 18.36 |
| GPT hybrid | 274.21 | 144.93 | 16.99 | 38.64 | 9.50 | 18.80 |

The tested Barnacle Linux binary had SHA-256 `9d968da204c6979a124336978ec6ec119c81f0ccf40925770146e8bf78b7f21e`.
[Raw hybrid ISO measurements](benchmarks/object-hybrid-iso.csv)

### PDF objects

Stock scans the raw PDF before extracting objects. The first matching indirect object wins in the tested document.
Barnacle scans decoded streams with fresh object contexts. Page content can also produce a normalized text child.
Document names come from the winning signature. [End-to-end fixtures](../tests/object_pdf.rs)

| PDF feature | Observed coverage |
| --- | --- |
| Page streams and embedded files | Unfiltered, Flate, ASCIIHex, ASCII85, run-length and chained ASCIIHex/Flate data. |
| LZW | Embedded files, page streams, resets, code-width changes, and chained ASCIIHex/LZW filters. [LZW comparisons](../tests/object_pdf_lzw.rs) |
| Page text | Parenthesized strings in page text arrays. The normalized bytes can match a whole-file hash. |
| Nested inputs | ZIP containing a PDF and a PDF with competing raw and child rules. |
| Policies and truncated input | Parser disabled, recursion and expanded-size alerts, a missing final trailer, and a truncated stream. |
| Packed indirect objects | Stored and Flate object streams, packed page dictionaries, content arrays, indirect lengths, and physical stream order. [Object-stream comparisons](../tests/object_pdf_streams.rs) |
| Standard encryption | Classic xref tables and cross-reference streams, qpdf RC4 (R2–R4), AES-128 (R4), and AES-256 (R5/R6), including encrypted object streams, LZW chains, and DCT images. Locked documents expose their ciphertext. |
| Additional PDF stages | JavaScript actions and other stream filters require further comparisons. |

For physical objects, both daemons scan the referenced page dictionary for an explicit catalog opening destination.
An inline local GoTo exposes the catalog. An indirect local action exposes the referenced object at its physical position.
The child contains the bytes between `obj` and `endobj`, including surrounding line endings.
Both daemons detect the Flate-compressed plaintext attachment after the outer PDF hash. They scan competing attachments in physical order.
Both scan stored attachments as ciphertext. A Flate filter after the first closing dictionary also preserves the ciphertext.
Direct embedded-file MIME subtypes can encode the slash as `#2f` or `#2F`.
Barnacle bounds security metadata to 16 KiB. It decrypts and inflates in 8 KiB blocks. Excluded children need no scratch file.
The comparisons cover restricted copy permissions, named stream filters, explicit embedded-file defaults, and cleartext metadata flags.
Stock scans physical bytes for the sampled explicit `Crypt` records. That range can include the line ending before `endstream`.
Flate and ASCIIHex can decode in sequence. The final attachment can fit its scan budget even when its intermediate is larger.
A Flate stage that cannot grow past its allowed block leaves its input eligible for matching.
When the output could exceed the byte limit, Barnacle counts it before writing large decoded attachments to disk.
A cross-reference stream can hold the encryption reference. Stock leaves that stream unencrypted and scans its inflated predictor rows.
Stock decrypts and inflates an encrypted object stream before reading its directory. It reads packed members only with the compact `/Type/ObjStm` spelling.
A decoded carrier larger than the remaining scan budget is skipped, but its eligible members are still scanned.
That carrier fits stock's first 256 KiB Flate allocation, so Barnacle keeps it in memory instead of a scratch file.
Stock scans stored carriers and stored streams as ciphertext.

When the empty user password fails, stock does not decrypt. Its Flate stage then fails on the ciphertext and it scans each stream's physical bytes.
Barnacle does the same only when both of stock's inflate attempts must fail at the zlib header. Other locked layouts yield incomplete coverage.
Stock sets its attachment flag only when `/EmbeddedFile` appears before the filter list.
Without that flag, a stream whose only filters are LZW or run-length is not scanned. The flag also selects the `/EFF` crypt filter.
In encrypted documents, stock decrypts a stream before its LZW chain. A leading DCT stage keeps the ciphertext.
Stock's ASCIIHex and ASCII85 decoders have no size limit. Only the final filter output counts against the scan budget.
Unsupported filters also yield incomplete coverage. [Security comparisons](../tests/object_pdf_security.rs)

Four clients scanned a 117,423-byte PDF with restricted copy permissions and a 221,880-byte CSV attachment.
Each engine used three fresh containers on one pinned ARM64 CPU with 2 GiB of RAM and scan caching disabled.
Barnacle reached 463 scans/s at 19.42 ms p95. Stock clamd reached 250 scans/s at 21.66 ms p95.
Median peak cgroup memory was 3.55 MiB for Barnacle and 8.20 MiB for stock.
It includes the driver and charged file-backed pages. All 3,078 replies matched the local attachment hash rule.
The Barnacle release binary SHA-256 was `7b6f168146b251574e80a1aa9463dbd2bd2656fa2ad621af7193174ba9f14b7f`.
[Raw measurements](benchmarks/object-pdf-restricted.csv)

To create the workload, use qpdf 12.4.2 with the shipment fixture and omit object streams.

```sh
qpdf --object-streams=disable --decrypt tests/fixtures/pdf/open/shipments.pdf shipments-plain.pdf
qpdf --object-streams=disable --encrypt '' '' 256 --allow-insecure --extract=n -- \
  shipments-plain.pdf shipments-restricted.pdf
```

Load `6df41fb06ea3f20d42a7fd3cf48b1aad:221880:PdfQa.Shipments` as the only rule.

Barnacle indexes only the requested object IDs. The PDF parser admits at most 65,536 physical objects.
The tests cover all eight explicit destination modes, local named destinations, sparse IDs, backward references, and ZIP attachments.
Chained actions and unresolved or ambiguous destinations remain incomplete.
[Destination comparisons](../tests/object_pdf_destinations.rs) · [PDF 1.7 sections 12.3.2 and 12.6.4.2](https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf)

Stock uses early LZW code-width changes for both `/LZWDecode` and `/LZW`, even with `/EarlyChange 0`.
Both daemons matched the same 2,724 output bytes from a 7,500-byte late-change attachment. qpdf 12.4.2 decoded all 7,500 original bytes.
The sampled unreferenced stream and grayscale image did not produce a decoded match.
Both daemons scan a decoded page stream before its normalized text.
Stock skips normalized page text of five bytes or fewer before testing file count or byte limits.
For longer text, the normalized size can trigger a scan-size alert before the file-count alert. [Page-text tests](../tests/object_pdf.rs)
The physical and packed-page comparisons include text spanning multiple 8,192-byte normalized output blocks.
Barnacle counts the text before using scratch storage when the source could exceed the remaining scan budget.

At 262,143 expanded bytes, a 10,000-byte file limit suppresses the LZW output and records a size alert.
At 262,144 bytes, stock requests another 256 KiB block. If that request exceeds the limit, both scanners scan the LZW input.
For an ASCIIHex/LZW chain this input is the ASCIIHex output. Later filters are skipped.
Barnacle uses a fixed 4,096-entry dictionary and spools at most the remaining object budget.
It counts terminal output without writing it when file count or recursion excludes the child.
The decoded size can still trigger a size alert. [LZW comparisons](../tests/object_pdf_lzw.rs) · [Sustained scan measurements](benchmarks/object-pdf-lzw-sustained.md)

Both daemons scan PDF attachments in Adobe XDP forms. They visit the first matching PDF in XML order.
If the form type appears in the first 1,024 bytes, its attached PDF can win over the form hash.
A later type marker allows the outer hash to win first. Both paths give the PDF a `CL_TYPE_XDP` parent.
`ScanPDF no` disables attachment extraction. `ScanArchive no` leaves it enabled. [PDF form comparisons](../tests/object_pdf.rs)

Both daemons match the decoded object stream before later physical streams.
Clamd reads the packed directory for the compact spelling `/Type/ObjStm`.
A packed page can mark a later physical stream for text extraction.
Packed dictionaries selected for scanning follow all physical streams, including the cross-reference stream.
For one stored carrier, deferred members borrow the original PDF bytes.
A single decoded carrier can supply its large opening dictionary directly when it fits the remaining storage budget.
Barnacle retains at most 64 KiB of other carrier data on that path. Sparse and multi-carrier inputs use the deferred spool.
A packed catalog with a local opening destination exposes the earlier of the catalog and the referenced member.
An inline GoTo exposes the catalog. Barnacle resolves one opening catalog per carrier. It checks cancellation while reading borrowed dictionary bytes.
The paired tests include a 1 MiB catalog, a large backward page reference, and the exact remaining scan budget.
References across carriers remain incomplete.
With the spaced spelling `/Type /ObjStm`, only the carrier stream participates in this stage.
The independent control uses qpdf 12.4.2 and contains one page and a text attachment. [qpdf control](../tests/fixtures/pdf/qpdf-object-stream.pdf)

The tests cover Flate expansion across the reference's initial 256 KiB buffer.
An oversized decoded directory can still supply a page reference when it fits this buffer.
If the next allocation exceeds the limit, the reference can scan the encoded carrier instead.
Barnacle stores deferred arrays and selected dictionaries in one private spool, bounded by the initial remaining object budget.
If the spool fills, a later selected object can produce incomplete coverage. [Object-stream layout](https://qpdf.readthedocs.io/en/stable/object-streams.html) · [Catalog benchmarks](benchmarks/object-pdf-catalog.md)

### Apple disk images

Stock scans the raw DMG, then its XML catalog, then each partition listed in the catalog.
An outer hash wins over a catalog hash. A catalog hash wins over a partition hash.
Stock preserves catalog order across partitions. Within a partition, it sorts stripes by starting sector.
The reconstructed partition has no filename and has `CL_TYPE_DMG` as its parent. [DMG comparisons](../tests/object_dmg.rs)

Four read-only images from Apple `hdiutil` reproduce the same harmless partition.
They cover stored data (UDRO), ADC (UDCO), zlib (UDZO), and bzip2 (UDBZ).
Rust fixtures cover zero-filled stripes, sparse-only partitions, multiple maps, and a DMG inside ZIP.
A catalog or projected partition exceeding its size budget stops the pass, including when alerts are disabled.
Segmented images, resource-only catalogs, and additional codecs need separate comparisons. [Control images](../tests/fixtures/dmg)

### MBR, GPT, and Apple partition tables

All three parsers run with `ScanArchive yes`. Barnacle checks partition extents and scans them directly from the image.
Apple `hdiutil` authored three independent images using the MBRSPUD, GPTSPUD, and SPUD layouts.
Both daemons found the same harmless text file inside all three HFS+ volumes. [Authoring controls](../tests/fixtures/partition)

| Layout | Stock scan order and selection |
| --- | --- |
| MBR | Whole image, 512-byte boot sector, then primary entries in table order. Extended entries lead to logical partitions. |
| GPT with 512-byte sectors | Partitions precede the whole image. A valid backup supplies entries if the primary checksum fails. Differing valid tables are scanned in primary then backup order. |
| GPT with 4096-byte sectors | The protective MBR triggers GPT after the raw scan. A matching whole-image hash wins. |
| Apple partition map | Partitions precede the whole image. Stock counts the map itself, then scans the named data partitions in table order. |

`MaxPartitions 0` suppresses partition scans. Empty MBR and GPT slots count toward the limit.
The MBR boot sector also consumes a file slot. An oversized first APM partition stops traversal before a later smaller partition.
Stock finds the legacy APM with a map at byte 512. It misses the same payload with a native map at byte 2048.
ZIP ancestry, container signatures, recursion, scan size, and file-count limits have paired controls. [Partition comparisons](../tests/object_partition.rs)

Stock-only controls record the three intersection heuristic names and their order against a matching partition signature.
Barnacle's heuristic matcher still needs that coverage. Vendor-specific extended layouts and non-ASCII partition names need additional comparisons.

### HFS+ and HFSX partitions

Both daemons visit regular files in catalog leaf order inside a DMG partition.
They scan the decompressed file, data fork, and resource fork in that order.
The original basename applies to each fork. The HFS partition supplies the parent type.
A DMG hash wins over a file hash. A file hash wins over a partition hash.
Apple's `hdiutil` control verifies detection of a root file and a nested file. [Control image](../tests/fixtures/dmg/hdiutil-hfsplus.dmg.gz)

Rust fixtures cover HFSX, fragmented data, Unicode names, symbolic links, and zlib data in attributes and resource forks.
Stock skips an inline stored attachment until it has inflated another file in the same catalog.
The comparisons also cover `ScanArchive`, recursion depth, file count, and the exact cumulative byte limit. [HFS comparisons](../tests/object_hfs.rs)

Barnacle reads contiguous forks directly and streams fragmented forks and compressed resources.
It handles eight extents per fork and indexes up to 32,768 compression attributes per partition.
Forks requiring overflow extents and larger attribute indexes produce incomplete coverage.
When an allocation block exceeds the catalog node size, both daemons skip file extraction and match the partition.

### UDF optical images

Stock scans the raw disc before its UDF members. An outer whole-file hash takes precedence.
The reference visits file entries in physical descriptor order. The test rearranges entries while preserving their directory names and references.
Barnacle checks each recorded extent against the image length and scans it directly. [UDF comparisons](../tests/object_udf.rs)

The Rust fixtures cover single short, long, and extended allocation descriptors, cross-sector data, truncation, and nested ZIP input.
Stock supplies an empty original filename and sets the scan parent to `CL_TYPE_UDF` for these members.
An extent exceeding the remaining scan budget ends the UDF pass. A later smaller file receives no scan.

Three UDF 1.02 controls place an ordinary text file before and after the ledger under test.
They derive from an Apple-authored disc with its volume descriptors ordered for stock's reader.
The single-extent control stores the 5,830-byte ledger contiguously.
The fragmented control stores the same ledger in two short allocation descriptors at nonconsecutive offsets.
The inline control stores 61 bytes inside the file entry. Debian 7-Zip 25.01 extracted all nine files byte-for-byte.

Stock and Barnacle stop the UDF pass at the fragmented or inline entry. The later ordinary file receives no scan.
Hashes for the joined ledger, each individual extent, and the inline payload all miss on their respective controls.
The earlier file still matches with parent `CL_TYPE_UDF`. A competing whole-disc hash wins in every layout.
With `MaxFiles 2`, the disc and its first member consume both slots. Only the single-extent control raises `MaxFiles`.
With exactly 40 bytes left after the disc, only the single-extent control raises `MaxScanSize`.
All three raise `MaxRecursion` at depth one when limit alerts are enabled.
Stock reports `OK` on a member-hash miss. Barnacle reports incomplete detection coverage. [Allocation tests](../tests/object_udf.rs)

Two independent control images contain the same harmless text files. Apple `hdiutil makehybrid` produced both with UDF version 1.02.
Stock reported `OK` on the pure UDF control with the two local member hashes loaded.
The ISO/UDF bridge detected the first text file and assigned `CL_TYPE_ISO9660` as its parent.
The checked-in images are gzip-compressed and the Rust tests expand them before scanning. [Authoring controls](../tests/fixtures/udf)

### XAR archives

Stock checks the decompressed XML catalog first. It then visits XML subdocuments, heap entries, and the raw archive.
Catalog order selects the first matching extended attribute or file. Heap offsets can appear in a different order.
Stock serializes a subdocument’s inner XML before matching it. [XAR comparisons](../tests/object_xar.rs)

Barnacle scans stored data, zlib, and LZMA directly. Bzip2 and XZ entries pass through their respective archive handlers.
An incorrect entry checksum does not suppress a detection. A damaged zlib member can precede a valid matching file.
An oversized catalog prevents scanning its heap. Byte, file count, and recursion limits use the daemon configuration.

Catalog decoding spills to a private file after 64 KiB. The pinned allocation ceiling is one GiB, including the terminating byte.
Both daemons detect the namespace-bearing inventory subdocument from Apple xar before its heap receipt or archive hash.
Each subtree keeps local namespace declarations first. It adds inherited declarations in first-use order, including uses by descendants.
Stock preserves XML comments, processing instructions, and CDATA in this subdocument. It merges adjacent CDATA sections where possible.
Comments and processing instructions use LF line endings. CDATA keeps its original line endings.
Attribute serialization escapes ampersands, quotes, and angle brackets. Literal attribute whitespace becomes spaces, while referenced whitespace keeps decimal character references.
With an explicit UTF-8 declaration, accented letters stay UTF-8. Without a declared encoding, attribute values use uppercase hexadecimal character references.
Element text, names, CDATA, comments, and processing instructions retain UTF-8 without a declared encoding.
A US-ASCII declaration accepts numeric character references. A literal non-ASCII byte interrupts catalog decoding.
Complete earlier subdocuments and heap entries remain eligible before the outer archive hash.
The size check precedes the file-count check. Without inherited bindings, six times the remaining source length bounds the output.
If that bound fits, Barnacle serializes once. Otherwise it counts the output before spilling an admitted subdocument larger than 64 KiB.
It supports up to 256 live namespace bindings and 256 attributes per element. Names beyond 1,024 bytes, prefixes beyond 256 bytes,
namespace URIs beyond 2,048 bytes, escaped namespace URIs, and unverified XML serialization return incomplete coverage.
Attribute values above 10,000,000 source bytes and character references longer than 32 bytes also return incomplete coverage.
LZMA dictionary estimates above 64 MiB also return incomplete coverage. [Apple fixture](../tests/fixtures/xar/README.md) · [Inventory benchmarks](benchmarks/object-xar-inventory.md)

### OLE compound documents

Stock scans an ordinary compound document’s streams before checking the outer file hash.
It visits each directory node before its right and left siblings. Storage children precede those siblings.
A child inside a nested storage still has the enclosing compound file as its scan parent. [Rust comparisons](../tests/object_ole.rs)

| OLE feature | Observed coverage |
| --- | --- |
| Ordinary streams | Mini sectors, regular sectors, nested storage, three competing streams, and a single-stream version 4 file. |
| Embedded Package | A root Package payload wins against its envelope. In a nested storage, the envelope hash can win first. |
| Nested formats | ZIP inside OLE, OLE inside ZIP, and parent-type matching on extracted streams and attachments. |
| Limits | File count, storage depth, scan recursion, remaining scan bytes, and scanning with `ScanOLE2 no`. |
| Coverage gaps | VBA, XLM, embedded Office images, protected HWP documents, encryption, and larger version 4 directories require further comparisons. |

Rust tests compare competing raw streams and embedded packages in macro-free Word, Excel, and PowerPoint documents.
They cover flat directories, nested storages, shared stream names, and the underlying filesystem’s scan order.
Barnacle creates empty private directory entries when it needs that order. It reads each payload from the compound file.

The Excel control contains a generated PNG in a macro-free workbook saved by Spreadsheet::WriteExcel 2.40.
Benchmarks compare the embedded PNG hash with one and four clients. [Excel picture measurements](benchmarks/object-pdf-excel.md)
Stock scans its BIFF report, the original PNG bytes, and then the outer file. It skips the raw Workbook stream.
The short report contains a 117-byte preamble. Generic body and whole-file signatures match it before the picture.
A report miss leaves the file count and scan-byte budget available for the picture.
Stock metadata describes an unnamed PNG under `CL_TYPE_MSXL`. Its parent signature matches `CL_TYPE_MSOLE2`. [Excel tests](../tests/object_ole_xls.rs)

Barnacle joins drawing-group and continuation records in a private spool. The controls cover PNG, JPEG, TIFF, and a multi-record DIB.
A bare JPEG followed by another store entry includes its next 17 bytes in the tested one-identifier layout.
The first image exceeding the byte budget stops picture traversal. Disabling `ScanImage` preserves picture hashes. Disabling `ScanOLE2` skips them.
The authored formula control contains `2+3` and `SQRT(A1*2)`. Both daemons match its 117-byte report before the PNG.
Barnacle bounds the report text for common arithmetic, references, ranges, and worksheet functions without evaluating the cells.
Stock exposes another 4,096 report bytes only after formatting one more byte. Barnacle matches the same complete blocks for ordinary worksheet records.
A 350-term sum produced a 4,213-byte report. An independently authored 120-row numeric ledger ending in SUM produced a 16,501-byte report.
Both report hashes beat the embedded picture. A matching generic body signature beat the competing report hash.
Barnacle counts output first when the report might exceed the remaining budget. A rejected report can still leave a smaller picture eligible.
Unverified text inside a visible block returns incomplete coverage. This includes unsupported records and formula suffixes inside earlier blocks. [BIFF formula example](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-xls/bccb00ac-67a1-490a-9f0b-5ce59978eb9a)
An Apache POI workbook contains three crate outlines in WMF, EMF, and PICT format.
Both daemons scan the 4,213-byte report first, then the three stored picture payloads in workbook order.
At 4,212 available scan bytes, the WMF signature wins. The WMF and EMF payloads retain their zlib encoding.
With OLE scanning disabled, the workbook hash wins. [Authored workbook](../tests/fixtures/xls/README.md)

Stock skips external `Data` and `Pictures` delay streams during the Excel drawing pass.
An inline picture after an unresolved reference can still match. A bare picture immediately after the reference in the same store can match first.
Stock prefers the root `Workbook` over `Book`. A missed picture in the root can leave a nested `Workbook` eligible.
An unresolved delayed-only root store can stop that traversal. The scratch filesystem determines the order of competing sibling workbooks.
Complete unframed picture records after BIFF EOF leave the outer file eligible for matching.
Zero padding inside the Workbook stream contributes lines to the report. The picture stays eligible when that report misses.
[Picture store entry specification](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/2f2d7f5e-d5c4-4cb7-b230-59b3fe8f10d6) · [Rust comparisons](../tests/object_ole_xls.rs)

Mixed Office storages scan native attachments, PowerPoint attachments, the Excel report, and pictures in that order.
Each storage scans its raw streams and descendants before visiting the child storages' extraction passes.
An oversized raw stream stops that walk. A matching outer file can still win.
The OLE passes are skipped when the outer file consumes the last scan byte.
Native attachment admission uses the recovered length before checking file count and recursion.
[PowerPoint compressed storage record](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/305e541f-2c91-49c5-a742-4955330fd2b9) · [Mixed Office comparisons](../tests/object_ole_xls.rs)

Four clients scanned an 88,064-byte workbook with a delayed PNG and an inline 81,160-byte bitmap.
Each engine used three fresh containers on one pinned ARM64 CPU with 2 GiB of RAM and caching disabled.
Barnacle reached 2,898 scans/s at 2.44 ms p95. Stock clamd reached 1,336 scans/s at 7.17 ms p95.
Median peak cgroup memory was 4.25 MiB for Barnacle and 6.02 MiB for stock, including the driver and charged file-backed pages.
All 3,078 replies matched the same local MD5 rule, `fbb077e639642f31fb93db9a0241dac7:81160:OfficePass.Bitmap`.
The Barnacle release binary SHA-256 was `dde4f901a905f6018d1b85f06fad0a0cd784365a3888f696621347222edd7d45`.
[Raw measurements](benchmarks/object-xls-workbooks.csv)

Adding passive Word, PowerPoint, and native Package streams produced an 89,600-byte mixed workbook.
The mixed workload used the same bitmap rule and container settings. All 3,078 replies matched.
Barnacle reached 2,891 scans/s at 2.50 ms p95. Stock reached 1,436 scans/s at 6.14 ms p95.
Median peak cgroup memory was 3.80 MiB for Barnacle and 6.27 MiB for stock.
The Barnacle binary SHA-256 was `328869affa9255da5955bb18813871dd25af229684fb125819c9b60c92c8adaf`.
[Raw mixed Office measurements](benchmarks/object-mixed-office.csv)

Both daemons scan top-level PowerPoint `ExOleObjStg` zlib payloads before the root presentation stream and its file hash.
A root native Package still wins. A presentation inside a storage receives its attachment pass after the root raw-stream pass.
Stock records the original attachment name as `ppt0000000c.doc` when the compressed data starts at byte 12.
An uncompressed external object produced no child match. [PowerPoint controls](../tests/object_ole_ppt.rs) · [Microsoft record definition](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ppt/305e541f-2c91-49c5-a742-4955330fd2b9)

Temporary-directory order selects among competing attachments. On the pinned Linux filesystem, reversing two records reversed the winning signature.
Stock stops the attachment pass when an expanded object exceeds a size limit. The tested 8,192-byte prefix never matched.
Barnacle keeps at most 4,096 record offsets per presentation stream, including with `MaxFiles 0`.
If the stream needs traversal, the next record returns incomplete coverage. The tests verify scratch cleanup after success, overflow, and cancellation.
Stock checks each attachment's byte limit before its file count and recursion depth.
A smaller blocked attachment can therefore report its limit before a later oversized attachment.
When both depth and file count exclude an attachment, stock reports the file count.
Barnacle reads streams with the MIT-licensed `cfb` crate. [Dependency license](https://github.com/mdsteele/rust-cfb/blob/master/LICENSE)

## Reference order and limits

The Rust runner generates two benign local signature files. It sends every sample through `INSTREAM` over a private Unix socket.
It enables extended detection logs, disables caching, and repeats each configuration with `AlertExceedsMax` off and on.
The 250 rows cover 24 profiles under both alert settings.
Both the protocol and log observations identify the signature. [Rust runner](../examples/object_reference.rs)

Barnacle matched 165 protocol and log rows exactly, including every stock detection and limit alert.
The remaining 85 stock `OK` replies produced Barnacle's explicit incomplete-coverage error.
The daemon returns this error for both unsupported objects and completed traversals with no matcher hit.
These 85 replies therefore do not measure how many object handlers remain unfinished.

| Observation | Stock result |
| --- | --- |
| A raw document matches a body rule and a whole-file hash. Its gzip layers also have matching hashes. | The innermost body rule wins in all three forms. The log reports the outer input's MD5 and size. |
| A two-entry ZIP has distinct child detections and reversed central directory order. | The first local entry wins on this fixture. |
| A truncated gzip contains an ordinary document without a local signature. | Stock returns `OK` on this fixture. |
| A local hash matches a five-byte input. | Stock returns `OK`. |
| `MaxRecursion` or `MaxFiles` is 1, 2 or 3. | The input counts as the first object. One gzip child needs 2. A gzip within gzip needs 3. |
| An expanded member is exactly `MaxFileSize` bytes. | Stock detects the member. The same gzip loses that detection when the limit is one byte lower. |
| The input and its expanded member total exactly `MaxScanSize`. | Stock detects the member. Reducing the limit by one byte produces a limit outcome. |
| One ZIP entry exceeds `MaxFileSize` and a later entry matches. | The later detection wins with both alert settings. An outer hash can also win after a child limit. |
| The scan reaches both the file count and recursion limit. | The ZIP fixture reports `MaxFiles` when alerts are enabled. |
| The scan exceeds its 1 ms deadline on a 2 MiB document collection. | Stock returns `OK` with alerts off and reports `Heuristics.Limits.Exceeded.MaxScanTime` with alerts on. |

The pinned defaults are 100 MiB per object, 400 MiB total, 17 recursion levels, and 10,000 objects.
The default scan timer and limit alerts are disabled. Zero disables the byte and file count limits.
Stock treats `MaxRecursion 0` as a request for the engine default. [Effective options](compatibility/clamd-options.txt) · [Reference limit code](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/others.c)

With alerts enabled, limits can yield `Heuristics.Limits.Exceeded.MaxFileSize`, `MaxScanSize`, `MaxFiles`, `MaxRecursion`, or `MaxScanTime`.
An earlier definitive signature can take precedence. An oversized top-level file takes a separate path.
Stock omits the extended MD5 and size when that initial file-size check produces the detection.
An internal limit logs the outer input's MD5 and size. [Reference scan pipeline](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/scanners.c)

## Replay

Run the following commands as an ordinary user in the pinned Debian environment.
The two output files record the profile, alert setting, sample, input size, protocol result, and extended log result.
The 1 ms observations depend on elapsed wall time. Use the reference VM when reproducing them.

```sh
cargo build --release --locked --bin barnacle --example object_reference
target/release/examples/object_reference /usr/sbin/clamd > /tmp/stock-objects.tsv
target/release/examples/object_reference target/release/barnacle > /tmp/barnacle-objects.tsv
diff -u /tmp/stock-objects.tsv /tmp/barnacle-objects.tsv
```

The official profile uses verified main 63, daily 28187, and bytecode 339. It includes a harmless nested gzip.
The stock replay compares both local and official databases against the frozen protocol observations. [Official replay steps](compatibility/replay.md)

## Concurrent nested scans

The benchmark uses the same 128 benign payloads and 101,744 active body rules as the body benchmark.
Half the inputs have one gzip layer. The other half have two.
Both daemons scanned the same bytes on one vCPU with 2 GiB RAM and no swap.
Each value is a median of three fresh guest boots. [VM configuration and database preparation](body-benchmark.md)

| Concurrent clients | Pass | Stock scans/s | Barnacle scans/s | Stock p95 ms | Barnacle p95 ms |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | First | 676 | 960 | 4.51 | 2.97 |
| 1 | Warm | 715 | 964 | 4.40 | 2.97 |
| 4 | First | 669 | 936 | 21.32 | 12.73 |
| 4 | Warm | 705 | 957 | 20.49 | 12.74 |

A separate pass repeats 128 objects after the timed workload.
Its scanner cgroup peak includes file-backed pages. The driver resets the kernel counter before this pass.
The driver samples allocated blocks on the temporary filesystem every millisecond.
Scratch growth includes unlinked files. Individual spikes between samples can exceed the reported growth.

| Clients | Daemon | Build peak MiB | Warm current MiB | Scan peak MiB | Sampled scratch growth MiB |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 | Stock | 94.16 | 100.87 | 103.21 | 0.75 |
| 1 | Barnacle | 79.11 | 73.27 | 74.29 | 0.75 |
| 4 | Stock | 94.16 | 101.51 | 108.22 | 3.02 |
| 4 | Barnacle | 79.14 | 73.64 | 76.23 | 2.25 |

All 9,216 responses returned the expected local signature. Barnacle took 271–272 ms to become ready. Stock took 243–244 ms.
These measurements cover this gzip workload and the body database. [Raw observations](benchmarks/object-profile-samples.csv)

Use the body benchmark's data disk and private daemon configuration. Build the current Rust driver.
Pass `gzip` after the client count. The driver runs the first, warm, and pressure passes in that order.

```sh
/data/body_bench "$daemon" /data/clamd.conf /run/clamav/clamd.ctl "$clients" gzip
```

The gzip benchmark used Barnacle binary SHA-256 `9b416808ed0f741d5d1ec8745d224ab67f49d6db9d90262f002043cb6cb02062`.

### Nested XZ streams

Six fresh guest boots alternated stock clamd and Barnacle. Four clients scanned the same 128 files per boot.
Each file had one or two XZ layers, encoded at preset 5. All 4,608 replies returned the expected local signature.

| Median of three boots | Stock clamd | Barnacle |
| --- | ---: | ---: |
| Warm scans/s | 349.19 | 489.20 |
| Warm p95 ms | 32.40 | 22.67 |
| Scan peak MiB | 113.83 | 75.56 |
| Sampled scratch growth MiB | 2.34 | 2.26 |
| Ready ms | 244.97 | 273.75 |

Run the same benchmark command with `xz` as its last argument. The body-rule database and VM settings match the gzip experiment.
The measured Barnacle binary had SHA-256 `e2e85a9bdc8ffb909bc3c704b0025316163ad4ad0490ccd6a1d3a66dc91a5d3c`. [Raw observations](benchmarks/object-xz-profile-samples.csv)

The integrated build at `e27c145` repeated the four-client XZ experiment on six fresh reference guests.
Each guest used one vCPU and 2 GiB RAM without swap. All 4,608 replies matched the expected local signature.

| Median of three boots | Stock clamd | Barnacle |
| --- | ---: | ---: |
| Warm scans/s | 328.33 | 460.24 |
| Warm p95 ms | 34.63 | 24.01 |
| Scan peak MiB | 113.69 | 79.28 |
| Sampled scratch growth MiB | 2.34 | 2.01 |
| Ready ms | 257.81 | 291.87 |

The compiled Barnacle binary had SHA-256 `15a5d95fae48cc20a5bffa50a487120bfeec5620aa6dea79c83544c17de7a2ed`.
[Integrated reference-guest results](benchmarks/object-xz-integrated.csv)
