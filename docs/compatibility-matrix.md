# Clamd compatibility matrix

This matrix targets Debian 13 arm64, ClamAV 1.4.3+dfsg-1, and engine functionality level 213.
The daemon, libclamav12, clamdscan, clamav-base, and scanning utilities use that package revision.
The local and official profiles use the [same daemon configuration](compatibility/oracle.conf.in).
Each run creates a private directory and binds an available loopback port. [Replay instructions](compatibility/replay.md)

Stock clamd supplies the full-scan verdicts. The Barnacle daemon reports incomplete coverage as a scan error.
Each profile tests the same fixtures against the stock daemon and Barnacle. [Daemon guide](daemon.md)

## Daemon and client coverage

| Surface | Verification and behavior |
| --- | --- |
| `PING`, `VERSION`, `VERSIONCOMMANDS` | The Rust oracle compares exact replies, database versions, and the advertised command order. |
| NUL, newline, and legacy frames | Check termination, fragmented commands, and disconnects using Unix sockets. |
| Unix and TCP | Compare loopback TCP and Unix stream submissions. Depot submits the same uploads over both transports. |
| `INSTREAM` | Compare raw frames and unmodified clamdscan. Exceeding the stream limit returns the stock size error. Unmatched content returns an explicit error. |
| `FILDES` | Run clamdscan with `--fdpass`. Rust socket tests verify descriptor ownership on success and rejection. |
| `SCAN`, `CONTSCAN`, `MULTISCAN`, `ALLMATCHSCAN` | Compare local detections and directory results. The all-match request returns an error while enumeration is incomplete. |
| `IDSESSION`, `END` | Check pipelined requests, numbered replies, session termination, and commands rejected inside a session. |
| `STATS`, `DETSTATS`, `DETSTATSCLEAR` | Check the stats frame and its terminator. The two legacy commands close the connection without a payload. |
| `SHUTDOWN`, `QUIT`, signals | Exercise both aliases, SIGHUP, SIGTERM, PID files, private socket cleanup, and a background launch. |
| `RELOAD`, SIGUSR2, timed self-check | Replace local rules during service operation. Invalid updates retain the last validated index. Other official generations require [#11](https://github.com/yavosh/barnacle/issues/11). |
| Service startup | Exercise the packaged foreground flag and an inherited Unix listener with the real systemd socket launcher. |
| Timeouts and cancellation | Compare command read deadlines with stock. Disconnect a partial upload and verify a new client can connect. |

Use the pinned command table for legacy framing and command availability. Later releases can advertise different commands.
[ClamAV 1.4.3 command dispatch](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/clamd/session.c) · [Protocol guide](https://docs.clamav.net/manual/Usage/ClamdProtocol.html)

## Configuration coverage

The [effective option list](compatibility/clamd-options.txt) contains all 135 entries that the pinned `clamconf` reports for this profile.
It includes hidden development options, compatibility aliases, and settings consumed by the on-access client.
The list substitutes `/oracle` and port `3310` for the temporary directory and ephemeral port.
`disabled` is the vendor tool's rendering, including zero-valued numeric options.

Barnacle reads `/etc/clamav/clamd.conf` by default. The packaged service passes `--foreground=true`.
The CLI accepts `--help`, `--version`, `--foreground`, `--debug`, `--log`, `--config-file`, `--fail-if-cvd-older-than`, `--datadir`, and `--pid`.
CLI values override file settings. The first value wins for single-valued directives.
`TCPAddr` and `ExcludePath` accept multiple entries. Unsupported regular expressions fail during startup.

The Linux arm64 test used the unmodified Debian package configuration and one harmless local hash.
The test created the service directory `/run/clamav` with owner and group `clamav`.
Barnacle dropped privileges to that account and created the configured socket with mode `0666` and group `clamav`.
Stock `clamdscan --ping` returned `PONG`. A path scan reported the fixture signature and returned exit status 1.
`SIGTERM` stopped the daemon and removed the socket.

| Configuration area | Behavior |
| --- | --- |
| Endpoints and limits | Supports Unix and TCP listeners, socket ownership, octal permissions, stale-socket checks, and timeouts. Adjusts `MaxQueue` for `MaxThreads`, `MaxRecursion`, and the soft descriptor limit. |
| Idle sessions | With one worker, both daemons answered an independent client's ping while a session waited between commands. The session then resumed with its next request ID. |
| Database lifecycle | Validates the configured generation before listening. Supports explicit reload, `SIGUSR2`, and periodic `SelfCheck`. A failed reload preserves the active generation. |
| Logging | Supports a local log, size limits, rotation, and reopening on `SIGHUP`. Enabling syslog or Prelude fails during startup. |
| Engine settings | Accepts the Debian package values for incomplete scanner stages and lists these settings in the startup log. Hash misses produce an incomplete-scan error. |
| Unsupported policy | Unknown directives, the sample `Example` marker, unsupported engine settings, and external `VirusEvent` commands prevent startup. |

The inventory includes obsolete aliases, development options, and on-access client settings.
The pinned parser accepts additional legacy directives, including `AllowSupplementaryGroups`, `ArchiveMaxFiles`, and `ScanOnAccess`.
These legacy spellings and alternate engine policies still need individual compatibility tests.
Full object scanning and bytecode execution have separate qualification tasks. [Object handling](https://github.com/yavosh/barnacle/issues/9) · [Bytecode](https://github.com/yavosh/barnacle/issues/4) · [Upstream options](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/common/optparser.c)

## Database coverage

All three archive signatures passed `sigtool --info`. Their header functionality level is 90.
The [pinned SHA-256 digests](whole-file-hashes.md#reproduce-the-pinned-generation) identify the exact input bytes.

| Archive | Generation | Signatures in header | File members |
| --- | ---: | ---: | ---: |
| main.cvd | 63 | 3,287,027 | 12 |
| daily.cvd | 28187 | 355,874 | 25 |
| bytecode.cvd | 339 | 80 | 87 |

These counts include one COPYING file per archive. Bytecode contains 85 CBC members. Member counts differ from header signature counts.
The local fixture profile uses harmless custom hashes. The official profile runs with the pinned generation.
Use each profile's recorded database digests when comparing results.

| Family and extensions | Archives containing these members | Coverage and next test |
| --- | --- | --- |
| Whole-file hashes, `.hdb .hsb` | main, daily | The offline matcher compares exact sizes, wildcards, miss behavior, duplicates, and competing names with stock. |
| PUA-only hashes and rules, `.hdu .hsu .mdu .msu .ndu .ldu` | daily | The profile disables PUA. Test enabling the appropriate categories. [#10](https://github.com/yavosh/barnacle/issues/10) |
| Ignore names and file allowlists, `.ign .ign2 .fp .sfp` | daily has all four. Main has `.fp .sfp`. | Hash loading applies ignore entries. Test full-scan allowlist and competing-match precedence. [#10](https://github.com/yavosh/barnacle/issues/10) |
| Extended patterns, `.ndb` | main, daily | 101,744 active rules compile. Raw object comparisons cover offsets, ranges, and match counts. [Body signature coverage](body-patterns.md) |
| Logical patterns, `.ldb` | main, daily | Local patterns, counts, and PCRE use scan-object context. Official feed coverage remains open. [#3](https://github.com/yavosh/barnacle/issues/3) |
| PE section hashes, `.mdb .msb` | main, daily | Exercise benign sections and signed-file metadata. [#10](https://github.com/yavosh/barnacle/issues/10) |
| Container metadata and certificates, `.cdb .crb` | main, daily | Exercise nested object metadata and certificate decisions. [#9](https://github.com/yavosh/barnacle/issues/9) · [#10](https://github.com/yavosh/barnacle/issues/10) |
| PE icons, `.idb` | daily | Local icon-group rules use PE resources and preserve rule precedence. [PE icon comparisons](../tests/logical_pe_icons.rs) |
| URL rules, `.pdb .wdb` | daily | Exercise benign URL fixtures. [#10](https://github.com/yavosh/barnacle/issues/10) |
| File types and dynamic settings, `.ftm .cfg` | daily | Check type reclassification at each layer and feature selection. [#9](https://github.com/yavosh/barnacle/issues/9) · [#10](https://github.com/yavosh/barnacle/issues/10) |
| Bytecode, `.cbc` | bytecode | The interpreter compiles 73 of 82 eligible signed modules. Local controls compare generated children, scan limits, icon-qualified triggers, PDF phases, and `PE_ALL` ordering against stock. Signed-feed activation remains open. [Bytecode requirements](bytecode.md) · [#4](https://github.com/yavosh/barnacle/issues/4) |
| Generation metadata, `.info` | main, daily, bytecode | Validate signed archives before activation. Exercise CVD and CLD update behavior. [#11](https://github.com/yavosh/barnacle/issues/11) |

The pinned loader also recognizes `.db .sdb .imp .zmd .rmd .gdb .cat .ioc .pwdb .cud` and build-dependent `.yar .yara`.
The frozen official archives contain none of these members. Track local-format qualification under [#10](https://github.com/yavosh/barnacle/issues/10).
[ClamAV 1.4.3 database loader](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/readdb.c) · [Signature formats](https://docs.clamav.net/manual/Signatures.html)

## Object handling coverage

The [dynamic module inventory](compatibility/engine-modules.txt) records the engine switches with the official feed.
The daemon's scan options and installed libraries also affect dispatch.
For example, the RAR switch is on. The pinned Debian image lacks the optional UnRAR interface.
ARM JIT, SWIZZOR, and the statistics module show as off in the dynamic settings.

| Handler group | Paired comparisons and remaining work |
| --- | --- |
| Raw, text, script, and HTML | Paired tests exercise HTML, script normalization, MIME, TNEF, and uuencoded attachments. [Text comparisons](../tests/object_text.rs) |
| Archives and installers | Tests cover compressed streams, archive order, NSIS, AutoIt EA05 and EA06, and ordinary InstallShield packages. Legacy InstallShield cabinets remain open. [Archive and installer coverage](object-handling.md#reference-handlers) |
| Executables | Tests cover PE resources, UPX 4.2.4 NRV PE32, ELF sections, Mach-O files, and Java classes in JARs. Other PE unpackers remain open. [Executable comparisons](object-handling.md#executable-containers) |
| Documents | Tests cover PDF, XDP, RTF, OLE2, Office XML, HWP, and OneNote. Excel comparisons cover picture entries, nested workbooks, and mixed Office extraction. VBA, XLM, and additional encryption cases remain open. [Document comparisons](object-handling.md#reference-handlers) · [Excel pictures](../tests/object_ole_xls.rs) |
| Media and disks | Tests cover image signature targets, WAVE, SWF, optical images, partition tables, HFS+, DMG, and XAR. Image heuristics and several disk layouts need further comparisons. [Media and disk coverage](object-handling.md#reference-handlers) |

Every remaining object handler needs a benign behavioral fixture under [#9](https://github.com/yavosh/barnacle/issues/9).
Each extracted object must retain its parent context and receive all eligible rules.
For the complete dispatch cases, see the [pinned scanner](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.3/libclamav/scanners.c).

## Reproduce the inventories

Run these commands inside the isolated Debian reference environment with the pinned packages installed.
Use only the oracle configuration and the verified databases.

```sh
mkdir -p /tmp/barnacle-options
sed -e 's|{root}|/oracle|g' -e 's|{port}|3310|g' docs/compatibility/oracle.conf.in \
  > /tmp/barnacle-options/clamd.conf
clamconf --config-dir=/tmp/barnacle-options | sed -n '/^Config file: clamd.conf$/,/^$/p' \
  | sed '1,2d;/^$/d' > /tmp/barnacle-options/actual.txt
diff -u docs/compatibility/clamd-options.txt /tmp/barnacle-options/actual.txt

printf 'reference probe\n' > /tmp/barnacle-options/sample.txt
clamscan --debug -d "$database_dir" /tmp/barnacle-options/sample.txt > /tmp/barnacle-options/scan.log 2>&1
sed -n -E 's/^LibClamAV debug: (Module .*|   \* Submodule .*)/\1/p' /tmp/barnacle-options/scan.log \
  > /tmp/barnacle-options/modules.txt
diff -u docs/compatibility/engine-modules.txt /tmp/barnacle-options/modules.txt

for name in main daily bytecode; do
  sigtool --info "$database_dir/$name.cvd" || exit 1
  sha256sum "$database_dir/$name.cvd"
  tail -c +513 "$database_dir/$name.cvd" | tar -tzf -
done
```
