# AutoIt inventory guide

Aut2Exe 3.3.18.0 compiled this guide as an A3X file. The input uses three statements.

```autoit
FileInstall("notice.txt", @TempDir & "\notice.txt")
FileInstall("ledger.txt", @TempDir & "\ledger.txt")
ConsoleWrite("Inventory guide prepared." & @CRLF)
```

The notice contains one line. Generate the ledger as 4,096 LF-terminated ASCII rows.

```sh
printf '%s\n' 'Inventory terminal reference sheet, revision six.' > notice.txt
awk 'BEGIN { for (i=0; i<4096; i++) printf "Shelf %04d holds quarterly material.\n", i }' > ledger.txt
```

Compile from the directory containing `guide.au3`, `notice.txt`, and `ledger.txt`.

```text
Aut2exe_x64.exe /in guide.au3 /out guide.a3x /comp 4 /nopack
```

The portable AutoIt ZIP had SHA-256 `ceb666a993a9f62621c3a0d4ee602774b2e7f543de1f08ec0380632ee3f89beb`.
The committed A3X file has SHA-256 `63c2cb1f6993fa1522df5f2572a84c6fba5fcc25f85d4c81854b0b6c03b0eb57`.
Compiler timestamps can change the generated digest.

Compile `quantities.au3` as `quantities.a3x` with the same options and notice. It has SHA-256 `cb2c0007e9f5a8af3164729f51a767e4bddcf4a80ac79325bbb21ead3000274b`.

```autoit
Local $cartons = 42
Local $serial = 4294967297
Local $rate = 1.25
ConsoleWrite($cartons & " / " & $serial & " @ " & $rate & @CRLF)
FileInstall("notice.txt", @TempDir & "\notice.txt")
```

The Rust tests submit the A3X bytes directly and within inert PE and ZIP containers. They check the rendered script and the exact document bytes.
[AutoIt compiler documentation](https://www.autoitscript.com/autoit3/docs/intro/compiler.htm) · [Rust comparisons](../../object_autoit.rs)

## Legacy EA05 archives

`notice-ea05.a3x` contains the same 50-byte notice under one stored EA05 record with a zero-salt header.
The file's SHA-256 is `0a266ba9110ca3ba0869e27f72801f2cccae17d1eb4755ae27777b5972257111`.

`ledger-ea05.a3x` packs the 50-byte notice and 151,552-byte ledger, in that order, with the `Inventory label!` salt.
The file's SHA-256 is `f787f1057a636dd7247656afcd21542ab6109cd99880ef7aa11b812231128e5e`.
The two Rust fixture generators used AutoIt RS 0.1.2 for the archive keystream.
[AutoIt RS 0.1.2](https://crates.io/crates/autoit-rs/0.1.2)
