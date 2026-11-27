# Licensing

Barnacle's own code uses the [MIT License](../LICENSE). The copyright holder is "The Barnacle authors". [Decision](https://github.com/yavosh/barnacle/issues/17)

## Provenance

Barnacle reimplements the observable behavior of stock clamd in Rust. The repository contains no ClamAV source code.

- Differential tests compare Barnacle with pinned Debian clamd 1.4.3+dfsg-1. Expected results come from stock's replies, logs, and extracted files.
- Some documents cite ClamAV 1.4.3 source files as behavioral references. These cover daemon commands, the database loader, scan dispatch, and limits. [Compatibility matrix](compatibility-matrix.md) · [Object handling](object-handling.md)
- The UPX unpacker was written without reading ClamAV, UCL, or UPX source. It follows the NRV bit-stream format and stock's observed output. [#22](https://github.com/yavosh/barnacle/issues/22)

Some bytes must match stock exactly for compatibility:

- Replies follow the clamd protocol. Signature names come from the loaded databases.
- Built-in heuristic names, such as `Heuristics.Limits.Exceeded.MaxFileSize`, match stock.
- A rebuilt UPX image starts with the fixed 0xd0-byte DOS header and stub that stock writes. The stub contains the text "This file was created by ClamAV for internal use and should not be run. ClamAV - A GPL virus scanner - http://www.clamav.net". Barnacle keeps these bytes so that hash signatures on unpacked children match stock. The [decision in #17](https://github.com/yavosh/barnacle/issues/17) keeps them.

## Signature databases and indexes

- Releases do not include ClamAV databases. Operators download them with FreshClam. The official CVD archives use GPLv2, and each one includes a `COPYING` file.
- Barnacle builds its indexes from the operator's databases. Releases do not include generated indexes, because the indexes derive from the databases.
- Git contains no official databases and no generated indexes. Tests read pinned database generations from outside the repository. Test fixtures are harmless files with local signatures.
- Git keeps captured stock output as test evidence, such as the [effective clamd options](compatibility/clamd-options.txt).

## Third-party Rust dependencies

Every package in `Cargo.lock` offers a permissive license. The licenses include MIT, Apache-2.0, BSD-3-Clause, Zlib, and Unicode-3.0. `lzma-rust2`, `nsis`, and `sevenz-rust2` use Apache-2.0 only. `r-efi` also offers LGPL-2.1-or-later; Barnacle uses it under MIT or Apache-2.0.

Barnacle statically links PCRE2 10.46 through `pcre2-sys` 0.2.10.
The bindings use MIT. PCRE2 uses BSD-3-Clause with the PCRE2 exception. [Third-party notices](../THIRD-PARTY-NOTICES.md#pcre2-regular-expressions)

A binary release must include the license text and copyright notices of each dependency compiled into it. This includes the `NOTICE` files of Apache-2.0 packages. Check the licenses again whenever `Cargo.lock` changes:

```sh
cargo metadata --locked --format-version 1 \
  | jq -r '.packages[] | select(.name != "barnacle") | "\(.license)\t\(.name) \(.version)"' \
  | sort
```
