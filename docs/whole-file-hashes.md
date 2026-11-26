# Match whole-file hashes offline

Build each generation from trusted, extracted hash databases. Keep the databases and index outside Git.
Use the same source generation, database order, functionality level, and signature provenance as the reference clamd.

```sh
cargo build --locked --release
target/release/barnacle build /tmp/fixture.bhi fixture.hdb fixture.hsb
target/release/barnacle scan memory /tmp/fixture.bhi example.bin
target/release/barnacle scan pread /tmp/fixture.bhi example.bin
target/release/barnacle scan mmap /tmp/fixture.bhi example.bin
```

The build command prints an inventory and writes a checksummed index to a new path.
Use `--official` only for inputs extracted from a verified official database.
For official inputs, include the generation's `.ign` and `.ign2` files.
Supply daily database members first, followed by main database members. Preserve their order within each archive.
The default uses local signature names with the reference engine's unofficial suffix.
The default functionality level is 213. Pass `--flevel LEVEL` to select another level.

A scan reads the input once. Use `-` as the input path to read from standard input.
A match prints `matched`, a tab, and the reported signature. A miss prints `unmatched`.
A successful lookup exits with status zero for either outcome. A failure reports an error and exits with nonzero status.
Only a complete engine scan can decide whether to deliver an upload.

To look up a precomputed digest, run the following command with a hexadecimal digest and a decimal file size in bytes.

```sh
target/release/barnacle lookup pread /tmp/fixture.bhi sha256 "$digest" "$size"
```

## Reproduce the pinned generation

The reference uses Debian 13 `clamav-daemon` 1.4.3+dfsg-1, functionality level 213, and disabled PUA detection.
Start with the verified FreshClam snapshot. The build helper checks all three archive digests before publishing an index.

| Archive | Version | SHA-256 |
| --- | ---: | --- |
| main.cvd | 63 | `0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365` |
| daily.cvd | 28187 | `423f7774182bfbc82b50c7796c68a93f8b1817ef7ebbc88d7def444bc2c8f35b` |
| bytecode.cvd | 339 | `6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb` |

The archived Soenneker.Clamav.Definitions 11.0.165 NuGet package contains all three pinned files.
Extract the CVD files into a new directory. Check their SHA-256 digests against the table.
[Archived NuGet package](https://api.nuget.org/v3-flatcontainer/soenneker.clamav.definitions/11.0.165/soenneker.clamav.definitions.11.0.165.nupkg)

```sh
snapshot_dir=$(mktemp -d)
curl --fail --location --output "$snapshot_dir/source.nupkg" \
  https://api.nuget.org/v3-flatcontainer/soenneker.clamav.definitions/11.0.165/soenneker.clamav.definitions.11.0.165.nupkg
for archive in main daily bytecode; do
  unzip -p "$snapshot_dir/source.nupkg" "contentFiles/any/any/Resources/clamav-database/$archive.cvd" > "$snapshot_dir/$archive.cvd"
done
(cd "$snapshot_dir" && sha256sum main.cvd daily.cvd bytecode.cvd)
```

```sh
python3 scripts/build_pinned_hash_index.py target/release/barnacle "$snapshot_dir" /tmp/pinned.bhi
cargo test --locked --test hash_reference
```

The first command reports eligible records before duplicate resolution. The following counts come from the pinned generation.

| Algorithm | Exact size | Wildcard size |
| --- | ---: | ---: |
| MD5 | 541,749 | 11 |
| SHA-1 | 3 | 0 |
| SHA-256 | 226 | 2 |
| Total | 541,978 | 13 |

Of 541,992 positive records, one matched an ignore entry. All other records passed the functionality-level check.
The 541,991 eligible records included 1,520 redundant records. The index contains 540,471 distinct keys and uses 40,377,715 bytes.
The build also counted 24 ignore entries, 40 disabled PUA records, and 998 allowlist records.
Allowlist handling, other rule families, and the full engine's object filters belong to later scan stages.
A raw hash match can occur on a small file that clamd skips.

## Index lifetime

The builder writes a temporary file in the destination directory, flushes it, and publishes it read-only.
Choose a new destination for each generation. Each open index keeps its generation for its lifetime.
All backends validate the checksum, sorted records, offsets, and names before accepting lookups.

- `memory` loads the encoded records and names into process memory.
- `pread` uses a directory in memory to select a block, then reads that block at its file offset.
- `mmap` reads the same blocks through a read-only file mapping.

Only map files managed as immutable generations. Modifying or truncating an open mapped inode can invalidate the mapping.
Replacing a directory entry with a different inode preserves the existing mapping.
