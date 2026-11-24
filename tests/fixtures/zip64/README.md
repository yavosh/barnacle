# ZIP64 fixtures

Each archive contains a receipt and the existing 103-byte blue PNG from `tests/fixtures/images/blue.png`.
The receipt repeats the ASCII line `The warehouse received four folders.` plus LF 256 times (9,472 bytes).
The member paths are `notes/receipt.txt` and `pix/blue.png`, in that order unless specified below.

| File | Writer | ZIP64 setting |
| --- | --- | --- |
| authored.zip | bsdtar 3.5.3, libarchive 3.7.4 | `--format=zip --options=zip:zip64` |
| stored.zip | bsdtar | `--format=zip --options=zip:zip64,zip:compression=store` |
| reversed.zip | bsdtar | `--format=zip --options=zip:zip64`, PNG listed first |
| control.zip | bsdtar | `--format=zip --options=zip:!zip64` |
| streamed.zip | Perl IO::Compress::Zip 2.102 | `Zip64 => 1, Stream => 1`, both members |
| Always.zip | Apache Commons Compress 1.27.1 | `Zip64Mode.Always`, both members |
| AlwaysWithCompatibility.zip | Apache Commons Compress 1.27.1 | `Zip64Mode.AlwaysWithCompatibility`, both members |
| mixed-true.zip | Apache Commons Compress 1.27.1 | `AlwaysWithCompatibility` for receipt, `AsNeeded` for PNG |
| mixed-false.zip | Apache Commons Compress 1.27.1 | `AsNeeded` for receipt, `AlwaysWithCompatibility` for PNG |

The Apache writer used a seekable file with `ZipArchiveOutputStream`.
It called `setUseZip64` before `putArchiveEntry` for each member.
The Perl writer opened a new member with `newStream`.
The tests read these files directly and require no external archive writer.
