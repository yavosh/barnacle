# Openable PDF controls

qpdf 12.4.2 rewrote the repository's harmless `qpdf-object-stream.pdf` with classic xref tables.
The plain file contains the original 36-byte accounting statement.
The R4 fixture uses AES-128. The R5 and R6 fixtures use AES-256.
These three documents open with the default empty user password and permit extraction.
The two-attachment R6 document adds a 45-byte dispatch slip. A separate locked control requires a credential.
Each artifact stays fixed because qpdf generates new salts and encryption values when writing a file.
The stored control keeps both streams uncompressed. The restricted control permits opening and disallows extraction.
The CSV manifest uses qpdf’s attachment writer. Its Flate filter follows the nested attachment parameters.
The MIME fixture uses qpdf’s text/plain attachment option and an ordinary escaped PDF name.
The larger fixture contains a synthetic shipment table. The Rust test reproduces all 13,000 rows. qpdf compressed and encrypted the attachment.

The R2, R3, and R4 RC4 controls use the same 36-byte statement. qpdf created them from `ordinary.pdf` with classic cross-reference tables.
The R4 and R6 cleartext metadata controls also contain that statement. All five documents open with an empty user credential.

```sh
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 40 -- ordinary.pdf r2-rc4.pdf
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 128 --use-aes=n -- ordinary.pdf r3-rc4.pdf
qpdf --allow-weak-crypto --object-streams=disable --encrypt '' '' 128 --use-aes=n --force-V4 -- ordinary.pdf r4-rc4.pdf
qpdf --object-streams=disable --encrypt '' '' 128 --use-aes=y --cleartext-metadata -- ordinary.pdf r4-clear-metadata.pdf
qpdf --object-streams=disable --encrypt '' '' 256 --allow-insecure --cleartext-metadata -- ordinary.pdf r6-clear-metadata.pdf
```

`r6-flate-hex.pdf` and `r6-identity.pdf` are Rust-authored controls using the qpdf R6 security metadata.
The first uses Flate followed by ASCIIHex and yields the 36-byte note.
The second uses direct `Crypt` with `Identity`. Stock passes the same note with its trailing LF.
`r6-explicit-eff.pdf` uses `/EFF /StdCF` for its receipt. Stock, qpdf, and Poppler recover the same 52 bytes.
`r6-stored-mime.pdf` uses the same explicit default with an uncompressed receipt. Stock scans its 81 physical stream bytes.
`r6-explicit-name.pdf` selects a named crypt filter on its receipt and page. Stock scans 96 bytes of the stored page stream.

The packed controls use qpdf 12.4.2 with cross-reference and object streams.
They retain the accounting statement and page text from the ordinary fixture.
The two-attachment control also contains the dispatch slip.

```sh
qpdf --allow-weak-crypto --object-streams=generate --encrypt '' '' 128 --use-aes=n -- ordinary.pdf r3-packed.pdf
qpdf --object-streams=generate --encrypt '' '' 128 --use-aes=y -- ordinary.pdf r4-packed.pdf
qpdf --object-streams=generate --encrypt '' '' 256 --allow-insecure --force-R5 -- ordinary.pdf r5-packed.pdf
qpdf --object-streams=generate --encrypt '' '' 256 --allow-insecure -- ordinary.pdf r6-packed.pdf
qpdf --object-streams=generate --encrypt '' '' 256 --allow-insecure --extract=n -- ordinary.pdf r6-restricted-packed.pdf
qpdf --compress-streams=n --object-streams=generate --encrypt '' '' 256 --allow-insecure -- ordinary.pdf r6-stored-packed.pdf
qpdf --object-streams=generate --decrypt two.pdf two-plain-packed.pdf
qpdf --object-streams=preserve --encrypt '' '' 256 --allow-insecure -- two-plain-packed.pdf r6-two-packed.pdf
```

The Rust test compacts the object-stream type name without shifting any offsets.
Stock reads packed page dictionaries only with that spelling in these controls.
The stored control exposes its ciphertext. The compressed cross-reference control exposes the inflated predictor rows.

The Rust-authored `r6-packed-classic.pdf` adds an object stream before the page and attachment.
It keeps the R6 encryption dictionary and uses a classic cross-reference table.
Its packed member contains a 65-byte inventory label.

`r6-packed-large-carrier.pdf` adds an 8,200-row shipment ledger before that label.
The encrypted carrier expands to 174,576 bytes. The test leaves 141 scan bytes for eligible objects.
Both Rust-authored files retain the page and statement from `r6.pdf`.

The LZW controls use a 36-byte LZW encoding of the accounting statement with 9-bit codes.
`lzw.pdf` writes `/Type /EmbeddedFile` before `/Filter /LZWDecode`. `lzw-late.pdf` reverses that order.
Stock flags the attachment only in `lzw.pdf`, so it skips the LZW-only attachment in `lzw-late.pdf`.
`hex-lzw.pdf` applies `[/ASCIIHexDecode /LZWDecode]` to the same statement.
Each file also has a DCT image XObject whose 33-byte payload is a JPEG start marker, a comment, and an end marker.

```sh
qpdf --stream-data=preserve --object-streams=disable --allow-weak-crypto --encrypt '' '' 128 --use-aes=n -- hex-lzw.pdf r3-hex-lzw.pdf
qpdf --stream-data=preserve --object-streams=disable --encrypt '' '' 128 --use-aes=y -- hex-lzw.pdf r4-hex-lzw.pdf
qpdf --stream-data=preserve --object-streams=disable --encrypt '' '' 256 --allow-insecure -- hex-lzw.pdf r6-hex-lzw.pdf
qpdf --stream-data=preserve --object-streams=disable --encrypt '' '' 256 --allow-insecure -- lzw.pdf r6-lzw.pdf
```

qpdf sorts dictionary keys, so `r6-lzw.pdf` places the filter before the type. Stock skips its attachment.
Stock decodes the encrypted ASCIIHex and LZW chain. It scans each encrypted DCT image as ciphertext.
