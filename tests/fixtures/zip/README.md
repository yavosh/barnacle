# Deflate64 ledger

Debian 7-Zip 25.01 created `ledger-deflate64.zip` from two ordinary text files.
The ledger repeats 1,500 rows twice. The Rust test generates the original 81,000 bytes and compares their whole-file signature.
The other member contains the text `ordinary archive attachment` and a final newline.

```sh
awk 'BEGIN { for (j=0;j<2;j++) for (i=0;i<1500;i++) printf "Report %04d: Unit %08d\n", i, (i * 65537) % 948283 }' > ledger.txt
printf 'ordinary archive attachment\n' > second.txt
chmod 644 ledger.txt second.txt
7z a -tzip -mm=Deflate64 -mx7 -mtm=off -mta=off -mtc=off ledger-deflate64.zip ledger.txt second.txt
```

The archive SHA-256 is `2d13d256a5ce7bf3e4337ca9e9f39a0ff302732fce93c85518f04b293ea0fa2a`.

## Mixed encryption

Info-ZIP created `mixed-encryption.zip` by adding a protected packing note followed by an ordinary accounting receipt.
The packing note contains `Ordinary packing note for the weekly office inventory.` and a newline.
The receipt contains `Quarterly statement from accounting.` with no final newline.
Both use the stored compression method. The fixture SHA-256 is `92098913570b0057a5c27fe57c2e55ef646515db2bffe2ef378833999ec1df50`.
