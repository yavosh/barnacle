# UPX fixtures

`ledger.c` is a harmless console program. It prints one ledger line and counts its digits.
Debian 13 (arm64) built and packed the fixtures with these tools:

- gcc-mingw-w64-i686 14.2.0-17+27
- upx-ucl 4.2.4-1.1

```sh
i686-w64-mingw32-gcc -O2 -s ledger.c -o ledger.exe
for method in nrv2b nrv2d nrv2e lzma; do
  upx -q -9 --$method ledger.exe -o ledger-$method.exe
done
i686-w64-mingw32-gcc -O2 -s -shared ledger.c -o ledger.dll
upx -q -9 --nrv2b ledger.dll -o ledger-dll-nrv2b.dll
x86_64-w64-mingw32-gcc -O2 -s ledger.c -o ledger64.exe
upx -q -9 --nrv2b ledger64.exe -o ledger64-nrv2b.exe
```

| File | Contents | SHA-256 |
| --- | --- | --- |
| `ledger.c` | Source | `79a6bd1718e44cfa23c5cb40cb3cf6ae73819aa44aca012a85b8439ad0ccf824` |
| `ledger.exe` | Unpacked PE32 | `aef1e9c96f20b2f6f5d39f119ec25359e81fec221948ca835834186d9d90c788` |
| `ledger-nrv2b.exe` | PE32, NRV2B | `44b99e7106b7f70c42e985bb161b022d19ebea430156cdbc3a9b021644a36a4e` |
| `ledger-nrv2d.exe` | PE32, NRV2D | `38d6ddf9188bc92d0575ab5583b7e35af6e703385e04e500c15b9b9795e5bd49` |
| `ledger-nrv2e.exe` | PE32, NRV2E | `db132424e2244f0695cb2f321a7cc7b9858386e21439396cb902a3e69f27f14d` |
| `ledger-lzma.exe` | PE32, LZMA | `1976971122153658f312e6a84a4be16d0094bee677e1a316bc18c0903f07f11c` |
| `ledger-dll-nrv2b.dll` | PE32 DLL, NRV2B | `91c0cd77958f0eca56115611bab64ab210cb881ff6673d21182f3c52ee7b1ecc` |
| `ledger64-nrv2b.exe` | PE32+, NRV2B | `ae6ce6854d7e0c4870804523eaf74559eff8eff3cafb51d86f9a10308f4a8ed9` |

Debian clamd 1.4.3 unpacks the three NRV executables to the same 69,632-byte image.
Its MD5 is `52bd7b6f5b3a2c728c73c46d48c1ac51`. Stock does not unpack the LZMA, DLL, or PE32+ fixtures.
[Comparisons](../../object_upx.rs)

## Provenance

The Barnacle decoders and image rebuild come from the NRV2B, NRV2D, and NRV2E bit-stream format.
They also follow stock's observed output: `clamscan --debug` logs and files kept with `--leave-temps`.
The authors did not consult ClamAV, UCL, or UPX source code.
