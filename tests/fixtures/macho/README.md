# Universal Mach-O controls

Apple Clang assembled two relocatable objects from the following assembly. Both contain data and no instructions.

```asm
.section __DATA,__const
.asciz "Reference note stored in a relocatable data object."
```

```sh
xcrun clang -arch arm64 -c notes.s -o arm64.o
xcrun clang -arch x86_64 -c notes.s -o x86_64.o
xcrun lipo -create arm64.o x86_64.o -output ordinary.o
xcrun lipo -fat64 -create arm64.o x86_64.o -output wide.o
```

The separate ELF control contains one populated data section. It pins whole-file and section-relative matches under both `ScanELF` settings.

```asm
.section .rodata
.ascii "A data-only ELF section for the scanner."
```

```sh
xcrun clang -target x86_64-unknown-linux-gnu -c notes-elf.s -o elf.o
```

The checked-in files use gzip. The Rust comparisons expand them before scanning. [Tests](../../object_macho.rs)
