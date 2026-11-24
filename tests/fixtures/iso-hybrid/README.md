# Hybrid ISO installation guide

The images contain a notice, a card in a subdirectory, and a FAT12 recovery volume with a text label.
The El Torito catalog designates the appended FAT12 volume. The volume contains only the label.
The fixtures use Debian trixie xorriso 1.5.6, dosfstools, and mtools. Generate the uncompressed images in a temporary directory.

```sh
mkdir -p tree/manual
printf '%s\n' 'Quarterly installation guide for the inventory terminal.' > tree/NOTICE.TXT
printf '%s\n' 'Inventory terminal operator card, revision five.' > tree/manual/CARD.TXT
printf '%s\n' 'EFI recovery volume label for the inventory terminal.' > recovery.txt
truncate -s 1440K efi.img
mkfs.fat -F 12 -i 53434e31 -n RECOVERY efi.img
mcopy -i efi.img recovery.txt ::RECOVERY.TXT
xorriso -as mkisofs -R -J -no-pad -V OFFICE_GUIDE \
    -append_partition 2 0xef efi.img \
    -c boot.cat -e --interval:appended_partition_2:all:: -no-emul-boot \
    -o mbr.iso tree
xorriso -as mkisofs -R -J -no-pad -V OFFICE_GUIDE \
    -partition_offset 16 -appended_part_as_gpt -append_partition 2 0xef efi.img \
    -c boot.cat -e --interval:appended_partition_2:all:: -no-emul-boot \
    -o gpt.iso tree
gzip -n -9 mbr.iso gpt.iso
```

The original uncompressed fixtures have these digests. Timestamps and partition GUIDs can change on regeneration.

| Image | SHA-256 |
| --- | --- |
| `mbr.iso` | `58bf896769e343a46dc6ba221e0d4eee2f26c0ca433c77d5db93eb5989c15bcf` |
| `gpt.iso` | `f4f6a584c2c46eac422802d248eb8bd772aae5221ff3aefd0ab4dbc798f2f490` |

The appended volume begins at ISO sector 36 in the MBR image and sector 57 in the GPT image.
[Rust comparisons](../../object_iso.rs) · [xorrisofs manual](https://www.gnu.org/software/xorriso/man_1_xorrisofs.html)
