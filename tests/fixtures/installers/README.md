# NSIS resource fixtures

Debian makensis 3.11-1 compiled notes.nsi with first.txt and second.txt.
The six binary files contain the NSIS archive starting at its four-byte flags field.
The Rust tests append that archive to a PE document with no entry point and a read-only data section.

To reproduce one fixture, run these commands from this directory with makensis 3.11-1 installed.

```sh
makensis -DOUTPUT=/tmp/notes.pkg -DCODEC=bzip2 -DOPTIONS=/SOLID notes.nsi
perl -0777 -ne 'binmode STDOUT; $i=index($_,"\xef\xbe\xad\xdeNullsoftInst"); die if $i<4; print substr($_,$i-4)' /tmp/notes.pkg > /tmp/bzip2-solid.bin
```

Use zlib, bzip2, or lzma for CODEC. Set OPTIONS to an empty string for independently compressed entries.
The test signatures match the original text files. The test compares ordinary extraction order, metadata, and limits with Debian clamd 1.4.3+dfsg-1.
