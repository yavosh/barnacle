# Crate outlines

Apache POI HSSF 5.4.1 wrote `crate-outlines.xls`. Its only worksheet contains a text cell and three drawings of a rectangle.
The worksheet name is `Packing list`. The cell A1 contains `Crate outlines`.
The drawing uses WMF, EMF, and Macintosh PICT, in that order.

The 48-byte WMF sets the window extent and draws a rectangle. The 132-byte EMF contains a header, rectangle, and end record.
The 534-byte PICT includes 512 reserved bytes and a version-1 picture with one frame rectangle.
HSSF stores the WMF and EMF as zlib streams. It stores the PICT source bytes unchanged after the bitmap tag.
Pinned clamd selects 41 bytes for WMF, 72 for EMF, and the final 501 bytes for PICT.

The workbook SHA-256 is `37561d585c292f3bf52ab33d0c14c85721425ffcaa1efc9d65dc3ba422c29439`.
[Rust comparisons](../../object_ole_xls.rs) · [OfficeArt picture records](https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-odraw/c67b883b-8136-4e91-a1a3-2981d16e934f)
