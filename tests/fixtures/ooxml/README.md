# Office package fixtures

These four macro-free documents contain the same inventory image. The image is [dots.png](../xls/dots.png).

Pandoc 3.12.1 generated the DOCX, PPTX, and ODT from [report.md](report.md). To reproduce their document contents, run these commands in a scratch directory.

```sh
cp "$fixtures/ooxml/report.md" report.md
cp "$fixtures/xls/dots.png" chart.png
export SOURCE_DATE_EPOCH=1735689600
pandoc report.md -o report.docx
pandoc report.md -o report.pptx
pandoc report.md -o report.odt
```

The XLSX uses `rust_xlsxwriter` 0.92.4 and the same `chart.png`. The workbook contains the following worksheet.

```rust
use rust_xlsxwriter::{Image, Workbook, XlsxError};

fn main() -> Result<(), XlsxError> {
    let mut book = Workbook::new();
    let ws = book.add_worksheet();
    ws.set_name("Inventory")?;
    ws.write_string(0, 0, "Quarterly inventory")?;
    ws.write_number(1, 0, 42)?;
    ws.insert_image(3, 0, &Image::new("chart.png")?)?;
    book.save("report.xlsx")
}
```

Pinned Debian clamd 1.4.3 classified the workbook's 867-byte `xl/styles.xml` as HTML at its `<tableStyles` element.
Its retained `nocomment.html` contained 879 bytes with MD5 `0a40ed6b0ea24f8929625d19592243fa`.
The local whole-file rule matched that view both directly and inside the workbook.

| File | SHA-256 |
| --- | --- |
| report.docx | `1d1d872ba471ca58e9739d11e4b221624cd0731d4fdd126120ecee3e4f700f3d` |
| report.odt | `988302912a9968299cfe2eb8de132bc30783ee68256aa2565ad35424583f2aa8` |
| report.pptx | `12f04ae119170f72f62f205bfa5354d48455200c2526dd334fba000560be64cc` |
| report.xlsx | `1e759cbde57612a029583440b5522e5f2e849211eb62d873d974cf9ca29fb4b6` |
