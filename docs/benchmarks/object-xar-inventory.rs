use std::fs::File;
use std::io::{self, BufWriter, Write};

fn main() -> io::Result<()> {
    for (name, size, namespaced) in [
        ("small", 4, true),
        ("large", 4096, true),
        ("plain", 4096, false),
    ] {
        let mut out = BufWriter::new(File::create(format!("{name}.xml"))?);
        let prefix = if namespaced { "inv:" } else { "" };
        let binding = if namespaced {
            " xmlns:inv=\"urn:inventory\""
        } else {
            ""
        };
        writeln!(out, "<{prefix}catalog{binding}>")?;
        for index in 0..size {
            writeln!(
                out,
                "<{prefix}part id=\"P-{index:04}\">Paper folders, box {index}</{prefix}part>"
            )?;
        }
        writeln!(out, "</{prefix}catalog>")?;
    }
    Ok(())
}
