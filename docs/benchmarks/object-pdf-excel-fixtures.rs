#[test]
#[ignore = "writes passive benchmark inputs in the specified scratch directory"]
fn generate_pdf_excel_workloads() -> io::Result<()> {
    use std::{
        collections::HashMap,
        io::{Cursor, Read},
    };
    let root = std::path::PathBuf::from(
        std::env::var_os("BARNACLE_BENCH_FIXTURES").expect("set fixture directory"),
    );
    let write = |kind: &str, file: &[u8], child: &[u8]| -> io::Result<()> {
        let path = root.join(kind);
        fs::create_dir_all(path.join("db"))?;
        fs::write(path.join("input"), file)?;
        fs::write(
            path.join("db/reference.hdb"),
            hash("Reference", child).replace(":Lzw.", ":Workspace."),
        )?;
        Ok(())
    };
    let mut ledger = Vec::new();
    for row in 0..32768 {
        writeln!(
            ledger,
            "Receipt {row:05}, produce, quantity {:02}, price 2.45",
            row % 37
        )?;
    }
    let mut dictionary = HashMap::new();
    let mut words = vec![256];
    let mut prefix = u16::from(ledger[0]);
    for &b in &ledger[1..] {
        if let Some(&word) = dictionary.get(&(prefix, b)) {
            prefix = word;
        } else {
            words.push(prefix);
            if dictionary.len() == 4096 - 258 {
                words.push(256);
                dictionary.clear();
            } else {
                dictionary.insert((prefix, b), 258 + dictionary.len() as u16);
            }
            prefix = u16::from(b);
        }
    }
    words.extend([prefix, 257]);
    let encoded = codes(words, 1);
    let file = pdf(
        stream("", b"q Q\n"),
        stream("/Type /EmbeddedFile /Filter /LZWDecode", &encoded),
    );
    write("pdf", &file, &ledger)?;
    let source = std::fs::read("tests/fixtures/xls/dots.xls")?;
    let mut workbook = Vec::new();
    cfb::CompoundFile::open(Cursor::new(source))?
        .open_stream("Workbook")?
        .read_to_end(&mut workbook)?;
    let mut reconstructed =
        cfb::CompoundFile::create_with_version(cfb::Version::V3, Cursor::new(Vec::new()))?;
    reconstructed
        .create_stream("Workbook")?
        .write_all(&workbook)?;
    for name in ["/", "/Workbook"] {
        reconstructed.set_created_time(name, std::time::UNIX_EPOCH)?;
        reconstructed.set_modified_time(name, std::time::UNIX_EPOCH)?;
    }
    let xls = reconstructed.into_inner().into_inner();
    write("xls", &xls, &std::fs::read("tests/fixtures/xls/dots.png")?)?;
    println!(
        "ledger {} encoded {} PDF {} BIFF {} Excel {}",
        ledger.len(),
        encoded.len(),
        file.len(),
        workbook.len(),
        xls.len()
    );
    Ok(())
}
