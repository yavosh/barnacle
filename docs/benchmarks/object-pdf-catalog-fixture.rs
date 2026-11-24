#[test]
#[ignore = "writes benchmark inputs into the specified directory"]
fn generate_catalog_workload() -> io::Result<()> {
    let root = std::path::PathBuf::from(std::env::var_os("BARNACLE_BENCH_FIXTURES").unwrap());
    let suffix = b") /OpenAction << /S /GoTo /D /Receipt >> >>\n";
    let mut catalog = b"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(notes.txt) 4 0 R] >> >> /Note (".to_vec();
    for row in 0..8192 {
        write!(
            catalog,
            "Receiving note {row:05}. Warehouse staff confirmed receipt against delivery line {:03}. ",
            row % 313
        )?;
    }
    let memo = b"Receiving confirmed the count of paper, pens, and folders. ";
    catalog.extend(
        memo.iter()
            .copied()
            .cycle()
            .take(1_048_617 - catalog.len() - suffix.len()),
    );
    catalog.extend(suffix);
    let page = format!("{PAGE_DICT}6 0 R >>\n");
    let sample = pack(
        true,
        true,
        [8, 6, 7],
        false,
        [
            &catalog,
            b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>\n",
            page.as_bytes(),
            b"<< /Type /Filespec /F (notes.txt) /EF << /F 7 0 R >> >>\n",
            b"<< /Title (Receiving report) >>\n",
        ],
        [1, 2, 3, 4, 5],
    )?;
    for (name, child) in [("packed", ATTACHMENT), ("catalog", catalog.as_slice())] {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("db"))?;
        fs::write(dir.join("input"), &sample.file)?;
        let md5 = barnacle::hash_reader(child)?.md5_hex();
        fs::write(
            dir.join("db/reference.hdb"),
            format!("{md5}:{}:Workspace.Reference\n", child.len()),
        )?;
    }
    Ok(())
}
