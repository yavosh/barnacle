#[test]
#[ignore = "generates the mail benchmark in a scratch directory"]
fn generate_mail_workloads() -> io::Result<()> {
    use std::fmt::Write as _;
    let root = PathBuf::from(std::env::var_os("BARNACLE_BENCH_FIXTURES").unwrap());
    let mut ledger = String::from("Receipt,Department,Quantity\n");
    for i in 0..16_384 {
        writeln!(
            ledger,
            "R-{i:06},Inventory-{:02},{}",
            i % 31,
            (i * 17) % 10000
        )
        .unwrap();
    }
    let rules = hash("Reference", ledger.as_bytes())?.replace(":Fwd.", ":Workspace.");
    let save = |name: &str, input: &[u8]| -> io::Result<()> {
        let dir = root.join(name);
        fs::create_dir_all(dir.join("db"))?;
        fs::write(dir.join("db/work.hdb"), &rules)?;
        fs::write(dir.join("input"), input)
    };

    let encoded = b64(ledger.as_bytes());
    let wrapped = encoded
        .as_bytes()
        .chunks(76)
        .map(|line| std::str::from_utf8(line).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    let message = inner().replace(&b64(RECEIPT.as_bytes()), &wrapped).replace(
        "Attached receipt.\n",
        &format!("The attached note follows.\n{UU}Please keep the receipt.\n"),
    );
    let forward =
        String::from_utf8(forwarded_attachment(message.as_bytes(), "8bit", true)).unwrap();
    save("lf", forward.as_bytes())?;
    save("crlf", forward.replace('\n', "\r\n").as_bytes())?;

    for encoding in ["8bit", "quoted-printable"] {
        let message = format!(
            "From: receipts@example.invalid\nSubject: Monthly ledger\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=ledger\n\n--ledger\nContent-Type: text/csv; name=ledger.csv\nContent-Transfer-Encoding: {encoding}\n\n{ledger}--ledger--\n"
        );
        save(encoding, message.replace('\n', "\r\n").as_bytes())?;
    }
    Ok(())
}
