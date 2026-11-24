//! Generate equivalent HWPML order ledgers and the one expected UTF-8 attachment.
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

fn main() -> io::Result<()> {
    let dir = PathBuf::from(env::args_os().nth(1).expect("supply a scratch directory"));
    fs::create_dir_all(dir.join("db"))?;
    let mut utf8 = Vec::new();
    let mut windows = Vec::new();
    for order in 0..65_536 {
        let row = format!("Order {order:05} | item {:04} | price ", order * 19 % 8009);
        utf8.extend(row.bytes());
        windows.extend(row.bytes());
        utf8.extend("12 € | café\n".bytes());
        windows.extend(b"12 \x80 | caf\xe9\n");
    }
    fs::write(dir.join("ledger.utf8"), &utf8)?;
    for (label, data) in [("utf-8", utf8), ("windows-1252", windows)] {
        let mut doc = fs::File::create(dir.join(format!("{label}.xml")))?;
        doc.write_all(b"\xef\xbb\xbf")?;
        write!(
            doc,
            "<?xml version=\"1.0\" encoding=\"{label}\"?><HWPML><TAIL><BINDATASTORAGE><BINDATA Id=\"1\" Compress=\"false\">"
        )?;
        doc.write_all(&data)?;
        doc.write_all(b"</BINDATA></BINDATASTORAGE></TAIL></HWPML>")?;
    }
    Ok(())
}
