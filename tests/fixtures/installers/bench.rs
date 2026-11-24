//! Build inert benchmark carriers from locally compiled resource archives.
#[path = "../../common/pe.rs"]
mod pe;

use std::{
    env, fs,
    io::{self, Write},
    path::Path,
};

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let [command, directory] = args.as_slice() else {
        return Err(io::Error::other(
            "usage: fixture prepare|resources DIRECTORY",
        ));
    };
    let dir = Path::new(directory);
    if command == "prepare" {
        fs::create_dir_all(dir.join("db"))?;
        fs::write(dir.join("notes.nsi"), include_bytes!("notes.nsi"))?;
        fs::write(dir.join("second.txt"), include_bytes!("second.txt"))?;
        let mut report = fs::File::create(dir.join("first.txt"))?;
        for n in 0..16000 {
            writeln!(
                report,
                "Reference ledger entry {n}: product {}, quantity {}, zone {}.",
                n * 19 % 8009,
                n * 13 % 127,
                n * 7 % 43
            )?;
        }
    } else if command == "resources" {
        for codec in ["zlib", "bzip2", "lzma"] {
            let package = fs::read(dir.join(format!("{codec}-blocks.pkg")))?;
            let magic = b"\xef\xbe\xad\xdeNullsoftInst";
            let start = package
                .windows(magic.len())
                .position(|part| part == magic)
                .and_then(|position| position.checked_sub(4))
                .ok_or_else(|| io::Error::other("missing NSIS archive header"))?;
            let mut image = pe::benign_pe();
            image.extend(&package[start..]);
            fs::write(dir.join(format!("{codec}.sample")), image)?;
        }
    } else {
        return Err(io::Error::other("expected prepare or resources"));
    }
    Ok(())
}
