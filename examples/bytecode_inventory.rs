//! Report aggregate bytecode requirements for the pinned archive.
use barnacle::{PINNED_FLEVEL, bytecode::Inventory};
use std::fs::File;
use std::io;

fn main() -> io::Result<()> {
    let path = std::env::args_os().nth(1).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "usage: bytecode_inventory <bytecode.cvd>",
        )
    })?;
    let inventory = Inventory::from_archive(File::open(path)?, u64::from(PINNED_FLEVEL))?;

    println!("modules\t{}", inventory.modules);
    println!("unsupported formats\t{}", inventory.unsupported_formats);
    println!("outside engine window\t{}", inventory.outside_engine_window);
    println!("functions\t{}", inventory.functions);
    println!("instructions\t{}", inventory.instructions);
    for (format, count) in inventory.formats {
        println!("format\t{format}\t{count}");
    }
    for (hook, count) in inventory.hooks {
        let active = inventory
            .eligible_hooks
            .get(&hook)
            .copied()
            .unwrap_or_default();
        println!("hook\t{hook}\t{count}\t{active}");
    }
    for ((min, max), count) in inventory.engine_windows {
        println!("engine window\t{min}\t{max}\t{count}");
    }
    for opcode in inventory.opcodes {
        println!("opcode\t{opcode}");
    }
    for (id, name) in inventory.apis {
        println!("api\t{id}\t{name}");
    }
    Ok(())
}
