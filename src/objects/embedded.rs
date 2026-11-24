use super::{ChildSink, Handling, Options, archive, autoit, installer, iso, xdp};
use crate::body::ObjectContext;
use aho_corasick::AhoCorasick;
use std::io;
use std::sync::LazyLock;

const MAGICS: &[(&[u8], &str)] = &[
    (b"PK\x03\x04", "CL_TYPE_ZIP"),
    (b"MSCF\0\0\0\0", "CL_TYPE_MSCAB"),
    (b"7z\xbc\xaf\x27\x1c", "CL_TYPE_7Z"),
    (b"\x60\xea", "CL_TYPE_ARJ"),
    (b"Rar!\x1a\x07\0", "CL_TYPE_RAR"),
    (iso::PVD, "CL_TYPE_ISO9660"),
    (autoit::MAGIC, "CL_TYPE_AUTOIT"),
    (xdp::MAGIC, "CL_TYPE_XDP"),
    (installer::NSIS_MAGIC, "CL_TYPE_NULSFT"),
    (installer::ISHIELD_MAGIC, "CL_TYPE_ISHIELD_MSI"),
    (b"MZ", "CL_TYPE_MSEXE"),
];
static FINDER: LazyLock<AhoCorasick> = LazyLock::new(|| {
    AhoCorasick::new(MAGICS.iter().map(|(magic, _)| *magic)).expect("static archive file types")
});

pub(super) fn contents(bytes: &[u8], kind: &str, sink: &mut dyn ChildSink) -> io::Result<Handling> {
    match kind {
        "CL_TYPE_AUTOIT" => autoit::extract(bytes, sink),
        "CL_TYPE_ZIP" => archive::zip_single(bytes, sink),
        "CL_TYPE_NULSFT" | "CL_TYPE_ISHIELD_MSI" => installer::extract(kind, bytes, sink),
        "CL_TYPE_MSEXE" => Ok(if sink.child_bytes(bytes, None)? {
            Handling::Stopped
        } else {
            Handling::Complete
        }),
        _ => archive::extract(bytes, sink),
    }
}

pub(super) fn pe_carrier(kind: &str) -> bool {
    matches!(kind, "CL_TYPE_MSEXE" | "CL_TYPE_MSOLE2")
}

// A saved text leaf with an embedded map can consume additional file and byte budgets.
pub(super) fn possible_text_map(bytes: &[u8], sink: &mut dyn ChildSink) -> io::Result<bool> {
    for start in (0..bytes.len()).step_by(65536) {
        sink.check()?;
        let end = (start + 65536 + FINDER.max_pattern_len() - 1).min(bytes.len());
        if FINDER.find_iter(&bytes[start..end]).any(|m| {
            let kind = MAGICS[m.pattern().as_usize()].1;
            if kind == "CL_TYPE_ISO9660" {
                return iso::Layout::at(bytes, start + m.start()).is_some();
            }
            !matches!(
                kind,
                "CL_TYPE_MSEXE"
                    | "CL_TYPE_ISHIELD_MSI"
                    | "CL_TYPE_NULSFT"
                    | "CL_TYPE_RAR"
                    | "CL_TYPE_AUTOIT"
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(super) fn enabled(carrier: &str) -> bool {
    !matches!(
        carrier,
        "CL_TYPE_GZ"
            | "CL_TYPE_CPIO_OLD"
            | "CL_TYPE_ZIP"
            | "CL_TYPE_OLD_TAR"
            | "CL_TYPE_POSIX_TAR"
            | "CL_TYPE_PART_ANY"
    )
}

pub(super) fn extract(
    bytes: &[u8],
    carrier: &str,
    offsets: std::ops::Range<usize>,
    count: &mut usize,
    options: &Options,
    sink: &mut dyn ChildSink,
) -> io::Result<Handling> {
    let mut result = Handling::Unrecognized;
    let max_files = sink.max_files();
    let mut start = offsets.start;
    while start < offsets.end {
        sink.check()?;
        let end = start.saturating_add(65536).min(offsets.end);
        let overlap = FINDER.max_pattern_len() - 1;
        let window = &bytes[start..end.saturating_add(overlap).min(bytes.len())];
        for found in FINDER.find_iter(window) {
            let at = start + found.start();
            if at >= end {
                break;
            }
            let kind = MAGICS[found.pattern().as_usize()].1;
            if kind == "CL_TYPE_ISO9660" {
                if options.scan_archive
                    && *count < 10
                    && let Some((volume, layout)) = iso::Layout::at(bytes, at)
                {
                    *count += 1;
                    let status = sink.cooked_iso(volume, layout, volume.len() == bytes.len())?;
                    if matches!(status, Handling::Incomplete | Handling::Stopped) {
                        return Ok(status);
                    }
                }
                continue;
            }
            if kind == "CL_TYPE_XDP" {
                if options.scan_pdf
                    && xdp::can_retype(carrier)
                    && let stopped @ (Handling::Incomplete | Handling::Stopped) =
                        sink.embedded_xdp(bytes)?
                {
                    return Ok(stopped);
                }
                continue;
            }
            if !options.scan_archive && kind != "CL_TYPE_MSEXE" {
                continue;
            }
            let mut suffix = &bytes[at..];
            if kind == "CL_TYPE_AUTOIT" && !autoit::recognized(suffix) {
                continue;
            }
            if kind == "CL_TYPE_ISHIELD_MSI" && !installer::is_ishield(suffix) {
                continue;
            }
            if kind == "CL_TYPE_MSEXE"
                && !suffix
                    .get(62..suffix.len().min(306))
                    .is_some_and(|window| window.windows(4).any(|w| w == b"PE\0\0"))
            {
                continue;
            }
            if kind == "CL_TYPE_ARJ" && !matches!(suffix.get(9..11), Some([0..=2, 2])) {
                continue;
            }
            // Both counters include offset zero and same-type markers, which stock
            // records before deciding whether this carrier permits extraction.
            if kind == "CL_TYPE_ZIP" {
                if max_files != 0 && *count > max_files {
                    continue;
                }
            } else if *count >= 10 {
                continue;
            }
            *count += 1;
            if at == 0 || (kind == carrier && kind != "CL_TYPE_MSEXE") || kind == "CL_TYPE_RAR" {
                continue;
            }
            match kind {
                "CL_TYPE_AUTOIT" if carrier != "CL_TYPE_MSEXE" => continue,
                "CL_TYPE_NULSFT" if carrier == "CL_TYPE_MSEXE" && at > 4 => {
                    suffix = &bytes[at - 4..]
                }
                "CL_TYPE_NULSFT" => continue,
                "CL_TYPE_ISHIELD_MSI" if carrier != "CL_TYPE_MSEXE" => continue,
                "CL_TYPE_MSEXE"
                    if !options.scan_pe
                        || !pe_carrier(carrier)
                        || (options.max_embedded_pe != 0
                            && suffix.len() as u64 > options.max_embedded_pe)
                        || !ObjectContext::raw(suffix).is_valid_pe() =>
                {
                    continue;
                }
                _ => {}
            }
            sink.check()?;
            match sink.embedded_archive(kind, suffix)? {
                Handling::Stopped => return Ok(Handling::Stopped),
                Handling::Incomplete => return Ok(Handling::Incomplete),
                Handling::Complete if result == Handling::Unrecognized => {
                    result = Handling::Complete
                }
                _ => {}
            }
            if kind == "CL_TYPE_MSEXE" {
                // The suffix contains any subsequent architecture images. Stock visits them recursively.
                return Ok(Handling::Stopped);
            }
        }
        start = end;
    }
    Ok(result)
}
