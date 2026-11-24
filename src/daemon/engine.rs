//! One immutable database generation, shared by all commands in an active scan.
mod cvd;
mod raw;

use super::Config;
use barnacle::body::BodyIndex;
use barnacle::index::{self, Index};
use barnacle::objects::{self, Limit, Options, Snapshot, Verdict};
use barnacle::{Feed, FileHashes, IgnoreSet, PINNED_FLEVEL, hash_reader};
use nix::libc;
use std::ffi::CStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn open_database(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid(format!(
            "expected a regular database: {}",
            path.display()
        )));
    }
    Ok(file)
}

#[derive(Eq, PartialEq)]
struct Source {
    path: PathBuf,
    inode: u64,
    device: u64,
    length: u64,
    changed: (i64, i64),
    modified: (i64, i64),
}

impl Source {
    fn new(path: PathBuf, m: &fs::Metadata) -> Self {
        Self {
            path,
            inode: m.ino(),
            device: m.dev(),
            length: m.len(),
            changed: (m.ctime(), m.ctime_nsec()),
            modified: (m.mtime(), m.mtime_nsec()),
        }
    }

    fn copy_to(&self, destination: &Path) -> io::Result<()> {
        let mut input = open_database(&self.path)?;
        let mut output = File::create_new(destination)?;
        let consistent = |m: fs::Metadata| Self::new(self.path.clone(), &m) == *self;
        if !consistent(input.metadata()?)
            || io::copy(
                &mut (&mut input).take(self.length.saturating_add(1)),
                &mut output,
            )? != self.length
            || !consistent(input.metadata()?)
        {
            return Err(invalid(format!(
                "{} changed while loading",
                self.path.display()
            )));
        }
        Ok(())
    }
}

fn extension(path: &Path) -> String {
    path.extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn sources(config: &Config) -> io::Result<Vec<Source>> {
    let mut inputs = Vec::new();
    for item in fs::read_dir(&config.database_directory)? {
        let path = item?.path();
        let ext = extension(&path);
        if !matches!(
            ext.as_str(),
            "db" | "hdb"
                | "hsb"
                | "hdu"
                | "hsu"
                | "fp"
                | "sfp"
                | "ign"
                | "ign2"
                | "cvd"
                | "cld"
                | "cud"
                | "crb"
                | "mdb"
                | "msb"
                | "imp"
                | "mdu"
                | "msu"
                | "ndb"
                | "ndu"
                | "ldb"
                | "ldu"
                | "cbc"
                | "sdb"
                | "zmd"
                | "rmd"
                | "cfg"
                | "info"
                | "wdb"
                | "pdb"
                | "gdb"
                | "ftm"
                | "idb"
                | "cdb"
                | "cat"
                | "ioc"
                | "yar"
                | "yara"
                | "pwdb"
        ) {
            continue;
        }
        if config.official_database_only
            && !matches!(ext.as_str(), "cvd" | "cld" | "ign" | "ign2")
            && !path.ends_with("daily.cfg")
            && !path.ends_with("local.gdb")
        {
            continue;
        }
        let m = fs::metadata(&path)?;
        if !m.is_file() {
            return Err(invalid(format!(
                "expected a regular database: {}",
                path.display()
            )));
        }
        inputs.push(Source::new(path, &m));
    }
    // clamd retains readdir order among databases with the same load priority.
    inputs.sort_by_key(|s| match extension(&s.path).as_str() {
        "ign" | "ign2" => 0,
        _ if s.path.ends_with("daily.cvd") => 1,
        _ => 2,
    });
    Ok(inputs)
}

pub(super) struct Detection {
    pub name: String,
    pub hashes: Option<FileHashes>,
}

pub(super) enum ScanResult {
    Found(Detection),
    Incomplete,
    Skipped,
}

pub(super) struct Generation {
    sources: Vec<Source>,
    index: Index,
    body: BodyIndex,
    temporary_directory: PathBuf,
    version: String,
    scan_limit: u64,
    objects: Options,
    scan_time: Duration,
    partial_only: bool,
    needs_hashes: bool,
    has_hash_rules: bool,
}

fn daily_version() -> io::Result<String> {
    let stamp: libc::time_t = cvd::DAILY_TIMESTAMP as _;
    let mut local = std::mem::MaybeUninit::uninit();
    let mut output = [0 as libc::c_char; 64];
    // SAFETY: the two writable buffers belong to this call. localtime_r initializes
    // local on success, and strftime writes a NUL-terminated string on success.
    unsafe {
        if libc::localtime_r(&stamp, local.as_mut_ptr()).is_null()
            || libc::strftime(
                output.as_mut_ptr(),
                output.len(),
                c"%a %b %e %T %Y".as_ptr(),
                local.as_ptr(),
            ) == 0
        {
            return Err(invalid("cannot format daily database time"));
        }
        Ok(format!(
            "ClamAV 1.4.3/28187/{}",
            CStr::from_ptr(output.as_ptr()).to_string_lossy()
        ))
    }
}

impl Generation {
    pub(super) fn load(config: &Config) -> io::Result<Self> {
        let inputs = sources(config)?;
        let has_cvd = inputs.iter().any(|s| extension(&s.path) == "cvd");
        if has_cvd
            && !cvd::PINNED
                .iter()
                .all(|(name, _, _)| inputs.iter().any(|s| s.path.ends_with(name)))
        {
            return Err(invalid(
                "expected verified daily.cvd, main.cvd and bytecode.cvd together",
            ));
        }
        if let Some(days) = config.fail_if_cvd_older_than {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_secs();
            if !has_cvd || now.saturating_sub(cvd::DAILY_TIMESTAMP) > days.saturating_mul(86_400) {
                return Err(invalid("database exceeds FailIfCvdOlderThan"));
            }
        }
        if config.detect_pua && has_cvd {
            return Err(invalid("PUA database matching is unsupported"));
        }
        let temp = tempfile::tempdir_in(&config.temporary_directory)?;
        let local_dir = temp.path().join("local");
        fs::create_dir(&local_dir)?;
        let mut paths = Vec::new();
        for source in &inputs {
            let path = &source.path;
            let ext = extension(path);
            match ext.as_str() {
                "cvd" => cvd::extract(path, temp.path(), &mut paths)?,
                "hdu" | "hsu" | "mdu" | "msu" | "ndu" | "ldu" if !config.detect_pua => continue,
                "hdb" | "hsb" | "ndb" | "ndu" | "ign" | "ign2" | "fp" | "sfp" => {
                    let output =
                        local_dir.join(path.file_name().expect("directory entry has a name"));
                    source.copy_to(&output)?;
                    paths.push((output, false));
                }
                _ => return Err(invalid(format!("unsupported database: {}", path.display()))),
            }
        }
        let (body_paths, hash_paths): (Vec<_>, Vec<_>) = paths
            .iter()
            .map(|(p, official)| (p.as_path(), *official))
            .partition(|(p, _)| matches!(extension(p).as_str(), "ndb" | "ndu"));
        let (mut feed, ignores) = if hash_paths.is_empty() && !body_paths.is_empty() {
            (Feed::default(), IgnoreSet::default())
        } else {
            Feed::load_sources_with_ignores(&hash_paths, PINNED_FLEVEL)?
        };
        let partial_only = has_cvd || feed.inventory.iter().any(|i| i.outside_matcher > 0);
        let has_hash_rules = !feed.rules.is_empty();
        let needs_hashes = (!partial_only && has_hash_rules) || config.extended_detection_info;
        let db = temp.path().join("index.bhi");
        index::build(&db, &mut feed.rules)?;
        drop(feed);
        let index = Index::open_pread(&db)?;
        // Each body source is a private copy in this generation's temporary directory.
        // Release its pages when parsing finishes, before building the search automata.
        let body = BodyIndex::load_with(&body_paths, PINNED_FLEVEL, &ignores, |path| {
            let file = File::open(path)?;
            fs::remove_file(path)?;
            Ok(file)
        })?;
        if inputs != sources(config)? {
            return Err(invalid("database changed while loading"));
        }
        let scan_limit = [config.objects.max_file_size, config.objects.max_scan_size]
            .into_iter()
            .filter(|&n| n != 0)
            .min()
            .unwrap_or(u64::MAX);
        let mut objects = config.objects.clone();
        objects.scan_normalized_script = body.needs_normalized_script();
        objects.map_normalized_script = body.needs_normalized_script_map();
        Ok(Self {
            sources: inputs,
            index,
            body,
            temporary_directory: config.temporary_directory.clone(),
            scan_limit,
            objects,
            scan_time: config.max_scan_time,
            partial_only,
            needs_hashes,
            has_hash_rules,
            version: if has_cvd {
                daily_version()?
            } else {
                "ClamAV 1.4.3".into()
            },
        })
    }

    pub(super) fn version(&self) -> &str {
        &self.version
    }

    pub(super) fn changed(&self, config: &Config) -> io::Result<bool> {
        Ok(self.sources != sources(config)?)
    }

    #[cfg(test)]
    fn scan(&self, reader: impl Read) -> io::Result<Option<Detection>> {
        Ok(match self.scan_checked(reader, || Ok(()))? {
            ScanResult::Found(hit) => Some(hit),
            ScanResult::Incomplete | ScanResult::Skipped => None,
        })
    }

    pub(super) fn scan_checked(
        &self,
        reader: impl Read,
        mut alive: impl FnMut() -> io::Result<()>,
    ) -> io::Result<ScanResult> {
        // clamd receives the upload before starting the engine's scan timer.
        let root_limit = self.objects.max_file_size;
        let read_limit = if root_limit == 0 {
            u64::MAX
        } else {
            root_limit.saturating_add(1)
        };
        let mut input = ScanInput {
            reader: reader.take(read_limit),
            object: (!self.partial_only).then(|| Snapshot::new(&self.temporary_directory)),
            capture_left: self.scan_limit,
            check: &mut alive,
        };
        let (size, hashes) = if self.needs_hashes {
            let hashes = hash_reader(&mut input)?;
            (hashes.size, Some(hashes))
        } else {
            (io::copy(&mut input, &mut io::sink())?, None)
        };
        (input.check)()?;
        if root_limit != 0 && size > root_limit {
            return Ok(self.limit_result(Limit::MaxFileSize, None));
        }
        if size > self.scan_limit {
            return Ok(self.limit_result(Limit::MaxScanSize, hashes));
        }
        // The pinned engine skips files of five bytes or less. Unimplemented
        // allowlists and other official matchers can suppress or supersede a hash.
        if size <= 5 {
            return Ok(ScanResult::Skipped);
        }
        if self.partial_only || size > i32::MAX as u64 {
            return Ok(ScanResult::Incomplete);
        }
        let object = input
            .object
            .expect("active matcher owns an object snapshot");
        let deadline = (!self.scan_time.is_zero())
            .then(|| Instant::now().checked_add(self.scan_time))
            .flatten();
        let mut expired = false;
        let verdict = object.with_bytes(|bytes| {
            objects::scan(
                bytes,
                &self.objects,
                &self.temporary_directory,
                |obj, check| {
                    let header = &obj.bytes[..obj.bytes.len().min(raw::HEADER_SIZE)];
                    let eligible = obj.normalized
                        || obj.handled_format
                        || raw::eligible(header, obj.layer.file_type);
                    if !eligible && !obj.context.is_valid_pe() {
                        return Ok(Verdict::Incomplete);
                    }
                    if let Some(name) =
                        self.body
                            .first_match_checked(obj.bytes, obj.context, &mut *check)?
                    {
                        return Ok(Verdict::Found(name.to_owned()));
                    }
                    // The script buffer goes directly to the body matcher. HTML parser
                    // artifacts are files and also pass through whole-file matching.
                    if self.has_hash_rules && eligible && !obj.body_only {
                        let found = if obj.parents.is_empty() && !obj.normalized {
                            hashes
                                .as_ref()
                                .expect("hash rules require root digests")
                                .lookup(|a, d, s| self.index.lookup(a, d, s))?
                        } else {
                            self.index.match_bytes(obj.bytes, check)?
                        };
                        if let Some(name) = found {
                            return Ok(Verdict::Found(name));
                        }
                    }
                    Ok(Verdict::Miss)
                },
                || {
                    (input.check)()?;
                    if deadline.is_some_and(|when| Instant::now() >= when) {
                        expired = true;
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    Ok(())
                },
            )
        });
        if expired {
            return Ok(self.limit_result(Limit::MaxScanTime, hashes));
        }
        Ok(match verdict? {
            Verdict::Found(name) => ScanResult::Found(Detection { name, hashes }),
            Verdict::Incomplete | Verdict::Miss => ScanResult::Incomplete,
            Verdict::Skipped => ScanResult::Skipped,
        })
    }

    fn limit_result(&self, limit: Limit, hashes: Option<FileHashes>) -> ScanResult {
        if self.objects.alert_exceeds_max {
            ScanResult::Found(Detection {
                name: limit.signature(),
                hashes,
            })
        } else {
            ScanResult::Skipped
        }
    }
}

struct ScanInput<'a, R> {
    reader: R,
    object: Option<Snapshot>,
    capture_left: u64,
    check: &'a mut dyn FnMut() -> io::Result<()>,
}

impl<R: Read> Read for ScanInput<'_, R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        (self.check)()?;
        let n = self.reader.read(buffer)?;
        if let Some(object) = &mut self.object {
            if n as u64 > self.capture_left {
                self.object = None;
            } else {
                object.write_all(&buffer[..n])?;
                self.capture_left -= n as u64;
            }
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use barnacle::body::ObjectContext;
    use md5::{Digest, Md5};

    struct Fixture {
        root: tempfile::TempDir,
        config: Config,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            let dir = root.path().join("db");
            fs::create_dir(&dir).unwrap();
            let config = Config {
                database_directory: dir,
                temporary_directory: root.path().to_owned(),
                ..Config::default()
            };
            Self { root, config }
        }

        fn write(&self, name: &str, value: impl AsRef<[u8]>) {
            fs::write(self.config.database_directory.join(name), value).unwrap();
        }
    }

    fn rule(payload: &[u8], name: &str) -> String {
        let digest: String = Md5::digest(payload)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{digest}:{}:{name}\n", payload.len())
    }

    #[test]
    fn active_generation_selects_normalized_text_views() {
        let f = Fixture::new();
        let receipt = b"WAREHOUSE blue FOLDERS. ".repeat(6000);
        f.write(
            "receipt.hdb",
            rule(&receipt.to_ascii_lowercase(), "Receipt"),
        );
        let hash_only = Generation::load(&f.config).unwrap();
        f.write(
            "receipt.ndb",
            "Ignored:7:EOF-6:666f6c646572\nFuture:0:*:666f6c646572:255\nMail:4:*:666f6c646572\n",
        );
        f.write("receipt.ign2", "Ignored\n");
        f.write("optional.ndu", "Optional:7:*:666f6c646572\n");
        let filtered = Generation::load(&f.config).unwrap();
        f.write("receipt.ndb", "Generic:0:*:77617265686f757365\n");
        let generic = Generation::load(&f.config).unwrap();
        f.write("receipt.ndb", "Mapped:7:EOF-6:616273656e74\n");
        let mapped = Generation::load(&f.config).unwrap();

        for skipped in [hash_only, filtered] {
            assert!(!skipped.objects.scan_normalized_script);
            assert!(!skipped.objects.map_normalized_script);
            assert!(skipped.scan(receipt.as_slice()).unwrap().is_none());
        }
        assert!(generic.objects.scan_normalized_script);
        assert!(!generic.objects.map_normalized_script);
        assert_eq!(
            generic.scan(receipt.as_slice()).unwrap().unwrap().name,
            "Generic.UNOFFICIAL"
        );
        assert!(mapped.objects.scan_normalized_script);
        assert!(mapped.objects.map_normalized_script);
        assert_eq!(
            mapped.scan(receipt.as_slice()).unwrap().unwrap().name,
            "Receipt.UNOFFICIAL"
        );
    }

    #[test]
    fn reload_preserves_old_generation_and_applies_ignores_and_limits() {
        let mut f = Fixture::new();
        let bytes = b"raw binary payload";
        f.write("fixture.hdb", rule(bytes, "First"));
        let old = Generation::load(&f.config).unwrap();
        assert_eq!(old.version(), "ClamAV 1.4.3");
        assert_eq!(
            old.scan(&bytes[..]).unwrap().unwrap().name,
            "First.UNOFFICIAL"
        );
        assert!(!old.changed(&f.config).unwrap());
        f.write("fixture.ign2", "First\n");
        f.write("freshclam.dat", "metadata");
        assert!(old.changed(&f.config).unwrap());
        assert_eq!(
            old.scan(&bytes[..]).unwrap().unwrap().name,
            "First.UNOFFICIAL"
        );
        let new = Generation::load(&f.config).unwrap();
        assert!(new.scan(&bytes[..]).unwrap().is_none());
        assert!(new.scan(&b"unknown content"[..]).unwrap().is_none());
        fs::remove_file(f.config.database_directory.join("fixture.ign2")).unwrap();
        f.config.objects.max_file_size = bytes.len() as u64 - 1;
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&bytes[..])
                .unwrap()
                .is_none()
        );
        f.config.objects.max_file_size = bytes.len() as u64;
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&bytes[..])
                .unwrap()
                .is_some()
        );
        assert_eq!(f.root.path().read_dir().unwrap().count(), 1);
    }

    #[test]
    fn body_only_generation_hashes_for_extended_logs() {
        let mut fixture = Fixture::new();
        fixture.write("local.ndb", "Marker:0:*:616263646566\n");
        let scan = |config: &Config| {
            Generation::load(config)
                .unwrap()
                .scan(&b"abcdef"[..])
                .unwrap()
                .unwrap()
        };
        assert!(scan(&fixture.config).hashes.is_none());
        fixture.config.extended_detection_info = true;
        let digests = scan(&fixture.config).hashes.unwrap();
        assert_eq!(digests.md5_hex(), "e80b5017098950fc58aad83c8c14978e");
        assert_eq!(digests.size, 6);
    }

    #[test]
    fn invalid_body_record_identifies_the_source_and_preserves_the_loaded_rules() {
        let fixture = Fixture::new();
        let good = "Before:0:*:4261726e61636c65\n";
        fixture.write("local.ndb", good);
        let previous = Generation::load(&fixture.config).unwrap();
        fixture.write("local.ndb", format!("{good}Broken:0:*:GGGG\n"));
        let error = Generation::load(&fixture.config).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("local.ndb:2:"));
        assert_eq!(
            previous.scan(&b"Barnacle"[..]).unwrap().unwrap().name,
            "Before.UNOFFICIAL"
        );
    }

    #[test]
    fn competing_and_unsupported_results_remain_incomplete() {
        let f = Fixture::new();
        let raw = b"abcdef";
        let ignored = b"OggS harmless bytes";
        let archive = b"\x1f\x8b\x08 fake gzip fixture";
        f.write(
            "local.hdb",
            [
                rule(raw, "Local"),
                rule(ignored, "Ogg"),
                rule(archive, "Outer"),
                rule(b"short", "Tiny"),
            ]
            .concat(),
        );
        let db = Generation::load(&f.config).unwrap();
        assert_eq!(db.scan(&raw[..]).unwrap().unwrap().name, "Local.UNOFFICIAL");
        assert!(db.scan(&ignored[..]).unwrap().is_none());
        assert!(db.scan(&archive[..]).unwrap().is_none());
        assert!(db.scan(&b"short"[..]).unwrap().is_none());
        f.write("suppress.fp", rule(raw, "Suppressed"));
        assert!(
            Generation::load(&f.config)
                .unwrap()
                .scan(&raw[..])
                .unwrap()
                .is_none()
        );
        f.write("suppress.fp", "invalid allowlist record");
        assert!(Generation::load(&f.config).is_err());
        f.write("suppress.fp", rule(raw, "Suppressed"));
        f.write("extra.ldb", "different matcher");
        assert!(db.changed(&f.config).unwrap());
        assert!(Generation::load(&f.config).is_err());
    }

    #[test]
    fn archives_fail_closed_before_activation() {
        let f = Fixture::new();
        for (name, _, _) in cvd::PINNED {
            f.write(name, b"tampered archive");
        }
        assert!(
            Generation::load(&f.config)
                .err()
                .unwrap()
                .to_string()
                .contains("SHA-256")
        );
        let local = Fixture::new();
        local.write("daily.cld", b"unverified replacement");
        assert!(Generation::load(&local.config).is_err());
    }

    #[test]
    #[ignore = "set BARNACLE_CVD_DIR to the verified FreshClam snapshot"]
    fn verified_archives_coexist_with_local_sources() {
        let snapshot = PathBuf::from(std::env::var_os("BARNACLE_CVD_DIR").unwrap());
        let f = Fixture::new();
        for (name, _, _) in cvd::PINNED {
            std::os::unix::fs::symlink(snapshot.join(name), f.config.database_directory.join(name))
                .unwrap();
        }
        let bytes = b"local mixed generation";
        f.write("local.hdb", rule(bytes, "Mixed"));
        f.write(
            "local.ndb",
            "MixedBody:0:*:6c6f63616c206d697865642067656e65726174696f6e\n",
        );
        let db = Generation::load(&f.config).unwrap();
        assert!(db.version().starts_with("ClamAV 1.4.3/28187/"));
        let local = hash_reader(&bytes[..])
            .unwrap()
            .lookup(|a, d, s| db.index.lookup(a, d, s))
            .unwrap();
        assert_eq!(local.as_deref(), Some("Mixed.UNOFFICIAL"));
        // Stock loads 101,744 body signatures from these official archives at flevel 213.
        assert_eq!(db.body.rule_count(), 101_745);
        assert_eq!(
            db.body
                .first_match(bytes, &ObjectContext::raw(bytes))
                .unwrap(),
            Some("MixedBody.UNOFFICIAL")
        );
        assert!(db.scan(&bytes[..]).unwrap().is_none());
    }
}
