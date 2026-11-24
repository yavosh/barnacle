use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use barnacle::objects::Options;
use regex::Regex;

pub(super) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Debug)]
pub(super) struct Config {
    pub database_directory: PathBuf,
    pub temporary_directory: PathBuf,
    pub official_database_only: bool,
    pub fail_if_cvd_older_than: Option<u64>,
    pub detect_pua: bool,
    pub stream_max_length: u64,
    pub objects: Options,
    pub max_scan_time: Duration,
    pub command_read_timeout: Duration,
    pub read_timeout: Duration,
    pub send_buf_timeout: Duration,
    pub max_directory_recursion: usize,
    pub follow_directory_symlinks: bool,
    pub follow_file_symlinks: bool,
    pub cross_filesystems: bool,
    pub allow_all_match_scan: bool,
    pub exclude_paths: Vec<Regex>,
    pub local_socket: Option<PathBuf>,
    pub local_socket_group: Option<String>,
    pub local_socket_mode: u32,
    pub fix_stale_socket: bool,
    pub tcp_addresses: Vec<String>,
    pub tcp_port: Option<u16>,
    pub backlog: i32,
    pub max_threads: usize,
    pub max_queue: usize,
    pub idle_timeout: Duration,
    pub self_check: Duration,
    pub concurrent_reload: bool,
    pub foreground: bool,
    pub debug: bool,
    pub user: Option<String>,
    pub pid_file: Option<PathBuf>,
    pub log_file: Option<PathBuf>,
    pub log_unlock: bool,
    pub log_time: bool,
    pub log_max_size: u64,
    pub log_rotate: bool,
    pub log_clean: bool,
    pub extended_detection_info: bool,
    pub log_verbose: bool,
    pub partial_engine_options: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database_directory: "/var/lib/clamav".into(),
            temporary_directory: std::env::temp_dir(),
            official_database_only: false,
            fail_if_cvd_older_than: None,
            detect_pua: false,
            stream_max_length: 100 << 20,
            objects: Options::default(),
            max_scan_time: Duration::ZERO,
            command_read_timeout: Duration::from_secs(30),
            read_timeout: Duration::from_secs(120),
            send_buf_timeout: Duration::from_millis(500),
            max_directory_recursion: 15,
            follow_directory_symlinks: false,
            follow_file_symlinks: false,
            cross_filesystems: true,
            allow_all_match_scan: true,
            exclude_paths: Vec::new(),
            local_socket: None,
            local_socket_group: None,
            local_socket_mode: 0o666,
            fix_stale_socket: true,
            tcp_addresses: Vec::new(),
            tcp_port: None,
            backlog: 200,
            max_threads: 10,
            max_queue: 100,
            idle_timeout: Duration::from_secs(30),
            self_check: Duration::from_secs(600),
            concurrent_reload: true,
            foreground: false,
            debug: false,
            user: None,
            pid_file: None,
            log_file: None,
            log_unlock: false,
            log_time: false,
            log_max_size: 1 << 20,
            log_rotate: false,
            log_clean: false,
            extended_detection_info: false,
            log_verbose: false,
            partial_engine_options: Vec::new(),
        }
    }
}

fn boolean(value: &str) -> io::Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "1" => Ok(true),
        "no" | "false" | "0" => Ok(false),
        _ => Err(invalid("expected yes or no")),
    }
}

fn number<T: std::str::FromStr>(value: &str) -> io::Result<T> {
    value.parse().map_err(|_| invalid("invalid numeric value"))
}

fn size(value: &str) -> io::Result<u64> {
    let (digits, multiplier) = match value.as_bytes().last().map(u8::to_ascii_lowercase) {
        Some(b'k') => (&value[..value.len() - 1], 1 << 10),
        Some(b'm') => (&value[..value.len() - 1], 1 << 20),
        Some(b'g') => (&value[..value.len() - 1], 1 << 30),
        _ => (value, 1),
    };
    number::<u64>(digits)?
        .checked_mul(multiplier)
        .ok_or_else(|| invalid("size exceeds supported range"))
}

impl Config {
    fn set(&mut self, key: &str, value: &str) -> io::Result<()> {
        match key {
            "DatabaseDirectory" => self.database_directory = value.into(),
            "TemporaryDirectory" => self.temporary_directory = value.into(),
            "OfficialDatabaseOnly" => self.official_database_only = boolean(value)?,
            "FailIfCvdOlderThan" => {
                self.fail_if_cvd_older_than = Some(number(value)?).filter(|d| *d > 0)
            }
            "DetectPUA" => self.detect_pua = boolean(value)?,
            "MaxFileSize" => self.objects.max_file_size = size(value)?,
            "MaxScanSize" => self.objects.max_scan_size = size(value)?,
            "MaxFiles" => self.objects.max_files = number(value)?,
            "MaxPartitions" => self.objects.max_partitions = number(value)?,
            "MaxRecursion" => self.objects.max_recursion = number(value)?,
            "MaxRecHWP3" => self.objects.max_rec_hwp3 = number(value)?,
            "AlertExceedsMax" => self.objects.alert_exceeds_max = boolean(value)?,
            "ScanArchive" => self.objects.scan_archive = boolean(value)?,
            "ScanPE" => self.objects.scan_pe = boolean(value)?,
            "MaxEmbeddedPE" => self.objects.max_embedded_pe = size(value)?,
            "ScanELF" => self.objects.scan_elf = boolean(value)?,
            "ScanPDF" => self.objects.scan_pdf = boolean(value)?,
            "ScanOLE2" => self.objects.scan_ole2 = boolean(value)?,
            "ScanHWP3" => self.objects.scan_hwp3 = boolean(value)?,
            "ScanXMLDOCS" => self.objects.scan_xml_docs = boolean(value)?,
            "ScanSWF" => self.objects.scan_swf = boolean(value)?,
            "ScanOneNote" => self.objects.scan_onenote = boolean(value)?,
            "ScanImage" => self.objects.scan_image = boolean(value)?,
            "AlertBrokenMedia" => self.objects.alert_broken_media = boolean(value)?,
            "ScanHTML" => self.objects.scan_html = boolean(value)?,
            "ScanMail" => self.objects.scan_mail = boolean(value)?,
            "MaxHTMLNormalize" | "MaxHTMLNoTags" | "MaxScriptNormalize" => {
                let n = size(value)?;
                let n = if n == 0 { u64::from(u32::MAX) } else { n };
                match key {
                    "MaxHTMLNormalize" => self.objects.max_html_normalize = n,
                    "MaxHTMLNoTags" => self.objects.max_html_no_tags = n,
                    _ => self.objects.max_script_normalize = n,
                }
            }
            "MaxScanTime" => self.max_scan_time = Duration::from_millis(number(value)?),
            "StreamMaxLength" => self.stream_max_length = size(value)?,
            "CommandReadTimeout" => self.command_read_timeout = Duration::from_secs(number(value)?),
            "ReadTimeout" => self.read_timeout = Duration::from_secs(number(value)?),
            "SendBufTimeout" => self.send_buf_timeout = Duration::from_millis(number(value)?),
            "MaxDirectoryRecursion" => self.max_directory_recursion = number(value)?,
            "FollowDirectorySymlinks" => self.follow_directory_symlinks = boolean(value)?,
            "FollowFileSymlinks" => self.follow_file_symlinks = boolean(value)?,
            "CrossFilesystems" => self.cross_filesystems = boolean(value)?,
            "AllowAllMatchScan" => self.allow_all_match_scan = boolean(value)?,
            "ExcludePath" => self
                .exclude_paths
                .push(Regex::new(value).map_err(|e| invalid(e.to_string()))?),
            "LocalSocket" => self.local_socket = Some(value.into()),
            "LocalSocketGroup" => self.local_socket_group = Some(value.into()),
            "LocalSocketMode" => {
                self.local_socket_mode =
                    u32::from_str_radix(value, 8).map_err(|_| invalid("invalid octal mode"))?;
                if self.local_socket_mode > 0o777 {
                    return Err(invalid("invalid socket permissions"));
                }
            }
            "FixStaleSocket" => self.fix_stale_socket = boolean(value)?,
            "TCPSocket" => self.tcp_port = Some(number(value)?),
            "TCPAddr" => self.tcp_addresses.push(value.into()),
            "MaxConnectionQueueLength" => self.backlog = number(value)?,
            "MaxThreads" => self.max_threads = number(value)?,
            "MaxQueue" => self.max_queue = number(value)?,
            "IdleTimeout" => self.idle_timeout = Duration::from_secs(number(value)?),
            "SelfCheck" => self.self_check = Duration::from_secs(number(value)?),
            "ConcurrentDatabaseReload" => self.concurrent_reload = boolean(value)?,
            "Foreground" => self.foreground = boolean(value)?,
            "Debug" => self.debug = boolean(value)?,
            "User" => self.user = Some(value.into()),
            "PidFile" => self.pid_file = Some(value.into()),
            "LogFile" => self.log_file = Some(value.into()),
            "LogFileUnlock" => self.log_unlock = boolean(value)?,
            "LogFileMaxSize" => self.log_max_size = size(value)?,
            "LogRotate" => self.log_rotate = boolean(value)?,
            "LogTime" => self.log_time = boolean(value)?,
            "LogClean" => self.log_clean = boolean(value)?,
            "ExtendedDetectionInfo" => self.extended_detection_info = boolean(value)?,
            "LogVerbose" => self.log_verbose = boolean(value)?,
            // clamonacc consumes the OnAccess settings in the same configuration.
            "OnAccessMaxFileSize" => {
                size(value)?;
            }
            "PreludeAnalyzerName" | "LogFacility" => {}
            "PreludeEnable"
            | "LogSyslog"
            | "ExitOnOOM"
            | "LeaveTemporaryFiles"
            | "GenerateMetadataJson" => {
                if boolean(value)? {
                    return Err(invalid(format!("unsupported option {key}")));
                }
            }
            "DisableCache" => {
                boolean(value)?;
            } // Every scan runs against its pinned generation.
            "Example" => {
                return Err(invalid(
                    "edit the example configuration before starting clamd",
                ));
            }
            // These Debian reference values apply to scanner stages that still produce an
            // incomplete-scan error. An alternate policy must be reviewed before activation.
            _ if reference_engine_value(key, value) => self.partial_engine_options.push(key.into()),
            _ => {
                return Err(invalid(format!(
                    "unknown or unsupported option or value for {key}"
                )));
            }
        }
        Ok(())
    }

    fn read(path: &Path, overrides: Vec<(&'static str, String)>) -> io::Result<Self> {
        let mut config = Self::default();
        let mut seen = HashSet::new();
        for (key, value) in overrides {
            if seen.insert(key.to_owned()) {
                config.set(key, &value)?;
            }
        }
        let file = fs::read_to_string(path)
            .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
        for (i, line) in file.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            if key == "Example" || value.is_empty() {
                return Err(invalid(format!(
                    "{}:{}: invalid directive {key}",
                    path.display(),
                    i + 1
                )));
            }
            if !matches!(key, "TCPAddr" | "ExcludePath") && !seen.insert(key.into()) {
                continue;
            }
            config
                .set(key, value)
                .map_err(|e| invalid(format!("{}:{}: {key}: {e}", path.display(), i + 1)))?;
        }
        if config.max_threads == 0 || config.backlog <= 0 {
            return Err(invalid(
                "MaxThreads and MaxConnectionQueueLength must be positive",
            ));
        }
        let (soft, _) = nix::sys::resource::getrlimit(nix::sys::resource::Resource::RLIMIT_NOFILE)?;
        config.max_queue = queue_limit(
            config.max_threads,
            config.objects.max_recursion,
            config.max_queue,
            soft.try_into().unwrap_or(usize::MAX),
        );
        Ok(config)
    }
}

// Stock reserves six service descriptors and MaxRecursion descriptors per scan.
fn queue_limit(threads: usize, recursion: usize, requested: usize, descriptors: usize) -> usize {
    let budget = descriptors
        .saturating_add(threads)
        .saturating_sub(threads.saturating_mul(recursion).saturating_add(6))
        .max(threads);
    requested.max(threads.saturating_mul(2)).min(budget)
}

fn reference_engine_value(key: &str, value: &str) -> bool {
    match key {
        "AlgorithmicDetection" | "PhishingSignatures" | "PhishingScanURLs" | "Bytecode" => {
            boolean(value).ok() == Some(true)
        }
        "AlertEncrypted"
        | "AlertEncryptedArchive"
        | "AlertEncryptedDoc"
        | "ArchiveBlockEncrypted"
        | "PhishingAlwaysBlockSSLMismatch"
        | "PhishingAlwaysBlockCloak"
        | "PartitionIntersection"
        | "ScanPartialMessages"
        | "HeuristicScanPrecedence"
        | "StructuredDataDetection"
        | "OLE2BlockMacros"
        | "ForceToDisk"
        | "DisableCertCheck" => boolean(value).ok() == Some(false),
        "BytecodeSecurity" => value == "TrustSigned",
        "MaxZipTypeRcg" => size(value).ok() == Some(1 << 20),
        "PCREMaxFileSize" => matches!(size(value), Ok(26214400 | 104857600)),
        "MaxIconsPE" => value == "100",
        "PCREMatchLimit" => value == "10000" || value == "100000",
        "PCRERecMatchLimit" => value == "5000" || value == "2000",
        "BytecodeTimeout" => value == "60000" || value == "10000",
        _ => false,
    }
}

pub(super) fn arguments(args: &[OsString]) -> io::Result<Option<Config>> {
    let mut args = args.iter();
    let mut path = PathBuf::from("/etc/clamav/clamd.conf");
    let mut overrides = Vec::new();
    while let Some(arg) = args.next() {
        let arg = arg
            .to_str()
            .ok_or_else(|| invalid("invalid command line encoding"))?;
        let (flag, inline) = arg
            .split_once('=')
            .map_or((arg, None), |(a, b)| (a, Some(b)));
        let key = match flag {
            "-h" | "--help" => {
                println!(
                    "Barnacle clamd-compatible daemon\nUsage: barnacle serve [--config-file FILE] [--foreground[=yes|no]]\n  --datadir DIR  --pid FILE  --log FILE  --debug  --fail-if-cvd-older-than DAYS\n  -V, --version"
                );
                return Ok(None);
            }
            "-V" | "--version" => {
                println!("ClamAV 1.4.3");
                return Ok(None);
            }
            "-F" | "--foreground" => "Foreground",
            "--debug" => "Debug",
            "-c" | "--config-file" => "ConfigFile",
            "--datadir" => "DatabaseDirectory",
            "--pid" | "-p" => "PidFile",
            "--log" | "-l" => "LogFile",
            "--fail-if-cvd-older-than" => "FailIfCvdOlderThan",
            _ => return Err(invalid(format!("unknown clamd argument {flag}"))),
        };
        let value = if let Some(value) = inline {
            value
        } else if matches!(key, "Foreground" | "Debug") {
            "yes"
        } else {
            args.next()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid(format!("{flag} requires a value")))?
        };
        if value.is_empty() {
            return Err(invalid(format!("empty value for {flag}")));
        }
        if key == "ConfigFile" {
            path = value.into();
        } else {
            overrides.push((key, value.to_owned()));
        }
    }
    Config::read(&path, overrides).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn adjusts_queue_to_the_scan_and_descriptor_budget() {
        assert_eq!(queue_limit(1, 17, 1, 1024), 2);
        assert_eq!(queue_limit(10, 17, 5, 1024), 20);
        assert_eq!(queue_limit(10, 17, 500, 256), 90);
        assert_eq!(queue_limit(10, 17, 100, 30), 10);
        assert_eq!(queue_limit(10, 17, 100, 1024), 100);
    }

    #[test]
    fn reads_clamd_flags_and_repeated_directives() -> io::Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(
            file,
            "Foreground no\nLocalSocket \"/run/test clam/socket\"\nMaxFileSize 25m\nMaxFileSize 2K\nTCPAddr localhost\nTCPAddr 127.0.0.1\nExcludePath ^/proc/\nExcludePath ^/sys/\nLogSyslog no\nSelfCheck 0\nConcurrentDatabaseReload no"
        )?;
        let args = [
            "--config-file".into(),
            file.path().into(),
            "--foreground=true".into(),
            "--fail-if-cvd-older-than=7".into(),
        ];
        let config = arguments(&args)?.unwrap();
        assert!(config.foreground);
        assert!(!config.concurrent_reload);
        assert!(config.self_check.is_zero());
        assert_eq!(
            config.local_socket.as_deref(),
            Some(Path::new("/run/test clam/socket"))
        );
        assert_eq!(config.objects.max_file_size, 25 << 20);
        assert_eq!(config.tcp_addresses, ["localhost", "127.0.0.1"]);
        assert_eq!(config.exclude_paths.len(), 2);
        assert_eq!(config.fail_if_cvd_older_than, Some(7));
        Ok(())
    }

    #[test]
    fn bad_configuration_prevents_service_start() -> io::Result<()> {
        for input in [
            "Example",
            "Bogus yes",
            "MaxThreads 0",
            "MaxQueue -1",
            "LocalSocketMode 688",
            "LogSyslog yes",
            "AlertEncrypted yes",
            "AlertEncryptedArchive yes",
            "AlertEncryptedDoc yes",
            "VirusEvent touch %v",
            "MaxFileSize 18446744073709551615G",
            "ExcludePath [",
        ] {
            let file = tempfile::NamedTempFile::new()?;
            fs::write(file.path(), input)?;
            assert!(Config::read(file.path(), Vec::new()).is_err(), "{input}");
        }
        Ok(())
    }
}
