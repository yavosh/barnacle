//! Capture and compare local ClamD protocol replies and unmodified clamdscan results.
#[path = "compat_oracle/daemon.rs"]
mod daemon;
#[path = "compat_oracle/fixtures.rs"]
mod fixtures;

use daemon::{Daemon, exchange, stream_frame, unix_request};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs::{self, File};
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

const REVISION: &str = "1.4.3+dfsg-1";
const STOCK: &str = "/usr/sbin/clamd";
const ARCHIVES: [(&str, &str); 3] = [
    (
        "daily.cvd",
        "423f7774182bfbc82b50c7796c68a93f8b1817ef7ebbc88d7def444bc2c8f35b",
    ),
    (
        "main.cvd",
        "0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365",
    ),
    (
        "bytecode.cvd",
        "6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb",
    ),
];
const CONFIG: &str = include_str!("../docs/compatibility/oracle.conf.in");

fn prepare_database(db: &Path, official: Option<&Path>) -> io::Result<BTreeMap<String, String>> {
    fs::create_dir(db)?;
    let mut hashes = BTreeMap::new();
    if let Some(source) = official {
        for (name, expected) in ARCHIVES {
            let copy = db.join(name);
            fs::copy(source.join(name), &copy)?;
            let actual = fixtures::file_hash(&copy)?;
            if actual != expected {
                return Err(io::Error::other(format!(
                    "{name} differs from the pinned generation"
                )));
            }
            hashes.insert(name.into(), actual);
        }
    } else {
        fixtures::write_rules(db)?;
        for name in ["fixture.hdb", "fixture.hsb"] {
            hashes.insert(name.into(), fixtures::file_hash(&db.join(name))?);
        }
    }
    Ok(hashes)
}

fn scan_result(reply: String) -> Value {
    let result = reply.strip_suffix('\0');
    let name = result
        .and_then(|s| s.strip_prefix("stream: "))
        .and_then(|s| s.strip_suffix(" FOUND"));
    let verdict = if result == Some("stream: OK") {
        "clean"
    } else if name.is_some() {
        "detected"
    } else if result.is_some_and(|s| s.ends_with(" ERROR")) {
        "error"
    } else {
        "unexpected"
    };
    json!({"reply": reply, "verdict": verdict, "signature": name})
}

fn client_scan(root: &Path, config: &Path, args: &[&str], input: &str) -> io::Result<Value> {
    let output = Command::new("/usr/bin/timeout")
        .args([
            "--kill-after=5",
            "30",
            "/usr/bin/clamdscan",
            "--no-summary",
            "--config-file",
        ])
        .arg(config)
        .args(args)
        .arg(input)
        .current_dir(root)
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .output()?;
    let code = output
        .status
        .code()
        .ok_or_else(|| io::Error::other("clamdscan terminated by signal"))?;
    if !(0..=2).contains(&code) {
        return Err(io::Error::other(format!(
            "clamdscan failed with exit code {code}"
        )));
    }
    let normalize = |out: Vec<u8>| -> io::Result<String> {
        Ok(String::from_utf8(out)
            .map_err(io::Error::other)?
            .replace(root.to_str().unwrap(), "{root}"))
    };
    Ok(
        json!({"exit": code, "stdout": normalize(output.stdout)?, "stderr": normalize(output.stderr)?}),
    )
}

fn tcp_request(addr: SocketAddr, bytes: &[u8]) -> io::Result<String> {
    let timeout = Duration::from_secs(10);
    let socket = TcpStream::connect_timeout(&addr, timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    exchange(socket, bytes)
}

fn profile(executable: &Path, official: Option<&Path>) -> io::Result<Value> {
    let temporary = tempfile::tempdir_in("/tmp")?;
    let root = temporary.path();
    let hashes = prepare_database(&root.join("db"), official)?;
    let corpus = fixtures::corpus()?;
    for (name, data) in &corpus {
        fs::write(root.join(name), data)?;
    }
    let config = root.join("clamd.conf");
    let socket = root.join("socket");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let addr = listener.local_addr()?;
    fs::write(
        &config,
        CONFIG
            .replace("{root}", root.to_str().unwrap())
            .replace("{port}", &addr.port().to_string()),
    )?;
    drop(listener);
    let _daemon = Daemon::start(executable, &config, &socket)?;
    let mut clients = json!({
        "path-detected": client_scan(root, &config, &[], "detected")?,
        "fdpass-detected": client_scan(root, &config, &["--fdpass"], "detected")?,
        "missing-path": client_scan(root, &config, &[], "missing")?,
    });
    let mut scans = BTreeMap::new();
    for (&name, data) in &corpus {
        clients[format!("stream-{name}")] = client_scan(root, &config, &["--stream"], name)?;
        let reply = unix_request(&socket, &stream_frame(data)?)
            .map_err(|e| io::Error::other(format!("INSTREAM {name}: {e}")))?;
        scans.insert(name, json!({"sha256": fixtures::hex(&Sha256::digest(data)), "bytes": data.len(), "instream": scan_result(reply)}));
    }
    Ok(json!({
        "database_sha256": hashes, "scans": scans,
        "wire": {
            "unix-zPING": unix_request(&socket, b"zPING\0")?,
            "unix-nPING": unix_request(&socket, b"nPING\n")?,
            "unix-zVERSION": unix_request(&socket, b"zVERSION\0")?,
            "unix-zVERSIONCOMMANDS": unix_request(&socket, b"zVERSIONCOMMANDS\0")?,
            "tcp-zPING": tcp_request(addr, b"zPING\0")?,
            "tcp-zINSTREAM-clean": tcp_request(addr, &stream_frame(&corpus["clean"])?)?,
        },
        "clamdscan": clients,
    }))
}

fn verify_package(program: &str, args: &[&str], expected: &str) -> io::Result<()> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() || String::from_utf8_lossy(&output.stdout).trim_end() != expected {
        return Err(io::Error::other(format!(
            "expected {expected} from {program} {args:?}"
        )));
    }
    Ok(())
}

fn capture(executable: &Path, db: &Path) -> io::Result<Value> {
    verify_package("dpkg", &["--print-architecture"], "arm64")?;
    verify_package(
        "dpkg-query",
        &["-W", "-f=${Version}", "clamdscan"],
        REVISION,
    )?;
    Ok(json!({
        "schema": 1, "architecture": "arm64", "reference_package": REVISION, "client_package": REVISION,
        "config_template": CONFIG,
        "profiles": {"local": profile(executable, None)?, "official": profile(executable, Some(db))?}
    }))
}

fn compare(expected: &Value, actual: &Value) -> io::Result<()> {
    fn mismatch(path: &str, left: &Value, right: &Value) -> io::Result<()> {
        if let (Some(lhs), Some(rhs)) = (left.as_object(), right.as_object()) {
            for (key, value) in lhs {
                let next = format!("{path}/{key}");
                let other = rhs
                    .get(key)
                    .ok_or_else(|| io::Error::other(format!("missing {next}")))?;
                mismatch(&next, value, other)?;
            }
            if let Some(key) = rhs.keys().find(|k| !lhs.contains_key(*k)) {
                return Err(io::Error::other(format!("unexpected {path}/{key}")));
            }
        } else if left != right {
            return Err(io::Error::other(format!(
                "{path}: expected {left}, observed {right}"
            )));
        }
        Ok(())
    }
    mismatch("", expected, actual)
}

// A fresh reference must exercise both detections and failures before it is trusted.
fn validate_reference(report: &Value) -> io::Result<()> {
    for profile in ["local", "official"] {
        let results = &report["profiles"][profile];
        for name in ["clean", "detected", "nested", "competing", "limit"] {
            let expected = match (profile, name) {
                (_, "limit") => "error",
                ("local", "detected" | "nested" | "competing") => "detected",
                _ => "clean",
            };
            let result = &results["scans"][name]["instream"];
            if result["verdict"] != expected {
                return Err(io::Error::other(format!(
                    "reference {profile}/{name}: expected {expected}, got {result}"
                )));
            }
        }
        let clients = &results["clamdscan"];
        for mode in [
            "path-detected",
            "stream-clean",
            "stream-detected",
            "stream-competing",
            "stream-nested",
            "fdpass-detected",
            "missing-path",
            "stream-limit",
        ] {
            let expected = match mode {
                "missing-path" => 2,
                "stream-clean" | "stream-limit" => 0,
                _ => i32::from(profile == "local"),
            };
            if clients[mode]["exit"] != expected {
                return Err(io::Error::other(format!(
                    "reference {profile}/{mode}: expected exit {expected}, got {}",
                    clients[mode]
                )));
            }
        }
    }
    Ok(())
}

fn load(path: &Path) -> io::Result<Value> {
    serde_json::from_reader(File::open(path)?).map_err(io::Error::other)
}

// Derive the exact milestone expectations from stock, preserving all other fields.
fn partial_reference(mut stock: Value) -> io::Result<Value> {
    validate_reference(&stock)?;
    const ERROR: &str = "stream: Incomplete scan: unsupported detection coverage. ERROR\0";
    for profile in ["local", "official"] {
        let results = &mut stock["profiles"][profile];
        let scans: &[&str] = if profile == "local" {
            &["clean"]
        } else {
            &["clean", "nested", "detected", "competing"]
        };
        for &name in scans {
            results["scans"][name]["instream"] = scan_result(ERROR.into());
        }
        results["wire"]["tcp-zINSTREAM-clean"] = json!(ERROR);
        // clamdscan also submits a truncated stream for its stream-limit probe.
        for &name in scans.iter().chain(["limit"].iter()) {
            results["clamdscan"][format!("stream-{name}")] = incomplete_client(name, false);
        }
        if profile == "official" {
            results["clamdscan"]["fdpass-detected"] = incomplete_client("detected", false);
            results["clamdscan"]["path-detected"] = incomplete_client("detected", true);
        }
    }
    Ok(stock)
}

fn incomplete_client(name: &str, path_mode: bool) -> Value {
    let prefix = if path_mode { "Incomplete scan: " } else { "" };
    json!({"exit": 2, "stdout": format!("{{root}}/{name}: {prefix}unsupported detection coverage. ERROR\n"), "stderr": ""})
}

fn main() -> io::Result<()> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [op, db] if op == "record" => {
            verify_package(
                "dpkg-query",
                &["-W", "-f=${Version}", "clamav-daemon"],
                REVISION,
            )?;
            let report = capture(Path::new(STOCK), Path::new(db))?;
            validate_reference(&report)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        [op, db, exe, expected] if op == "check" || op == "check-partial" => {
            let mut reference = load(Path::new(expected))?;
            if op == "check-partial" {
                reference = partial_reference(reference)?;
            }
            let report = capture(Path::new(exe), Path::new(db))?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            compare(&reference, &report)
        }
        [op, expected, observed] if op == "compare" => {
            compare(&load(Path::new(expected))?, &load(Path::new(observed))?)
        }
        _ => Err(io::Error::other(
            "usage: compat_oracle record OFFICIAL_DB | check|check-partial OFFICIAL_DB DAEMON REFERENCE.json | compare REFERENCE.json OBSERVED.json",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partial_reference_requires_specific_errors_and_preserves_local_hits() {
        let stock: Value =
            serde_json::from_str(include_str!("../docs/compat-reference.json")).unwrap();
        let expected = partial_reference(stock.clone()).unwrap();
        assert!(compare(&stock, &expected).is_err());
        for (pointer, wrong) in [
            (
                "/profiles/local/scans/detected/instream/reply",
                json!("stream: OK\0"),
            ),
            (
                "/profiles/local/scans/nested/instream/reply",
                json!("stream: unexpected ERROR\0"),
            ),
            ("/profiles/official/clamdscan/path-detected/exit", json!(0)),
            ("/profiles/official/wire/unix-zPING", json!("PONG\n")),
        ] {
            let mut observed = expected.clone();
            *observed.pointer_mut(pointer).unwrap() = wrong;
            assert!(compare(&expected, &observed).is_err());
        }
    }

    #[test]
    fn changed_winner_or_framing_fails_comparison() {
        let detected = scan_result("stream: One.UNOFFICIAL FOUND\0".into());
        assert_eq!(detected["signature"], "One.UNOFFICIAL");
        assert!(compare(&detected, &detected).is_ok());
        for raw in [
            "stream: Two.UNOFFICIAL FOUND\0",
            "stream: One.UNOFFICIAL FOUND\n",
            "stream: OK\0",
        ] {
            assert!(compare(&detected, &scan_result(raw.into())).is_err());
        }
    }

    #[test]
    fn measured_profile_must_use_the_same_generation_and_config() {
        let measured: Value =
            serde_json::from_str(include_str!("../docs/compat-reference.json")).unwrap();
        for pointer in [
            "/profiles/official/database_sha256/main.cvd",
            "/config_template",
        ] {
            let mut changed = measured.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("modified");
            let failure = compare(&measured, &changed).unwrap_err().to_string();
            assert!(failure.starts_with(pointer), "{failure}");
        }
    }

    #[test]
    fn rejects_missing_results_and_changed_client_errors() {
        let client = json!({"stream-limit": {"exit":2, "stderr":"limit"}});
        assert!(compare(&client, &json!({})).is_err());
        assert!(compare(&client, &json!({"stream-limit": {"exit":2, "stderr":""}})).is_err());
    }
}
