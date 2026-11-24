# Replay the pinned daemon reference

Use Debian 13 arm64 with `clamav-daemon`, `clamdscan`, and `clamav` at `1.4.3+dfsg-1`.
Run as an ordinary user in an isolated guest or container. Allow loopback TCP and local Unix sockets.
The runner starts private foreground daemons and directs each request to a private socket or loopback port.
Supply the [verified database generation](../whole-file-hashes.md) in a read-only directory.

Build the Rust executables in the checkout and run the offline tests.

```sh
cargo build --locked --release --bin barnacle --examples
cargo test --locked --all-targets
cargo test --locked --test hash_reference live_stock_daemon -- --ignored
```

Set `snapshot_dir` to the directory containing `daily.cvd`, `main.cvd`, and `bytecode.cvd`.
The runner checks their digests before use. It runs the local hash rules and official databases in separate daemon profiles.

```sh
oracle=target/release/examples/compat_oracle
"$oracle" record "$snapshot_dir" > /tmp/stock.json
"$oracle" compare docs/compat-reference.json /tmp/stock.json
"$oracle" check "$snapshot_dir" /usr/sbin/clamd docs/compat-reference.json > /tmp/stock-repeat.json
```

For a candidate daemon, replace `/usr/sbin/clamd` in the last command with its executable path.
The runner passes the same `clamd.conf` and uses the unmodified reference client. It compares exact replies, signatures, client output, and exit codes.
A difference exits unsuccessfully and identifies the first differing JSON field.

Use the following command to verify the partial daemon milestone.

```sh
"$oracle" check-partial "$snapshot_dir" target/release/barnacle docs/compat-reference.json > /tmp/barnacle.json
```

The two profiles contain 38 wire and client observations. The local gzip returns the inner signature through INSTREAM and clamdscan.
The partial comparison requires 22 exact stock outcomes and 16 specific incomplete-scan responses.
The incomplete cases include unmatched files and the full official database.
The runner also checks the input hashes, configuration, version, signature names, framing, and client exit codes.
Use `check` for full equivalence.

## Observe the current offline matcher

Build the pinned index using the [matcher guide](../whole-file-hashes.md). Set `index` to that immutable index path.
Run the current Barnacle CLI against the same fixture bytes.

```sh
target/release/examples/compat_matcher target/release/barnacle "$index" > /tmp/matcher.json
```

The matcher report includes each CLI reply and its corresponding stock `INSTREAM` result.
A direct local detection must report the stock signature. A miss says only that the whole-file hash did not match.
A nested detection and an oversized stream exercise daemon behavior beyond this matcher.

The Rust matcher runner embeds the [pinned stock results](../compat-reference.json).
Compare its output with the [recorded matcher results](matcher-results.json).
