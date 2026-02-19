# MWDB ClamYara Plugin

**MWDB ClamYara** is a local MWDB plugin that automatically scans newly uploaded and re-uploaded files using **ClamAV** and **YARA**.  
The plugin is designed to be **simple, portable, and safe**, relying exclusively on **CLI tools** and the official **MWDB API**.

---

## Features

- Automatic scanning on:
  - file creation
  - file reupload
- ClamAV scanning via `clamdscan` (**recommended, fast; requires `clamd` daemon**)
- YARA scanning via `yara` CLI
- Results published directly to MWDB:
  - human-readable comments
  - structured tags
- Safe temporary file handling (no disk leaks)
- Path traversal protection for temporary files
- Configurable via environment variables
- Robust input validation for all configuration values
- No Python bindings for ClamAV or YARA required

> Note: Using `clamdscan` instead of `clamscan` avoids expensive per-scan signature DB loads.  
> In high-throughput environments (many uploads/reuploads), `clamdscan` is strongly preferred.

---

## Design Principles

This plugin intentionally focuses **only on ClamAV and YARA**.

Reasons:
- Commercial antivirus engines usually prohibit this usage without expensive licenses
- ClamAV and YARA are widely accepted, open-source, and suitable for automation
- CLI usage ensures maximum portability across environments

The architecture strictly separates responsibilities:

| Component | Responsibility |
|-----------|----------------|
| `scanner.py` | Execute CLI scans and return results |
| `hook.py` | MWDB integration (comments, tags, lifecycle hooks) |
| `utils.py` | Temporary file handling and path validation |
| `config.py` | Environment-based configuration with validation |
| `__init__.py` | MWDB plugin bootstrap |

---

## Requirements

### System Requirements

- Linux environment
- Python 3.10+
- MWDB server with plugin support

### External Tools

The following tools **must be installed and available in PATH**:

- **ClamAV** — `clamd` + `clamdscan`
- **YARA** — `yara`

No Python bindings (`yara-python`, `clamd` Python module) are required.

---

## Installation

1. Clone the repository into the MWDB plugins directory:

   ```bash
   git clone https://github.com/dyussekeyev/mwdb-plugin-clamyara.git
   ```

2. Checkout the desired version:

   ```bash
   git checkout v0.0.3
   ```

3. Install Python dependencies:

   ```bash
   pip install mwdblib
   ```

4. Ensure `clamdscan` and `yara` are installed and accessible:

   ```bash
   clamdscan --version
   yara --version
   ```

---

## Configuration

All configuration is done via environment variables.

### Required

| Variable | Description |
|----------|-------------|
| `CLAMYARA_MWDB_API_URL` | MWDB API base URL |
| `CLAMYARA_MWDB_API_KEY` | MWDB API key for authentication |

> ⚠️ If either required variable is missing, the plugin will refuse to start and log an error.

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `CLAMYARA_CLAMAV_ENABLED` | `true` | Enable ClamAV scanning |
| `CLAMYARA_CLAMD_SOCKET` | *(empty)* | Optional unix socket path for `clamdscan` (e.g. `/run/clamav/clamd.ctl`) |
| `CLAMYARA_CLAMAV_TIMEOUT` | `60` | ClamAV scan timeout in seconds |
| `CLAMYARA_YARA_ENABLED` | `true` | Enable YARA scanning |
| `CLAMYARA_YARA_RULES_PATH` | `/opt/yara/rules.yar` | Path to YARA rules file |
| `CLAMYARA_MAX_FILE_SIZE` | `52428800` | Maximum file size in bytes (50 MB). Must be a positive integer. |

### Example

```bash
export CLAMYARA_MWDB_API_URL="https://mwdb.local/api"
export CLAMYARA_MWDB_API_KEY="your_api_key"
export CLAMYARA_YARA_RULES_PATH="/opt/yara/rules.yar"
export CLAMYARA_MAX_FILE_SIZE="52428800"

# Optional: force clamdscan to use a specific unix socket
export CLAMYARA_CLAMD_SOCKET="/run/clamav/clamd.ctl"
```

---

## How It Works

1. MWDB triggers a plugin hook on file event:
   - `on_created_file`
   - `on_reuploaded_file`
2. The plugin resolves a shared MWDB API client (created once per process)
3. File metadata is queried; **size is checked before downloading content**
4. If the file exceeds `CLAMYARA_MAX_FILE_SIZE`, it is skipped with a warning
5. File content is downloaded and written to a secure temporary file
6. Scanning is performed:
   - ClamAV via `clamdscan` (timeout: `CLAMYARA_CLAMAV_TIMEOUT`, default 60 s)
   - YARA via `yara` (timeout: 30 s)
7. Results are published to MWDB:
   - A comment with the scan summary
   - Tags for each detection
8. The temporary file is **always** removed in a `finally` block

---

## Output Format

### Comment Example

```
ClamAV: Win.Trojan.Generic (Version: ClamAV 1.3.0)
YARA: APT_Loader, Packed_PE
```

### Tags Example

```
clamav:win.trojan.generic
yara:apt_loader
yara:packed_pe
```

Duplicate tags are automatically avoided.

---

## ClamAV setup guide (install, initial DB load, and detection tests)

This section is intentionally detailed, because `clamdscan` requires **both**:
1) signature DB present/updated (`freshclam`), and  
2) `clamd` daemon running and reachable.

### 1) Install ClamAV

#### Debian / Ubuntu

```bash
sudo apt update
sudo apt install -y clamav clamav-daemon
```

#### RHEL / CentOS / Fedora (example)

Package names vary between distros, but typically:

```bash
sudo dnf install -y clamav clamav-update clamav-server clamav-server-systemd
```

### 2) Initial signature DB download (freshclam)

Run a first update manually:

```bash
sudo systemctl stop clamav-freshclam 2>/dev/null || true
sudo freshclam
```

Enable periodic updates (if your distro provides a service unit):

```bash
sudo systemctl enable --now clamav-freshclam
sudo systemctl status clamav-freshclam --no-pager
```

Troubleshooting tips:
- If `freshclam` fails due to proxy/SSL/network, fix network access first.
- If you are rate-limited by upstream mirrors, retry later or configure a local mirror.

### 3) Start and verify `clamd`

Start the daemon (unit name depends on distro):

```bash
sudo systemctl enable --now clamav-daemon 2>/dev/null || true
sudo systemctl enable --now clamd 2>/dev/null || true
```

Check status:

```bash
sudo systemctl status clamav-daemon --no-pager 2>/dev/null || true
sudo systemctl status clamd --no-pager 2>/dev/null || true
```

Verify the client can talk to the daemon:

```bash
clamdscan --version
```

If `clamdscan` cannot connect, the error is usually self-explanatory (socket missing / connection refused).

#### Finding the `clamd` socket path

Depending on distro, typical socket paths include:
- `/run/clamav/clamd.ctl`
- `/var/run/clamav/clamd.ctl`

You can search for it:

```bash
sudo find /run /var/run -maxdepth 3 -type s -name "*clamd*" 2>/dev/null || true
```

Or inspect listening unix sockets:

```bash
sudo ss -xlpn | grep -i clamd || true
```

If you found the socket, you can pass it to the plugin:

```bash
export CLAMYARA_CLAMD_SOCKET="/run/clamav/clamd.ctl"
```

### 4) Test ClamAV detection with EICAR

EICAR is a harmless standardized test string.

Create a file:

```bash
cat > /tmp/eicar.com <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF
```

Scan:

```bash
clamdscan --no-summary /tmp/eicar.com
echo $?
```

Expected:
- output contains `FOUND`
- exit code is `1`

---

## YARA rules: sources and testing

### Public sources of YARA rules

Below is a list of widely used public rule sources (curate/pin to commits/tags for production use):

- Elastic protection artifacts (includes YARA): https://github.com/elastic/protections-artifacts
- YARA-Rules community repo: https://github.com/Yara-Rules/rules
- Florian Roth / Neo23x0 signature base (includes YARA rules): https://github.com/Neo23x0/signature-base
- Intezer public YARA rules: https://github.com/intezer/yara-rules
- CAPE Sandbox YARA rules: https://github.com/kevoreilly/CAPEv2/tree/master/data/yara

### How to test YARA rules locally

1) Quick sanity test against a benign file:

```bash
yara /opt/yara/rules.yar /bin/ls >/dev/null
echo $?
```

2) If you have a known sample that should match certain rules:

```bash
yara /opt/yara/rules.yar /path/to/sample
```

If the output prints rule names, those rule names will be used as MWDB tags:
- `yara:<rule_name>`

---

## Security Considerations

- **Memory safety** — file size is validated via metadata *before* content is downloaded, preventing OOM on oversized files
- **Path traversal protection** — all temporary file paths are validated to reside inside the system temp directory before being passed to CLI tools
- **No shell injection** — all subprocess calls use list arguments (never `shell=True`)
- **CLI timeouts** — ClamAV and YARA are executed with strict timeouts to prevent hangs
- **Startup validation** — missing or invalid configuration values raise errors at startup, not silently at runtime
- **Guaranteed cleanup** — temporary files are always removed via `try/finally`, preventing disk leaks

---

## Limitations

- Only ClamAV and YARA are supported (by design)
- CLI tools must be installed on the MWDB host
- No parallel scanning (by design, to avoid resource exhaustion)
- YARA rules must be compiled into a single file at `CLAMYARA_YARA_RULES_PATH`

---

## Changelog

### v0.0.4

- **Performance:** switched ClamAV scanning to `clamdscan` (requires `clamd` daemon) to avoid repeated signature DB loads on each scan
- **Config:** added `CLAMYARA_CLAMD_SOCKET` to optionally specify a `clamd` unix socket
- **Config:** added `CLAMYARA_CLAMAV_TIMEOUT` to configure ClamAV scan timeout
- **Docs:** added detailed ClamAV installation/initial DB download (`freshclam`) and EICAR detection test instructions
- **Docs:** added YARA rules sources and basic testing commands

### v0.0.3

- **Security:** file size is now checked via metadata before downloading content (prevents OOM)
- **Security:** added path traversal validation for all temporary file paths
- **Fix:** corrected `AttributeError` when comparing MWDB tag objects (`.tag` attribute used correctly)
- **Fix:** corrected YARA return code interpretation (`returncode != 0` is always an error)
- **Fix:** `MAX_FILE_SIZE` env var is now validated as a positive integer with a descriptive error on misconfiguration
- **Fix:** ClamAV signature parsing hardened with a regex to handle signatures containing colons
- **Fix:** empty lines in YARA output no longer cause `IndexError`
- **Improvement:** MWDB API client is now created once per process (lazy singleton), not on every file event
- **Improvement:** missing `CLAMYARA_MWDB_API_URL` / `CLAMYARA_MWDB_API_KEY` now produce an explicit `RuntimeError` at startup
- **Improvement:** network errors from `mwdb.query_file()` are now caught and logged gracefully

### v0.0.2

- Refactored architecture with strict separation of concerns
- Switched to CLI-only scanning (no Python bindings)
- Added guaranteed temporary file cleanup
- Added file size limit protection
- Improved error handling and logging
- Environment-based configuration
- Fully MWDB-native integration

### v0.0.1

- Initial implementation
- Basic ClamAV and YARA scanning
- Manual temporary directory handling

---

## License

MIT License

---

## Author

**Askar Dyussekeyev**
