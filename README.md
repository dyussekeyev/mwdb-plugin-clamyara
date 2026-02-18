# MWDB ClamYara Plugin

**MWDB ClamYara** is a local MWDB plugin that automatically scans newly uploaded and re-uploaded files using **ClamAV** and **YARA**.  
The plugin is designed to be **simple, portable, and safe**, relying exclusively on **CLI tools** and the official **MWDB API**.

---

## Features

- Automatic scanning on:
  - file creation
  - file reupload
- ClamAV scanning via `clamscan`
- YARA scanning via `yara` CLI
- Results published directly to MWDB:
  - human-readable comments
  - structured tags
- Safe temporary file handling (no disk leaks)
- Path traversal protection for temporary files
- Configurable via environment variables
- Robust input validation for all configuration values
- No Python bindings for ClamAV or YARA required

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

- **ClamAV** — `clamscan`
- **YARA** — `yara`

No Python bindings (`yara-python`, `clamd`) are required.

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

4. Ensure `clamscan` and `yara` are installed and accessible:

   ```bash
   clamscan --version
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
| `CLAMYARA_YARA_ENABLED` | `true` | Enable YARA scanning |
| `CLAMYARA_YARA_RULES_PATH` | `/opt/yara/rules.yar` | Path to YARA rules file |
| `CLAMYARA_MAX_FILE_SIZE` | `52428800` | Maximum file size in bytes (50 MB). Must be a positive integer. |

### Example

```bash
export CLAMYARA_MWDB_API_URL="https://mwdb.local/api"
export CLAMYARA_MWDB_API_KEY="your_api_key"
export CLAMYARA_YARA_RULES_PATH="/opt/yara/rules.yar"
export CLAMYARA_MAX_FILE_SIZE="52428800"
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
   - ClamAV via `clamscan` (timeout: 60 s)
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

## Security Considerations

- **Memory safety** — file size is validated via metadata *before* content is downloaded, preventing OOM on oversized files
- **Path traversal protection** — all temporary file paths are validated to reside inside the system temp directory before being passed to CLI tools
- **No shell injection** — all subprocess calls use list arguments (never `shell=True`)
- **CLI timeouts** — `clamscan` and `yara` are executed with strict timeouts to prevent hangs
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
