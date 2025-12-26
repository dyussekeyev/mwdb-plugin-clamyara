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
- Configurable via environment variables
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
|---------|----------------|
| `scanner.py` | Execute CLI scans and return results |
| `hook.py` | MWDB integration (comments, tags, lifecycle hooks) |
| `utils.py` | Temporary file handling |
| `config.py` | Environment-based configuration |
| `__init__.py` | MWDB plugin bootstrap |

---

## Requirements

### System Requirements

- Linux environment
- Python 3.9+
- MWDB server with plugin support

### External Tools

The following tools **must be installed and available in PATH**:

- **ClamAV**
  - `clamscan`
- **YARA**
  - `yara`

No Python bindings (`yara-python`, `clamd`) are required.

---

## Installation

1. Clone the repository into the MWDB plugins directory:
   `git clone https://github.com/dyussekeyev/mwdb-plugin-clamyara.git`

2. Checkout the desired version:
   `git checkout v0.0.2-dev`

3. Install Python dependencies:
   `pip install mwdblib`

4. Ensure `clamscan` and `yara` are installed and accessible.

---

## Configuration

All configuration is done via environment variables.

### Required

| Variable | Description |
|--------|-------------|
| `CLAMYARA_MWDB_API_URL` | MWDB API URL |
| `CLAMYARA_MWDB_API_KEY` | MWDB API key |

### Optional

| Variable | Default | Description |
|--------|---------|-------------|
| `CLAMYARA_CLAMAV_ENABLED` | `true` | Enable ClamAV scanning |
| `CLAMYARA_YARA_ENABLED` | `true` | Enable YARA scanning |
| `CLAMYARA_YARA_RULES_PATH` | `/opt/yara/rules.yar` | Path to YARA rules file |
| `CLAMYARA_MAX_FILE_SIZE` | `52428800` | Maximum file size in bytes (50 MB) |

Example:

`export CLAMYARA_MWDB_API_URL="https://mwdb.local/api"`  
`export CLAMYARA_MWDB_API_KEY="your_api_key"`  
`export CLAMYARA_YARA_RULES_PATH="/opt/yara/rules.yar"`

---

## How It Works

1. MWDB triggers plugin hooks:
   - `on_created_file`
   - `on_reuploaded_file`
2. The plugin downloads the file via MWDB API
3. File size is validated against `CLAMYARA_MAX_FILE_SIZE`
4. File is written to a temporary location
5. Scanning is performed:
   - ClamAV via `clamscan`
   - YARA via `yara`
6. Results are published to MWDB:
   - Comment with scan summary
   - Tags for detections
7. Temporary file is removed unconditionally

---

## Output Format

### Comment Example

ClamAV: Win.Trojan.Generic (Version: ClamAV 1.3.0)  
YARA: APT_Loader, Packed_PE

### Tags Example

clamav:win.trojan.generic  
yara:apt_loader  
yara:packed_pe

Duplicate tags are automatically avoided.

---

## Safety Considerations

- Temporary files are always removed using `try/finally`
- Large files are skipped before writing to disk
- CLI execution uses timeouts to prevent hangs
- Failures are logged but do not interrupt MWDB operation

---

## Limitations

- Only ClamAV and YARA are supported
- CLI tools must be installed on the MWDB host
- No parallel scanning (by design, to avoid resource exhaustion)

---

## Changelog

### v0.0.2-dev

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
