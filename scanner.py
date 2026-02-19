import re
import subprocess
import logging

from . import config
from .utils import validate_temp_path

logger = logging.getLogger("mwdb.plugin.clamyara")

_CLAM_FOUND_RE = re.compile(r"^.+:\s+(.+)\s+FOUND$", re.MULTILINE)


class ClamYaraScanner:
    @staticmethod
    def clamav_version() -> str:
        """
        Best-effort ClamAV version detection using clamdscan only.
        """
        try:
            proc = subprocess.run(
                ["clamdscan", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if proc.returncode == 0:
                out = (proc.stdout or proc.stderr).strip()
                return out if out else "Unknown"
            return "Unknown"
        except Exception:
            return "Unknown"

    @staticmethod
    def scan_clamav(file_path: str) -> str:
        """
        Returns:
            - signature name
            - 'Undetected'
            - 'Error'
        """
        try:
            validate_temp_path(file_path)  # защита от path traversal

            # clamdscan return codes:
            # - 0: no virus found
            # - 1: virus(es) found
            # - 2: error
            cmd = ["clamdscan", "--no-summary", "--fdpass"]

            if config.CLAMD_SOCKET:
                # On many builds this is supported; if not, clamdscan will error (rc=2).
                cmd.extend(["--unix-socket", config.CLAMD_SOCKET])

            cmd.append(file_path)

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.CLAMAV_TIMEOUT,
            )

            if proc.returncode == 0:
                return "Undetected"

            if proc.returncode == 1:
                output = (proc.stdout or "").strip()
                if "FOUND" in output:
                    match = _CLAM_FOUND_RE.search(output)
                    if match:
                        return match.group(1).strip()
                return "Detected"

            # rc=2 or other -> error
            stderr = (proc.stderr or "").strip()
            stdout = (proc.stdout or "").strip()
            logger.error("clamdscan error (rc=%d): %s %s", proc.returncode, stderr, stdout)
            return "Error"

        except subprocess.TimeoutExpired:
            logger.error("ClamAV scan timeout")
            return "Error"

        except FileNotFoundError:
            logger.error("clamdscan not found in PATH (ClamAV/clamdscan is required)")
            return "Error"

        except ValueError:
            logger.error("ClamAV scan rejected: invalid file path %r", file_path)
            return "Error"

        except Exception:
            logger.exception("ClamAV scan failed")
            return "Error"

    @staticmethod
    def scan_yara(file_path: str) -> list[str]:
        """
        Returns list of rule names
        """
        try:
            validate_temp_path(file_path)  # защита от path traversal
            proc = subprocess.run(
                ["yara", config.YARA_RULES_PATH, file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode == 0:
                # Пустой вывод = нет совпадений (это нормально)
                return [
                    line.split()[0]
                    for line in proc.stdout.splitlines()
                    if line.strip()
                ]

            # Любой ненулевой код — ошибка (returncode 1 = ошибка YARA, не "нет совпадений")
            logger.error("YARA error (rc=%d): %s", proc.returncode, proc.stderr.strip())
            return []

        except subprocess.TimeoutExpired:
            logger.error("YARA scan timeout")
            return []

        except ValueError:
            logger.error("YARA scan rejected: invalid file path %r", file_path)
            return []

        except Exception:
            logger.exception("YARA scan failed")
            return []
