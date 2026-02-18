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
        try:
            proc = subprocess.run(
                ["clamscan", "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return proc.stdout.strip() if proc.returncode == 0 else "Unknown"
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
            proc = subprocess.run(
                ["clamscan", "--no-summary", file_path],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if proc.returncode == 0:
                return "Undetected"

            if proc.returncode == 1:
                output = proc.stdout.strip()
                if "FOUND" in output:
                    match = _CLAM_FOUND_RE.search(output)
                    if match:
                        return match.group(1).strip()
                return "Detected"

            logger.error("ClamAV error (rc=%d): %s", proc.returncode, proc.stderr.strip())
            return "Error"

        except subprocess.TimeoutExpired:
            logger.error("ClamAV scan timeout")
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
