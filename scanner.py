import subprocess
import logging

from . import config

logger = logging.getLogger("mwdb.plugin.clamyara")


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
                    return output.split(":")[-1].replace("FOUND", "").strip()
                return "Detected"

            logger.error("ClamAV error: %s", proc.stderr.strip())
            return "Error"

        except subprocess.TimeoutExpired:
            logger.error("ClamAV scan timeout")
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
            proc = subprocess.run(
                ["yara", config.YARA_RULES_PATH, file_path],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if proc.returncode == 0:
                return [line.split()[0] for line in proc.stdout.splitlines()]

            if proc.returncode == 1:
                return []

            logger.error("YARA error: %s", proc.stderr.strip())
            return []

        except subprocess.TimeoutExpired:
            logger.error("YARA scan timeout")
            return []

        except Exception:
            logger.exception("YARA scan failed")
            return []
