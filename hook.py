import logging

from mwdb.core.plugins import PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

from .scanner import ClamYaraScanner
from .utils import create_temp_file, safe_remove
from . import config

logger = logging.getLogger("mwdb.plugin.clamyara")


class ClamYaraHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        self._process_file(file, "created")

    def on_reuploaded_file(self, file: File):
        self._process_file(file, "reuploaded")

    def _process_file(self, file: File, reason: str):
        sha256 = file.sha256
        logger.info("Scanning file %s (%s)", sha256, reason)

        mwdb = MWDB(
            api_url=config.MWDB_API_URL,
            api_key=config.MWDB_API_KEY,
        )

        temp_path = None
        try:
            mwdb_file = mwdb.query_file(sha256)

            if len(mwdb_file.content) > config.MAX_FILE_SIZE:
                logger.warning(
                    "Skipping file %s: size %d exceeds limit",
                    sha256,
                    len(mwdb_file.content),
                )
                return

            temp_path = create_temp_file(prefix=f"clamyara_{sha256}_")
            with open(temp_path, "wb") as f:
                f.write(mwdb_file.content)

            comment = ""

            # -------- ClamAV --------
            if config.CLAMAV_ENABLED:
                cl_result = ClamYaraScanner.scan_clamav(temp_path)
                cl_version = ClamYaraScanner.clamav_version()

                comment += f"ClamAV: {cl_result} (Version: {cl_version})\n"

                if cl_result not in ("Error", "Undetected"):
                    self._add_tag(file, "clamav", cl_result)

            # -------- YARA --------
            if config.YARA_ENABLED:
                yr_result = ClamYaraScanner.scan_yara(temp_path)

                if yr_result:
                    comment += f"YARA: {', '.join(yr_result)}\n"
                    for detect in yr_result:
                        self._add_tag(file, "yara", detect)
                else:
                    comment += "YARA: Undetected\n"

            if comment:
                file.add_comment(comment.strip())

        finally:
            safe_remove(temp_path)

    @staticmethod
    def _add_tag(file: File, av_name: str, av_result: str):
        tag_value = f"{av_name.lower()}:{av_result.lower()}"

        for tag in file.tags:
            if tag.lower() == tag_value:
                return

        file.add_tag(tag_value)
