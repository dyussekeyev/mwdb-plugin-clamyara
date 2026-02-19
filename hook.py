import logging
from typing import ClassVar, Optional

from mwdb.core.plugins import PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

from .scanner import ClamYaraScanner
from .utils import create_temp_file, safe_remove
from . import config

logger = logging.getLogger("mwdb.plugin.clamyara")


class ClamYaraHookHandler(PluginHookHandler):
    _mwdb: ClassVar[Optional[MWDB]] = None

    @classmethod
    def _get_mwdb(cls) -> MWDB:
        if cls._mwdb is None:
            if not config.MWDB_API_URL or not config.MWDB_API_KEY:
                raise RuntimeError(
                    "CLAMYARA_MWDB_API_URL and CLAMYARA_MWDB_API_KEY must be set"
                )
            cls._mwdb = MWDB(
                api_url=config.MWDB_API_URL,
                api_key=config.MWDB_API_KEY,
            )
        return cls._mwdb

    def on_created_file(self, file: File):
        self._process_file(file, "created")

    def on_reuploaded_file(self, file: File):
        self._process_file(file, "reuploaded")

    def _process_file(self, file: File, reason: str):
        sha256 = file.sha256
        logger.info("Scanning file %s (%s)", sha256, reason)

        try:
            mwdb = self._get_mwdb()
        except RuntimeError:
            logger.exception("MWDB client is not configured")
            return

        temp_path = None
        try:
            try:
                mwdb_file = mwdb.query_file(sha256)
            except Exception:
                logger.exception("Failed to query file %s from MWDB API", sha256)
                return

            # Проверяем размер через метаданные ДО загрузки содержимого
            if mwdb_file.file_size > config.MAX_FILE_SIZE:
                logger.warning(
                    "Skipping file %s: size %d exceeds limit",
                    sha256,
                    mwdb_file.file_size,
                )
                return

            content = mwdb_file.content  # загружаем только после проверки размера

            temp_path = create_temp_file(prefix=f"clamyara_{sha256}_")
            with open(temp_path, "wb") as f:
                f.write(content)

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
                mwdb_file.add_comment(comment.strip())

        finally:
            safe_remove(temp_path)

    @staticmethod
    def _add_tag(file: File, av_name: str, av_result: str):
        tag_value = f"{av_name.lower()}:{av_result.lower()}"

        for tag in file.tags:
            # tag — объект Tag, строка хранится в атрибуте .tag
            if tag.tag.lower() == tag_value:
                return

        file.add_tag(tag_value)

