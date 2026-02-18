import os
import tempfile
import logging

logger = logging.getLogger("mwdb.plugin.clamyara")


def create_temp_file(prefix: str) -> str:
    """
    Create temporary file and return its path.
    Caller MUST delete it.
    """
    fd, path = tempfile.mkstemp(prefix=prefix)
    os.close(fd)
    return path


def safe_remove(path: str):
    try:
        if path and os.path.exists(path):
            os.remove(path)
            logger.debug("Removed temporary file: %s", path)
    except Exception:
        logger.exception("Failed to remove temporary file: %s", path)
