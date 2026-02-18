import os
import tempfile
import logging

logger = logging.getLogger("mwdb.plugin.clamyara")

_TEMP_DIR = tempfile.gettempdir()


def create_temp_file(prefix: str) -> str:
    """
    Create temporary file and return its path.
    Caller MUST delete it.
    """
    fd, path = tempfile.mkstemp(prefix=prefix, dir=_TEMP_DIR)
    os.close(fd)
    return path


def validate_temp_path(path: str) -> None:
    """
    Raise ValueError if path is not inside the system temp directory.
    Prevents path traversal attacks.
    """
    real_path = os.path.realpath(path)
    real_temp = os.path.realpath(_TEMP_DIR)
    if not real_path.startswith(real_temp + os.sep):
        raise ValueError(f"Invalid temp file path: {path!r}")


def safe_remove(path: str | None) -> None:
    try:
        if path and os.path.exists(path):
            os.remove(path)
            logger.debug("Removed temporary file: %s", path)
    except Exception:
        logger.exception("Failed to remove temporary file: %s", path)
