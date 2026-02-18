import os


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        result = int(value)
        if result <= 0:
            raise ValueError("Must be positive")
        return result
    except ValueError:
        raise ValueError(
            f"Environment variable {name!r} must be a positive integer, got {value!r}"
        )


# MWDB API
MWDB_API_URL = os.getenv("CLAMYARA_MWDB_API_URL")
MWDB_API_KEY = os.getenv("CLAMYARA_MWDB_API_KEY")

# Enable scanners
YARA_ENABLED = _env_bool("CLAMYARA_YARA_ENABLED", True)
CLAMAV_ENABLED = _env_bool("CLAMYARA_CLAMAV_ENABLED", True)

# YARA
YARA_RULES_PATH = os.getenv(
    "CLAMYARA_YARA_RULES_PATH",
    "/opt/yara/rules.yar",
)

# Safety
MAX_FILE_SIZE = _env_int("CLAMYARA_MAX_FILE_SIZE", 50 * 1024 * 1024)  # 50 MB
