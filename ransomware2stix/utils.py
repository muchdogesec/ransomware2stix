
import unicodedata


def sanitize_str(value: str) -> str:
    if not isinstance(value, str):
        return value

    # PostgreSQL-safe constraint: only remove null bytes
    return value.replace("\x00", "")