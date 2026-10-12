"""UTC timestamps with explicit uncertainty, not guessed ground truth."""

from datetime import datetime, timedelta, timezone
from typing import Any

from minisiem.config import LIMITS

UTC = timezone.utc


def timestamp(value: Any, now: datetime | None = None) -> tuple[datetime, str, str, list[str]]:
    """Preserve source spelling/zone; impute missing/invalid time with a warning."""
    now = now or datetime.now(UTC)
    original = "" if value is None else str(value)
    warnings: list[str] = []
    try:
        if value is None or value == "":
            raise ValueError("missing")
        if isinstance(value, (int, float)) or original.replace(".", "", 1).isdigit():
            dt = datetime.fromtimestamp(float(value), UTC)
            zone = "epoch/UTC"
        else:
            dt = datetime.fromisoformat(original.replace("Z", "+00:00"))
            zone = str(dt.tzinfo) if dt.tzinfo else "unspecified; assumed UTC"
            if dt.tzinfo is None:
                warnings.append("timezone_missing_assumed_UTC")
                dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
        if dt > now + timedelta(seconds=LIMITS.future_seconds):
            warnings.append("future_timestamp")
        if dt.year < 2000:
            warnings.append("very_old_timestamp")
        return dt, original, zone, warnings
    except (ValueError, TypeError, OverflowError, OSError):
        return now, original, "unknown", ["missing_or_malformed_timestamp_imputed"]


def iso(dt: datetime) -> str:
    """Stable sortable ISO string, with six fractional digits."""
    return dt.astimezone(UTC).isoformat(timespec="microseconds")
