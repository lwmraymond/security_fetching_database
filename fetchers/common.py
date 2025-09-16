"""Shared helpers for fetcher scripts.

This module centralises filesystem helpers for writing JSONL output and
maintaining incremental state for each upstream source.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

OUTPUT_DIR = Path("output")
STATE_DIR = Path("state")
DEFAULT_START = datetime(2025, 1, 1, tzinfo=timezone.utc)


def ensure_directories() -> None:
    """Create the output and state directories if they do not exist."""
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _state_path(name: str) -> Path:
    return STATE_DIR / f"{name}.json"


def load_state(name: str) -> Dict[str, Any]:
    """Load persisted state for a fetcher.

    Parameters
    ----------
    name:
        Name of the fetcher, e.g. ``"nvd"``.
    """
    path = _state_path(name)
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_state(name: str, state: Dict[str, Any]) -> None:
    """Persist state for a fetcher atomically."""
    ensure_directories()
    path = _state_path(name)
    tmp_path = path.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2, sort_keys=True)
        fh.write("\n")
    tmp_path.replace(path)


def write_jsonl(name: str, records: Iterable[Dict[str, Any]]) -> int:
    """Append records to a JSONL file for a given fetcher.

    Parameters
    ----------
    name:
        Name of the fetcher (used as the filename stem).
    records:
        Iterable of dictionaries to serialise.

    Returns
    -------
    int
        Number of records written.
    """
    ensure_directories()
    path = OUTPUT_DIR / f"{name}.jsonl"
    count = 0
    with path.open("a", encoding="utf-8") as fh:
        for record in records:
            json.dump(record, fh, ensure_ascii=False, separators=(",", ":"))
            fh.write("\n")
            count += 1
    return count


def parse_datetime(value: Optional[Any]) -> Optional[datetime]:
    """Parse an arbitrary timestamp into an aware ``datetime``."""
    if value is None:
        return None
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # ``datetime.fromisoformat`` supports ``YYYY`` (year only) so guard.
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise TypeError(f"Unsupported datetime value: {type(value)!r}")


def format_datetime(value: Optional[datetime]) -> Optional[str]:
    """Format a datetime instance using RFC3339 representation."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, str):
        return value
    raise TypeError(f"Unsupported datetime value: {type(value)!r}")


def new_ingest_timestamp() -> str:
    """Return the current UTC time formatted for storage."""
    return format_datetime(datetime.now(timezone.utc))  # type: ignore[arg-type]


def normalise_text(text: Optional[str]) -> Optional[str]:
    if text is None:
        return None
    stripped = text.strip()
    return stripped or None


def deduplicate_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicate records based on their ``id`` field."""
    unique: Dict[str, Dict[str, Any]] = {}
    for record in records:
        record_id = record.get("id")
        if not record_id:
            continue
        unique[record_id] = record
    return list(unique.values())
