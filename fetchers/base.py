"""Base classes shared by fetcher implementations."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, Set

import requests

from .common import (
    DEFAULT_START,
    ensure_directories,
    format_datetime,
    load_state,
    parse_datetime,
    save_state,
    write_jsonl,
)
from .config import USER_AGENT, SourceConfig


class BaseFetcher:
    """Reusable functionality for fetchers that persist incremental state."""

    def __init__(self, config: SourceConfig) -> None:
        self.config = config
        ensure_directories()
        self.session = self.create_session()
        self.state = load_state(config.name)

    def create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        return session

    @property
    def source_name(self) -> str:
        return self.config.name

    def get_last_timestamp(self, *, default: datetime = DEFAULT_START) -> datetime:
        value = parse_datetime(self.state.get(self.config.timestamp_field))
        return value or default

    def get_last_ids(self) -> Set[str]:
        return set(self.state.get(self.config.ids_field, []))

    def persist_state(self, *, timestamp: datetime, ids: Iterable[str]) -> None:
        self.state[self.config.timestamp_field] = format_datetime(timestamp)
        self.state[self.config.ids_field] = sorted({id_ for id_ in ids if id_})
        save_state(self.config.name, self.state)

    def append_records(self, records: Iterable[Dict[str, Any]]) -> int:
        return write_jsonl(self.config.name, records)
