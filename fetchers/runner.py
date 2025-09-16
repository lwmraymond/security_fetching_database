"""Utilities for orchestrating multiple fetchers."""
from __future__ import annotations

import logging
from typing import Dict, Iterable, Tuple, Type

from .base import BaseFetcher
from .fetch_cisco import CiscoFetcher
from .fetch_github import GitHubFetcher
from .fetch_msrc import MicrosoftFetcher
from .fetch_nvd import NvdFetcher
from .fetch_osv import OSVFetcher

FetcherType = Type[BaseFetcher]
FETCHER_CLASSES: Tuple[FetcherType, ...] = (
    NvdFetcher,
    OSVFetcher,
    GitHubFetcher,
    MicrosoftFetcher,
    CiscoFetcher,
)


def run_all(fetcher_classes: Iterable[FetcherType] = FETCHER_CLASSES) -> Dict[str, int]:
    """Execute each fetcher sequentially and return their record counts."""

    results: Dict[str, int] = {}
    for fetcher_cls in fetcher_classes:
        try:
            fetcher = fetcher_cls()
        except Exception:
            logging.exception("Failed to initialise fetcher %s", fetcher_cls.__name__)
            config = getattr(fetcher_cls, "CONFIG", None)
            if config is not None:
                results[getattr(config, "name", fetcher_cls.__name__)] = -1
            else:
                results[fetcher_cls.__name__] = -1
            continue
        try:
            count = fetcher.run()
        except Exception:
            logging.exception("Fetcher %s failed", fetcher.source_name)
            results[fetcher.source_name] = -1
        else:
            results[fetcher.source_name] = count
        finally:
            try:
                fetcher.session.close()
            except Exception:
                pass
    return results
