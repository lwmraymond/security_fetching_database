"""Fetch security updates from the Microsoft MSRC Security Update Guide API."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

import requests

from .common import (
    DEFAULT_START,
    ensure_directories,
    format_datetime,
    load_state,
    new_ingest_timestamp,
    normalise_text,
    parse_datetime,
    save_state,
    write_jsonl,
)

logger = logging.getLogger(__name__)
API_URL = "https://api.msrc.microsoft.com/sug/v2.0/en-US/updates"
STATE_NAME = "microsoft_msrc"
STATE_LAST_RELEASE = "last_release"
STATE_LAST_IDS = "last_ids"
PAGE_SIZE = 100
REQUEST_TIMEOUT = 60


class MicrosoftFetcher:
    def __init__(self) -> None:
        ensure_directories()
        api_key = os.environ.get("MSRC_API_KEY")
        if not api_key:
            raise RuntimeError("MSRC_API_KEY environment variable is required")
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update(
            {
                "api-key": api_key,
                "User-Agent": "security-fetcher/0.1",
            }
        )
        self.state = load_state(STATE_NAME)
        self.last_release = parse_datetime(self.state.get(STATE_LAST_RELEASE)) or DEFAULT_START
        self.last_ids: Set[str] = set(self.state.get(STATE_LAST_IDS, []))

    def run(self) -> int:
        logger.info("Starting MSRC fetch from %s", format_datetime(self.last_release))
        records: List[Dict[str, Any]] = []
        max_release = self.last_release
        max_ids: Set[str] = set()
        next_url: Optional[str] = None
        params: Optional[Dict[str, Any]] = {
            "$filter": f"releaseDate ge {format_datetime(self.last_release - timedelta(minutes=1))}",
            "$orderby": "releaseDate",
            "$top": PAGE_SIZE,
        }

        while True:
            url = next_url or API_URL
            response = self.session.get(url, params=params if next_url is None else None, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            updates = data.get("value", [])
            if not updates:
                break

            for update in updates:
                record, release_date = self._transform(update)
                if record is None or release_date is None:
                    continue
                if release_date < self.last_release:
                    continue
                record_id = record.get("id")
                if release_date == self.last_release and record_id and record_id in self.last_ids:
                    continue
                records.append(record)
                if release_date > max_release:
                    max_release = release_date
                    max_ids = {record_id} if record_id else set()
                elif release_date == max_release and record_id:
                    max_ids.add(record_id)

            next_url = data.get("@odata.nextLink")
            if not next_url:
                break
            params = None

        if records:
            write_jsonl(STATE_NAME, records)
            self.state[STATE_LAST_RELEASE] = format_datetime(max_release)
            self.state[STATE_LAST_IDS] = sorted(id_ for id_ in max_ids if id_)
            save_state(STATE_NAME, self.state)
        logger.info("Finished MSRC fetch with %s new records", len(records))
        return len(records)

    def _transform(self, update: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[datetime]]:
        cve_number = update.get("cveNumber") or update.get("cveNumberList", [None])[0]
        record_id = cve_number or update.get("id")
        release_date = parse_datetime(update.get("releaseDate"))
        revised_date = parse_datetime(update.get("lastRevisedDate")) or release_date
        description = normalise_text(update.get("description")) or normalise_text(update.get("cveTitle"))
        severity = self._extract_severity(update)
        references = self._extract_references(update)
        patches = self._extract_patches(update)

        record = {
            "source": STATE_NAME,
            "id": record_id,
            "title": normalise_text(update.get("cveTitle")) or record_id,
            "description": description,
            "published": format_datetime(release_date),
            "modified": format_datetime(revised_date),
            "severity": severity,
            "aliases": [cve_number] if cve_number and cve_number != record_id else [],
            "affected": self._extract_affected(update),
            "references": references,
            "patches": patches,
            "source_url": update.get("articleUrl") or update.get("documentUrl"),
            "ingested_at": new_ingest_timestamp(),
            "raw": update,
        }
        return record, release_date

    def _extract_severity(self, update: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        cvss = update.get("cvssScoreSet") or {}
        base_score = cvss.get("base") or update.get("cvssScore")
        vector = cvss.get("vector") or update.get("cvssVector")
        severity = update.get("severity")
        if any(value is not None for value in (base_score, vector, severity)):
            return {
                "system": "CVSS",
                "score": base_score,
                "severity": severity,
                "vector": vector,
            }
        return None

    def _extract_affected(self, update: Dict[str, Any]) -> List[Dict[str, Any]]:
        products = update.get("product")
        if isinstance(products, list):
            product_list = products
        elif products:
            product_list = [products]
        else:
            product_list = update.get("productNames", [])
        return [
            {
                "product": product,
                "productFamily": update.get("productFamily"),
                "platform": update.get("platform"),
            }
            for product in product_list or []
        ]

    def _extract_references(self, update: Dict[str, Any]) -> List[Dict[str, Any]]:
        references: List[Dict[str, Any]] = []
        for article in update.get("kbArticles", []):
            references.append(
                {
                    "url": article.get("articleUrl"),
                    "id": article.get("articleId"),
                    "type": "KB",
                }
            )
        for url_key in ("articleUrl", "documentUrl", "cvrfUrl"):
            url = update.get(url_key)
            if url:
                references.append({"url": url, "type": url_key})
        return references

    def _extract_patches(self, update: Dict[str, Any]) -> List[Dict[str, Any]]:
        patches: List[Dict[str, Any]] = []
        for article in update.get("kbArticles", []):
            patches.append(
                {
                    "type": "KB",
                    "description": f"KB article {article.get('articleId')}",
                    "url": article.get("articleUrl"),
                }
            )
        for download in update.get("downloadUrls", []):
            patches.append(
                {
                    "type": "Download",
                    "url": download,
                }
            )
        return patches


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    fetcher = MicrosoftFetcher()
    fetcher.run()


if __name__ == "__main__":
    main()
