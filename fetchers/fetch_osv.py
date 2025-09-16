"""Fetch vulnerability data from the OSV API."""
from __future__ import annotations

import logging
from datetime import timedelta
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
API_URL = "https://api.osv.dev/v1/vulns"
STATE_NAME = "osv"
STATE_LAST_MODIFIED = "last_modified"
STATE_LAST_IDS = "last_ids"
PAGE_SIZE = 100
REQUEST_TIMEOUT = 60


class OSVFetcher:
    def __init__(self) -> None:
        ensure_directories()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "security-fetcher/0.1"})
        self.state = load_state(STATE_NAME)
        self.last_modified = parse_datetime(self.state.get(STATE_LAST_MODIFIED)) or DEFAULT_START
        self.last_ids: Set[str] = set(self.state.get(STATE_LAST_IDS, []))

    def run(self) -> int:
        logger.info("Starting OSV fetch from %s", format_datetime(self.last_modified))
        records: List[Dict[str, Any]] = []
        max_modified = self.last_modified
        max_ids: Set[str] = set()
        page_token: Optional[str] = None

        while True:
            params: Dict[str, Any] = {"page_size": PAGE_SIZE}
            if page_token:
                params["page_token"] = page_token
            params["modified_since"] = format_datetime(self.last_modified - timedelta(minutes=1))
            response = self.session.get(API_URL, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            vulns = data.get("vulns") or data.get("results") or []
            if not vulns:
                break

            for vuln in vulns:
                record, modified = self._transform(vuln)
                if record is None or modified is None:
                    continue
                if modified < self.last_modified:
                    continue
                vuln_id = record.get("id")
                if modified == self.last_modified and vuln_id and vuln_id in self.last_ids:
                    continue
                records.append(record)
                if modified > max_modified:
                    max_modified = modified
                    max_ids = {vuln_id} if vuln_id else set()
                elif modified == max_modified and vuln_id:
                    max_ids.add(vuln_id)

            page_token = data.get("next_page_token") or data.get("nextPageToken")
            if not page_token:
                break

        if records:
            write_jsonl(STATE_NAME, records)
            self.state[STATE_LAST_MODIFIED] = format_datetime(max_modified)
            self.state[STATE_LAST_IDS] = sorted(id_ for id_ in max_ids if id_)
            save_state(STATE_NAME, self.state)
        logger.info("Finished OSV fetch with %s new records", len(records))
        return len(records)

    def _transform(self, vuln: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[datetime]]:
        vuln_id = vuln.get("id")
        published = parse_datetime(vuln.get("published"))
        modified = parse_datetime(vuln.get("modified"))
        summary = normalise_text(vuln.get("summary"))
        details = normalise_text(vuln.get("details"))
        severity = self._extract_severity(vuln)
        aliases = vuln.get("aliases", [])

        record = {
            "source": STATE_NAME,
            "id": vuln_id,
            "title": summary or vuln_id,
            "description": details or summary,
            "published": format_datetime(published),
            "modified": format_datetime(modified),
            "severity": severity,
            "aliases": aliases,
            "affected": self._extract_affected(vuln),
            "references": vuln.get("references", []),
            "patches": self._extract_patches(vuln),
            "source_url": f"https://osv.dev/vulnerability/{vuln_id}" if vuln_id else None,
            "ingested_at": new_ingest_timestamp(),
            "raw": vuln,
        }
        return record, modified

    def _extract_severity(self, vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        severities = vuln.get("severity", [])
        for entry in severities:
            score = entry.get("score")
            if not score:
                continue
            if isinstance(score, (int, float)):
                score_value = score
                vector = None
            else:
                score_value = None
                vector = score
            return {
                "system": entry.get("type"),
                "score": score_value,
                "vector": vector,
            }
        return None

    def _extract_affected(self, vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
        affected_list: List[Dict[str, Any]] = []
        for entry in vuln.get("affected", []):
            package = entry.get("package", {})
            ranges = entry.get("ranges", [])
            events = []
            for range_entry in ranges:
                events.extend(range_entry.get("events", []))
            affected_list.append(
                {
                    "package": {
                        "ecosystem": package.get("ecosystem"),
                        "name": package.get("name"),
                        "purl": package.get("purl"),
                    },
                    "versions": entry.get("versions", []),
                    "ranges": ranges,
                    "events": events,
                }
            )
        return affected_list

    def _extract_patches(self, vuln: Dict[str, Any]) -> List[Dict[str, Any]]:
        patches: List[Dict[str, Any]] = []
        for entry in vuln.get("references", []):
            ref_type = (entry.get("type") or "").upper()
            if ref_type in {"FIX", "PATCH", "ADVISORY"}:
                patches.append(
                    {
                        "type": ref_type,
                        "description": normalise_text(entry.get("title")),
                        "url": entry.get("url"),
                    }
                )
        for aff in vuln.get("affected", []):
            package = aff.get("package", {})
            for range_entry in aff.get("ranges", []):
                for event in range_entry.get("events", []):
                    fixed_version = event.get("fixed") or event.get("limit")
                    if fixed_version:
                        patches.append(
                            {
                                "type": "VERSION",
                                "description": f"Fixed in {package.get('name')} {fixed_version}",
                                "ecosystem": package.get("ecosystem"),
                                "version": fixed_version,
                            }
                        )
        return patches


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    fetcher = OSVFetcher()
    fetcher.run()


if __name__ == "__main__":
    main()
