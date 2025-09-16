"""Fetch advisories from the Cisco PSIRT openVuln API."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

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
TOKEN_URL = "https://cloudsso.cisco.com/as/token.oauth2"
API_URL = "https://api.cisco.com/security/advisories/all"
STATE_NAME = "cisco"
STATE_LAST_PUBLISHED = "last_published"
STATE_LAST_IDS = "last_ids"
PAGE_SIZE = 50
REQUEST_TIMEOUT = 60


class CiscoFetcher:
    def __init__(self) -> None:
        ensure_directories()
        client_id = os.environ.get("CISCO_CLIENT_ID")
        client_secret = os.environ.get("CISCO_CLIENT_SECRET")
        if not client_id or not client_secret:
            raise RuntimeError("CISCO_CLIENT_ID and CISCO_CLIENT_SECRET environment variables are required")
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "security-fetcher/0.1"})
        self.client_id = client_id
        self.client_secret = client_secret
        self.state = load_state(STATE_NAME)
        self.last_published = parse_datetime(self.state.get(STATE_LAST_PUBLISHED)) or DEFAULT_START
        self.last_ids: Set[str] = set(self.state.get(STATE_LAST_IDS, []))

    def run(self) -> int:
        logger.info("Starting Cisco fetch from %s", format_datetime(self.last_published))
        token = self._obtain_token()
        headers = {"Authorization": f"Bearer {token}"}
        records: List[Dict[str, Any]] = []
        max_published = self.last_published
        max_ids: Set[str] = set()
        next_url: Optional[str] = None
        params: Optional[Dict[str, Any]] = {
            "last_published": (self.last_published - timedelta(days=1)).date().isoformat(),
            "limit": PAGE_SIZE,
        }

        while True:
            url = next_url or API_URL
            response = self.session.get(
                url,
                headers=headers,
                params=params if next_url is None else None,
                timeout=REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            data = response.json()
            advisories = data.get("advisories", [])
            if not advisories:
                break

            for advisory in advisories:
                advisory_records = self._transform(advisory)
                for record, published in advisory_records:
                    if published is None:
                        continue
                    if published < self.last_published:
                        continue
                    record_id = record.get("id")
                    if published == self.last_published and record_id and record_id in self.last_ids:
                        continue
                    record["ingested_at"] = new_ingest_timestamp()
                    records.append(record)
                    if published > max_published:
                        max_published = published
                        max_ids = {record_id} if record_id else set()
                    elif published == max_published and record_id:
                        max_ids.add(record_id)

            pagination = data.get("pagination", {})
            next_url = pagination.get("next")
            if not next_url:
                break
            params = None

        if records:
            write_jsonl(STATE_NAME, records)
            self.state[STATE_LAST_PUBLISHED] = format_datetime(max_published)
            self.state[STATE_LAST_IDS] = sorted(id_ for id_ in max_ids if id_)
            save_state(STATE_NAME, self.state)
        logger.info("Finished Cisco fetch with %s new records", len(records))
        return len(records)

    def _obtain_token(self) -> str:
        response = requests.post(
            TOKEN_URL,
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        token_data = response.json()
        token = token_data.get("access_token")
        if not token:
            raise RuntimeError("Failed to obtain Cisco access token")
        return token

    def _transform(self, advisory: Dict[str, Any]) -> List[Tuple[Dict[str, Any], Optional[datetime]]]:
        advisory_id = advisory.get("advisoryId")
        first_published = parse_datetime(advisory.get("firstPublished"))
        last_updated = parse_datetime(advisory.get("lastUpdated")) or first_published
        summary = normalise_text(advisory.get("summary"))
        products = advisory.get("productNames", [])
        references = self._extract_references(advisory)
        base_record = {
            "source": STATE_NAME,
            "advisory_id": advisory_id,
            "title": summary or advisory_id,
            "description": summary,
            "published": format_datetime(first_published),
            "modified": format_datetime(last_updated),
            "references": references,
            "aliases": [advisory_id] if advisory_id else [],
            "source_url": advisory.get("publicationUrl"),
            "raw": advisory,
        }

        records: List[Tuple[Dict[str, Any], Optional[datetime]]] = []
        cve_entries = advisory.get("cves", [])
        if not cve_entries:
            record = dict(base_record)
            record["id"] = advisory_id
            record["severity"] = self._severity_from_advisory(advisory)
            record["affected"] = self._affected(products, advisory)
            record["patches"] = self._patches(advisory)
            records.append((record, first_published))
            return records

        for entry in cve_entries:
            if isinstance(entry, str):
                cve_id = entry
                details: Dict[str, Any] = {}
            else:
                cve_id = entry.get("cve") or entry.get("name")
                details = entry
            record = dict(base_record)
            record["id"] = cve_id
            record["severity"] = self._severity_from_cve(details, advisory)
            record["affected"] = self._affected(products, advisory)
            record["patches"] = self._patches(advisory)
            record["cvss"] = details.get("cvssBaseScore") or details.get("baseScore")
            records.append((record, last_updated or first_published))
        return records

    def _severity_from_advisory(self, advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sir = advisory.get("sir")
        if not sir:
            return None
        return {
            "system": "Cisco SIR",
            "severity": sir,
        }

    def _severity_from_cve(self, cve: Dict[str, Any], advisory: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        base_score = cve.get("cvssBaseScore") or cve.get("baseScore")
        vector = cve.get("vector") or cve.get("cvssVector")
        severity = cve.get("baseSeverity") or advisory.get("sir")
        if any(value is not None for value in (base_score, vector, severity)):
            return {
                "system": "CVSS",
                "score": base_score,
                "vector": vector,
                "severity": severity,
            }
        return None

    def _affected(self, products: List[str], advisory: Dict[str, Any]) -> List[Dict[str, Any]]:
        if isinstance(products, list):
            product_list = products
        elif products:
            product_list = [products]
        else:
            product_list = []
        affected = []
        for product in product_list:
            affected.append(
                {
                    "product": product,
                    "platform": advisory.get("platform"),
                    "firstFixed": advisory.get("firstFixed"),
                }
            )
        return affected

    def _patches(self, advisory: Dict[str, Any]) -> List[Dict[str, Any]]:
        patches: List[Dict[str, Any]] = []
        bug_ids = advisory.get("bugIDs") or []
        if isinstance(bug_ids, str):
            bug_ids = [bug_ids]
        for bug_id in bug_ids:
            patches.append({"type": "Bug", "id": bug_id})
        first_fixes = advisory.get("firstFixes") or []
        if isinstance(first_fixes, str):
            first_fixes = [first_fixes]
        for fix in first_fixes:
            patches.append({"type": "Fix", "description": fix})
        download_urls = advisory.get("downloadUrl") or []
        if isinstance(download_urls, str):
            download_urls = [download_urls]
        for download in download_urls:
            patches.append({"type": "Download", "url": download})
        fixed_software = advisory.get("fixedSoftware")
        if isinstance(fixed_software, list):
            for item in fixed_software:
                patches.append({"type": "Software", "description": item})
        elif fixed_software:
            patches.append({"type": "Software", "description": fixed_software})
        return patches

    def _extract_references(self, advisory: Dict[str, Any]) -> List[Dict[str, Any]]:
        references: List[Dict[str, Any]] = []
        url = advisory.get("publicationUrl")
        if url:
            references.append({"url": url, "type": "advisory"})
        for ref in advisory.get("cwe", []):
            references.append({"id": ref, "type": "CWE"})
        for signature in advisory.get("ipsSignatures", []):
            references.append({"id": signature, "type": "IPS"})
        return references


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    fetcher = CiscoFetcher()
    fetcher.run()


if __name__ == "__main__":
    main()
