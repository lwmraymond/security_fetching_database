"""Fetch advisories from the Cisco PSIRT openVuln API."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from .base import BaseFetcher
from .config import EnvKeys, Sources
from .common import (
    format_datetime,
    new_ingest_timestamp,
    normalise_text,
    parse_datetime,
)

logger = logging.getLogger(__name__)
class CiscoFetcher(BaseFetcher):
    CONFIG = Sources.CISCO

    def __init__(self) -> None:
        client_id = os.environ.get(EnvKeys.CISCO_CLIENT_ID)
        client_secret = os.environ.get(EnvKeys.CISCO_CLIENT_SECRET)
        if not client_id or not client_secret:
            raise RuntimeError("CISCO_CLIENT_ID and CISCO_CLIENT_SECRET environment variables are required")
        super().__init__(self.CONFIG)
        self.client_id = client_id
        self.client_secret = client_secret
        self.last_published = self.get_last_timestamp()
        self.last_ids: Set[str] = self.get_last_ids()

    def run(self) -> int:
        logger.info(
            "Starting %s fetch from %s",
            self.source_name.upper(),
            format_datetime(self.last_published),
        )
        token = self._obtain_token()
        headers = {"Authorization": f"Bearer {token}"}
        records: List[Dict[str, Any]] = []
        max_published = self.last_published
        max_ids: Set[str] = set()
        next_url: Optional[str] = None
        params: Optional[Dict[str, Any]] = {
            "last_published": (self.last_published - timedelta(days=1)).date().isoformat(),
            "limit": self.config.page_size or 50,
        }

        while True:
            url = next_url or self.config.api_url
            response = self.session.get(
                url,
                headers=headers,
                params=params if next_url is None else None,
                timeout=self.config.request_timeout,
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
            self.append_records(records)
            self.persist_state(timestamp=max_published, ids=max_ids)
        logger.info(
            "Finished %s fetch with %s new records",
            self.source_name.upper(),
            len(records),
        )
        return len(records)

    def _obtain_token(self) -> str:
        token_url = self.config.token_url
        if not token_url:
            raise RuntimeError("Cisco token URL is not configured")
        response = requests.post(
            token_url,
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            timeout=self.config.request_timeout,
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
            "source": self.source_name,
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
