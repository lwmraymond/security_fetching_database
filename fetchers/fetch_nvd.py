"""Fetch CVE data from the NVD v2 API and store it as JSONL."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set

from .base import BaseFetcher
from .config import Sources
from .common import (
    format_datetime,
    new_ingest_timestamp,
    normalise_text,
    parse_datetime,
)

logger = logging.getLogger(__name__)
RATE_LIMIT_SLEEP = 15


class NvdFetcher(BaseFetcher):
    CONFIG = Sources.NVD

    def __init__(self) -> None:
        super().__init__(self.CONFIG)
        self.last_modified = self.get_last_timestamp()
        self.last_ids: Set[str] = self.get_last_ids()

    def run(self) -> int:
        logger.info(
            "Starting %s fetch from %s",
            self.source_name.upper(),
            format_datetime(self.last_modified),
        )
        records: List[Dict[str, Any]] = []
        max_modified = self.last_modified
        max_ids: Set[str] = set()
        start_index = 0
        results_per_page = self.config.page_size or 2000

        while True:
            params = {
                "resultsPerPage": results_per_page,
                "startIndex": start_index,
                "lastModifiedStartDate": format_datetime(self.last_modified - timedelta(minutes=1)),
            }
            logger.debug("Requesting %s with params %s", self.config.api_url, params)
            response = self.session.get(
                self.config.api_url,
                params=params,
                timeout=self.config.request_timeout,
            )
            if response.status_code == 429:
                logger.warning("NVD rate limit hit, sleeping for %s seconds", RATE_LIMIT_SLEEP)
                time.sleep(RATE_LIMIT_SLEEP)
                continue
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                record, modified_dt = self._transform(item)
                if record is None or modified_dt is None:
                    continue
                if modified_dt < self.last_modified:
                    continue
                cve_id = record.get("id")
                if (
                    modified_dt == self.last_modified
                    and cve_id
                    and cve_id in self.last_ids
                ):
                    continue
                records.append(record)
                if modified_dt > max_modified:
                    max_modified = modified_dt
                    max_ids = {cve_id} if cve_id else set()
                elif modified_dt == max_modified and cve_id:
                    max_ids.add(cve_id)

            total_results = data.get("totalResults")
            start_index = data.get("startIndex", start_index) + data.get(
                "resultsPerPage",
                results_per_page,
            )
            if total_results is not None and start_index >= total_results:
                break

        if records:
            self.append_records(records)
            self.persist_state(timestamp=max_modified, ids=max_ids)
        logger.info(
            "Finished %s fetch with %s new records",
            self.source_name.upper(),
            len(records),
        )
        return len(records)

    def _transform(self, item: Dict[str, Any]) -> tuple[Optional[Dict[str, Any]], Optional[datetime]]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        published = parse_datetime(cve.get("published"))
        modified = parse_datetime(cve.get("lastModified"))
        description = self._get_description(cve)
        severity = self._extract_severity(cve)
        affected = self._extract_affected(cve)
        references = self._extract_references(cve)
        patches = [
            {
                "type": "reference",
                "description": normalise_text(", ".join(ref.get("tags", [])) or "Patch"),
                "url": ref.get("url"),
            }
            for ref in cve.get("references", [])
            if any(tag.lower() in {"patch", "vendor advisory"} for tag in ref.get("tags", []))
        ]

        record = {
            "source": self.source_name,
            "id": cve_id,
            "title": cve_id,
            "description": description,
            "published": format_datetime(published),
            "modified": format_datetime(modified),
            "severity": severity,
            "affected": affected,
            "references": references,
            "patches": patches,
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            "ingested_at": new_ingest_timestamp(),
            "raw": item,
        }
        return record, modified

    def _get_description(self, cve: Dict[str, Any]) -> Optional[str]:
        descriptions = cve.get("descriptions", [])
        for entry in descriptions:
            if entry.get("lang") == "en":
                return normalise_text(entry.get("value"))
        return normalise_text(descriptions[0].get("value")) if descriptions else None

    def _extract_severity(self, cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if not entries:
                continue
            metric = entries[0]
            cvss_data = metric.get("cvssData", {})
            base_score = metric.get("baseScore") or cvss_data.get("baseScore")
            base_severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity")
            vector = cvss_data.get("vectorString")
            version = cvss_data.get("version") or key.replace("cvssMetric", "CVSS")
            return {
                "system": version,
                "score": base_score,
                "severity": base_severity,
                "vector": vector,
            }
        return None

    def _extract_affected(self, cve: Dict[str, Any]) -> List[Dict[str, Any]]:
        affected: List[Dict[str, Any]] = []
        for configuration in cve.get("configurations", []):
            for node in configuration.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue
                    criteria = match.get("criteria") or match.get("cpe23Uri")
                    vendor, product, version = self._parse_cpe(criteria)
                    affected.append(
                        {
                            "vendor": vendor,
                            "product": product,
                            "cpe": criteria,
                            "versions": {
                                "version": version,
                                "versionStartIncluding": match.get("versionStartIncluding"),
                                "versionStartExcluding": match.get("versionStartExcluding"),
                                "versionEndIncluding": match.get("versionEndIncluding"),
                                "versionEndExcluding": match.get("versionEndExcluding"),
                            },
                        }
                    )
        return affected

    def _extract_references(self, cve: Dict[str, Any]) -> List[Dict[str, Any]]:
        references = []
        for ref in cve.get("references", []):
            references.append(
                {
                    "url": ref.get("url"),
                    "tags": ref.get("tags", []),
                }
            )
        return references

    def _parse_cpe(self, cpe: Optional[str]) -> tuple[Optional[str], Optional[str], Optional[str]]:
        if not cpe or not cpe.startswith("cpe:2.3:"):
            return None, None, None
        parts = cpe.split(":")
        vendor = parts[3] if len(parts) > 3 and parts[3] not in {"*", "-"} else None
        product = parts[4] if len(parts) > 4 and parts[4] not in {"*", "-"} else None
        version = parts[5] if len(parts) > 5 and parts[5] not in {"*", "-"} else None
        return vendor, product, version


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    fetcher = NvdFetcher()
    fetcher.run()


if __name__ == "__main__":
    main()
