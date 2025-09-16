"""Fetch security advisories from the GitHub Advisory Database."""
from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set

from .base import BaseFetcher
from .config import EnvKeys, Sources
from .common import (
    format_datetime,
    new_ingest_timestamp,
    normalise_text,
    parse_datetime,
)

logger = logging.getLogger(__name__)
GRAPHQL_QUERY_TEMPLATE = """
query($cursor: String) {{
  securityAdvisories(first: {page_size}, orderBy: {{field: UPDATED_AT, direction: DESC}}, after: $cursor) {{
    nodes {
      ghsaId
      cveId
      summary
      description
      severity
      permalink
      publishedAt
      updatedAt
      withdrawnAt
      references {
        url
      }
      identifiers {
        type
        value
      }
      vulnerabilities(first: 20) {
        nodes {
          package {
            ecosystem
            name
          }
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""


class GitHubFetcher(BaseFetcher):
    CONFIG = Sources.GITHUB

    def __init__(self) -> None:
        token = os.environ.get(EnvKeys.GITHUB_TOKEN)
        if not token:
            raise RuntimeError("GITHUB_TOKEN environment variable is required")
        super().__init__(self.CONFIG)
        self.session.headers.update({"Authorization": f"bearer {token}"})
        self.last_updated = self.get_last_timestamp()
        self.last_ids: Set[str] = self.get_last_ids()
        self.query = GRAPHQL_QUERY_TEMPLATE.format(
            page_size=self.config.page_size or 100,
        )

    def run(self) -> int:
        logger.info(
            "Starting %s fetch from %s",
            self.source_name.upper(),
            format_datetime(self.last_updated),
        )
        records: List[Dict[str, Any]] = []
        max_updated = self.last_updated
        max_ids: Set[str] = set()
        cursor: Optional[str] = None

        while True:
            payload = {"query": self.query, "variables": {"cursor": cursor}}
            response = self.session.post(
                self.config.api_url,
                json=payload,
                timeout=self.config.request_timeout,
            )
            response.raise_for_status()
            data = response.json()
            if "errors" in data:
                raise RuntimeError(f"GitHub GraphQL error: {data['errors']}")
            advisories = data.get("data", {}).get("securityAdvisories", {})
            nodes = advisories.get("nodes", [])
            page_info = advisories.get("pageInfo", {})
            reached_past = False

            for node in nodes:
                updated = parse_datetime(node.get("updatedAt"))
                if updated and updated < self.last_updated:
                    reached_past = True
                    break
                adv_id = node.get("cveId") or node.get("ghsaId")
                if updated and updated == self.last_updated and adv_id and adv_id in self.last_ids:
                    continue
                record = self._transform(node)
                records.append(record)
                if updated:
                    if updated > max_updated:
                        max_updated = updated
                        max_ids = {adv_id} if adv_id else set()
                    elif updated == max_updated and adv_id:
                        max_ids.add(adv_id)

            if reached_past:
                break
            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        if records:
            self.append_records(records)
            self.persist_state(timestamp=max_updated, ids=max_ids)
        logger.info(
            "Finished %s fetch with %s new records",
            self.source_name.upper(),
            len(records),
        )
        return len(records)

    def _transform(self, node: Dict[str, Any]) -> Dict[str, Any]:
        ghsa_id = node.get("ghsaId")
        cve_id = node.get("cveId")
        published = parse_datetime(node.get("publishedAt"))
        updated = parse_datetime(node.get("updatedAt"))
        severity = node.get("severity")
        references = [{"url": ref.get("url")} for ref in node.get("references", [])]
        aliases = [identifier.get("value") for identifier in node.get("identifiers", []) if identifier.get("value")]
        affected = []
        patches: List[Dict[str, Any]] = []
        for vuln in node.get("vulnerabilities", {}).get("nodes", []):
            package = vuln.get("package", {})
            affected.append(
                {
                    "package": {
                        "ecosystem": package.get("ecosystem"),
                        "name": package.get("name"),
                    },
                    "vulnerableVersionRange": vuln.get("vulnerableVersionRange"),
                    "firstPatchedVersion": vuln.get("firstPatchedVersion"),
                }
            )
            patched = vuln.get("firstPatchedVersion", {})
            if patched and patched.get("identifier"):
                patches.append(
                    {
                        "type": "PACKAGE",
                        "description": f"First patched version for {package.get('name')}",
                        "ecosystem": package.get("ecosystem"),
                        "version": patched.get("identifier"),
                    }
                )

        record_id = cve_id or ghsa_id
        return {
            "source": self.source_name,
            "id": record_id,
            "title": normalise_text(node.get("summary")) or record_id,
            "description": normalise_text(node.get("description")) or normalise_text(node.get("summary")),
            "published": format_datetime(published),
            "modified": format_datetime(updated),
            "severity": {
                "system": "GitHub",
                "severity": severity,
            }
            if severity
            else None,
            "aliases": aliases,
            "affected": affected,
            "references": references,
            "patches": patches,
            "source_url": node.get("permalink"),
            "withdrawn_at": format_datetime(parse_datetime(node.get("withdrawnAt"))),
            "ingested_at": new_ingest_timestamp(),
            "raw": node,
        }


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    fetcher = GitHubFetcher()
    fetcher.run()


if __name__ == "__main__":
    main()
