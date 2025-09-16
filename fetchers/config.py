"""Centralised configuration for vulnerability fetchers."""
from __future__ import annotations

from dataclasses import dataclass

USER_AGENT = "security-fetcher/0.1"
DEFAULT_TIMEOUT = 60


class EnvKeys:
    """Names of environment variables required by specific fetchers."""

    GITHUB_TOKEN = "GITHUB_TOKEN"
    MSRC_API_KEY = "MSRC_API_KEY"
    CISCO_CLIENT_ID = "CISCO_CLIENT_ID"
    CISCO_CLIENT_SECRET = "CISCO_CLIENT_SECRET"


@dataclass(frozen=True)
class SourceConfig:
    """Configuration describing how a source persists incremental state."""

    name: str
    api_url: str
    timestamp_field: str
    ids_field: str
    request_timeout: int = DEFAULT_TIMEOUT
    page_size: int | None = None
    token_url: str | None = None


class Sources:
    """Source metadata shared across fetcher implementations."""

    NVD = SourceConfig(
        name="nvd",
        api_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        timestamp_field="last_modified",
        ids_field="last_ids",
        request_timeout=60,
        page_size=2000,
    )

    OSV = SourceConfig(
        name="osv",
        api_url="https://api.osv.dev/v1/vulns",
        timestamp_field="last_modified",
        ids_field="last_ids",
        request_timeout=60,
        page_size=100,
    )

    GITHUB = SourceConfig(
        name="github",
        api_url="https://api.github.com/graphql",
        timestamp_field="last_updated",
        ids_field="last_ids",
        request_timeout=60,
        page_size=100,
    )

    MICROSOFT_MSRC = SourceConfig(
        name="microsoft_msrc",
        api_url="https://api.msrc.microsoft.com/sug/v2.0/en-US/updates",
        timestamp_field="last_release",
        ids_field="last_ids",
        request_timeout=60,
        page_size=100,
    )

    CISCO = SourceConfig(
        name="cisco",
        api_url="https://api.cisco.com/security/advisories/all",
        timestamp_field="last_published",
        ids_field="last_ids",
        request_timeout=60,
        page_size=50,
        token_url="https://cloudsso.cisco.com/as/token.oauth2",
    )
