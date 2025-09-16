# security_fetching_database

This repository collects security vulnerability data from multiple public
sources and serialises it into a unified JSONL format. Each data source has a
standalone Python fetcher that retrieves updates for the 2025 calendar year and
stores them under `output/<source>.jsonl`. Incremental state is kept under
`state/<source>.json` so repeated runs only download new or recently updated
records.

## Prerequisites

1. Python 3.11+ (Python 3.12 is bundled with the development container).
2. Install dependencies once:

   ```bash
   pip install -r requirements.txt
   ```

3. Export credentials for the authenticated data sources:

   | Source   | Environment variables |
   |----------|----------------------|
   | GitHub Security Advisories | `GITHUB_TOKEN` (classic token with the `security_events` scope) |
   | Microsoft MSRC | `MSRC_API_KEY` (register for a key at the [MSRC portal](https://aka.ms/msrcportal)) |
   | Cisco PSIRT openVuln | `CISCO_CLIENT_ID`, `CISCO_CLIENT_SECRET` |

   The NVD and OSV APIs do not require authentication by default, although an
   NVD API key can be configured via the `NVD_API_KEY` environment variable if
   you wish to extend the scripts later.

## Running individual fetchers

Each fetcher writes newline-delimited JSON records to its respective file. Run a
single fetcher with Python:

```bash
python -m fetchers.fetch_nvd
python -m fetchers.fetch_osv
python -m fetchers.fetch_github
python -m fetchers.fetch_msrc
python -m fetchers.fetch_cisco
```

The first execution seeds the incremental state at `2025-01-01T00:00:00Z`. Every
subsequent run resumes from the latest `modified`/`published` timestamp that was
processed and avoids writing duplicate records even when upstream APIs return
updated entries with the same timestamp.

## Output schema

All fetchers emit a consistent envelope with the following top-level keys:

| Field | Description |
|-------|-------------|
| `source` | Identifier for the upstream data source (e.g. `nvd`, `osv`). |
| `id` | CVE, GHSA, or vendor-specific identifier. |
| `title` and `description` | Human readable summary text. |
| `published` / `modified` | RFC3339 timestamps. |
| `severity` | Normalised severity dictionary when the upstream source provides scoring data. |
| `aliases` | Alternate identifiers where available. |
| `affected` | List describing impacted products or packages. |
| `references` | URLs or identifiers linked to advisories, bulletins, or KB articles. |
| `patches` | Known fixes such as patched versions, KB articles, or firmware downloads. |
| `source_url` | Canonical advisory URL when supplied by the provider. |
| `ingested_at` | Timestamp when the record was written locally. |
| `raw` | Full upstream payload for traceability.

Because the files are JSONL, they can be streamed into downstream storage or
further transformed with standard tooling.

## Cleaning up

Generated `output/` and `state/` folders are git-ignored. Delete them to force a
fresh run:

```bash
rm -rf output state
```
