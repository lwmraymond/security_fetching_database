"""Command line entry-point for running all fetchers sequentially."""
from __future__ import annotations

import logging

from .runner import run_all


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    results = run_all()
    for source, count in results.items():
        if count >= 0:
            logging.info("Fetcher %s processed %s new records", source, count)
        else:
            logging.error("Fetcher %s failed", source)


if __name__ == "__main__":
    main()
