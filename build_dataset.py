"""Build a balanced URL dataset from phishing and Tranco CSV files."""

from __future__ import annotations

import argparse
import csv
import random
from pathlib import Path
from urllib.parse import urlsplit

ROOT_DIR = Path(__file__).resolve().parent
PHISHING_PATH = ROOT_DIR / "data" / "raw" / "phishing.csv"
TRANCO_PATH = ROOT_DIR / "data" / "raw" / "tranco.csv"
OUTPUT_PATH = ROOT_DIR / "data" / "processed" / "urls.csv"
RANDOM_SEED = 42

_URL_HEADERS = {"url", "urls", "link", "uri", "website", "site", "hostname", "host"}
_DOMAIN_HEADERS = {"domain", "domains", "website", "site", "hostname", "host"}


def _normalized_header(value: str) -> str:
    return "".join(character for character in value.lower().strip() if character.isalnum())


def _header_column(rows: list[list[str]], kind: str) -> tuple[int, int | None]:
    """Return the row and column of a recognized URL/domain header, if present."""
    if not rows:
        return 0, None

    normalized = [_normalized_header(cell) for cell in rows[0]]
    aliases = _URL_HEADERS if kind == "phishing" else _DOMAIN_HEADERS

    for index, name in enumerate(normalized):
        if name in aliases or name.endswith("url") or name.endswith("domain"):
            return 1, index

    return 0, None


def _looks_like_address(value: str) -> bool:
    candidate = value.strip()
    return bool(candidate) and ("." in candidate or "://" in candidate)


def _column_without_header(rows: list[list[str]], kind: str) -> int:
    """Infer a data column for common headerless URL and Tranco CSV formats."""
    if kind == "legitimate" and len(rows[0]) > 1:
        first_value = rows[0][0].strip()
        if first_value.isdigit():
            return 1

    width = max(len(row) for row in rows)
    scores = [
        sum(index < len(row) and _looks_like_address(row[index]) for row in rows)
        for index in range(width)
    ]
    return max(range(width), key=scores.__getitem__)


def _read_addresses(path: Path, kind: str) -> list[str]:
    with path.open("r", encoding="utf-8-sig", newline="") as csv_file:
        rows = [row for row in csv.reader(csv_file) if row]

    if not rows:
        raise ValueError(f"No rows found in {path}")

    start_row, column = _header_column(rows, kind)
    if column is None:
        column = _column_without_header(rows, kind)

    values = [
        row[column].strip()
        for row in rows[start_row:]
        if column < len(row) and row[column].strip()
    ]
    if not values:
        raise ValueError(f"No usable {kind} URLs/domains found in {path}")
    return values


def _with_https(domain: str) -> str:
    candidate = domain.strip()
    if urlsplit(candidate).scheme:
        return candidate
    return f"https://{candidate}"


def _duplicate_key(url: str) -> tuple[str, str, str]:
    candidate = url.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    return (
        parsed.netloc.lower(),
        parsed.path or "/",
        parsed.query,
    )


def _unique_by_address(urls: list[str]) -> list[str]:
    unique: dict[tuple[str, str, str], str] = {}
    for url in urls:
        unique.setdefault(_duplicate_key(url), url)
    return list(unique.values())


def build_dataset(
    phishing_path: Path = PHISHING_PATH,
    tranco_path: Path = TRANCO_PATH,
    output_path: Path = OUTPUT_PATH,
    *,
    random_seed: int = RANDOM_SEED,
) -> int:
    """Create a balanced CSV and return the number of rows written."""
    phishing_urls = _unique_by_address(
        _read_addresses(phishing_path, "phishing")
    )
    legitimate_urls = _unique_by_address(
        [_with_https(domain) for domain in _read_addresses(tranco_path, "legitimate")]
    )

    # If a URL appears in both sources, retain it only as phishing to avoid
    # assigning a known phishing URL a legitimate label.
    phishing_keys = {_duplicate_key(url) for url in phishing_urls}
    legitimate_urls = [
        url for url in legitimate_urls if _duplicate_key(url) not in phishing_keys
    ]

    sample_size = min(len(phishing_urls), len(legitimate_urls))
    if sample_size == 0:
        raise ValueError(
            "Cannot create a balanced dataset: both input files must contain "
            "at least one unique URL after removing cross-source duplicates."
        )

    rng = random.Random(random_seed)
    phishing_sample = rng.sample(phishing_urls, sample_size)
    legitimate_sample = rng.sample(legitimate_urls, sample_size)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(("url", "label"))
        writer.writerows((url, 1) for url in phishing_sample)
        writer.writerows((url, 0) for url in legitimate_sample)

    return sample_size * 2


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--phishing",
        type=Path,
        default=PHISHING_PATH,
        help=f"Phishing CSV path (default: {PHISHING_PATH})",
    )
    parser.add_argument(
        "--tranco",
        type=Path,
        default=TRANCO_PATH,
        help=f"Tranco CSV path (default: {TRANCO_PATH})",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help=f"Output CSV path (default: {OUTPUT_PATH})",
    )
    args = parser.parse_args()

    count = build_dataset(args.phishing, args.tranco, args.output)
    print(f"Wrote {count} balanced URL rows to {args.output}")


if __name__ == "__main__":
    main()
