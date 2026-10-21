import csv

from build_dataset import build_dataset


def test_build_dataset_deduplicates_balances_and_labels_urls(tmp_path) -> None:
    phishing_path = tmp_path / "phishing.csv"
    phishing_path.write_text(
        "url\n"
        "http://phish.example/login\n"
        "http://phish.example/login\n"
        "http://danger.example/account\n",
        encoding="utf-8",
    )
    tranco_path = tmp_path / "tranco.csv"
    tranco_path.write_text(
        "1,legit-one.example\n"
        "2,legit-two.example\n"
        "3,legit-three.example\n"
        "4,legit-one.example\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "processed" / "urls.csv"

    written_count = build_dataset(phishing_path, tranco_path, output_path)

    with output_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert written_count == 4
    assert list(rows[0]) == ["url", "label"]
    assert sum(row["label"] == "1" for row in rows) == 2
    assert sum(row["label"] == "0" for row in rows) == 2
    assert len({row["url"] for row in rows}) == 4
    assert all(row["url"].startswith("https://") for row in rows if row["label"] == "0")


def test_phishing_label_wins_for_cross_source_duplicate(tmp_path) -> None:
    phishing_path = tmp_path / "phishing.csv"
    phishing_path.write_text(
        "http://same.example/\n"
        "http://unique-phish.example/\n",
        encoding="utf-8",
    )
    tranco_path = tmp_path / "tranco.csv"
    tranco_path.write_text(
        "1,same.example\n"
        "2,unique-legit.example\n",
        encoding="utf-8",
    )
    output_path = tmp_path / "urls.csv"

    build_dataset(phishing_path, tranco_path, output_path)

    with output_path.open(encoding="utf-8", newline="") as csv_file:
        rows = list(csv.DictReader(csv_file))

    assert len(rows) == 2
    assert sum(row["label"] == "1" for row in rows) == 1
    assert sum(row["label"] == "0" for row in rows) == 1
    assert "https://same.example" not in {row["url"] for row in rows}
