"""Tests for report aggregation helpers (language merge, repo id mapping)."""

from pathlib import Path


def test_repo_id_to_repo_name():
    from scanner.output import repo_id_to_repo_name

    assert repo_id_to_repo_name("public-apis_public-apis") == "public-apis/public-apis"
    assert repo_id_to_repo_name("foo_bar") == "foo/bar"
    assert repo_id_to_repo_name("nounderscore") == "nounderscore"


def test_load_repo_languages_from_aggregate_csv_skips_empty(tmp_path: Path):
    from scanner.output import load_repo_languages_from_aggregate_csv

    p = tmp_path / "agg.csv"
    p.write_text(
        "repo_name,language,stars\n"
        "a/b,Python,\n"
        "c/d,,,\n"
        "e/f,Go,\n",
        encoding="utf-8",
    )
    m = load_repo_languages_from_aggregate_csv(p)
    assert m == {"a/b": "Python", "e/f": "Go"}
