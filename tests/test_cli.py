import json
from pathlib import Path

import pytest

from secret_scanner.cli import main

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def test_main_exits_nonzero_when_high_severity_findings_exist():
    assert main([str(FIXTURES_DIR / "dirty_sample.py")]) == 1


def test_main_exits_zero_on_clean_file():
    assert main([str(FIXTURES_DIR / "clean_sample.py")]) == 0


def test_main_fail_on_none_always_exits_zero():
    assert main([str(FIXTURES_DIR / "dirty_sample.py"), "--fail-on", "none"]) == 0


def test_main_redacts_secrets_by_default(capsys):
    main([str(FIXTURES_DIR / "dirty_sample.py"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    aws_finding = next(f for f in payload["findings"] if f["rule"] == "aws-access-key-id")
    assert aws_finding["matched_text"] != "AKIAABCDEFGHIJKLMNOP"
    assert "..." in aws_finding["matched_text"]


def test_main_reveal_shows_the_full_secret(capsys):
    main([str(FIXTURES_DIR / "dirty_sample.py"), "--format", "json", "--reveal"])
    payload = json.loads(capsys.readouterr().out)

    matched_values = {finding["matched_text"] for finding in payload["findings"]}
    assert "AKIAABCDEFGHIJKLMNOP" in matched_values


def test_main_respects_ignore_file(tmp_path, capsys):
    (tmp_path / ".secretscanignore").write_text("vendor/*\n", encoding="utf-8")
    (tmp_path / "app.py").write_text('KEY = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "lib.py").write_text('KEY = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")

    exit_code = main([str(tmp_path), "--format", "json", "--fail-on", "none"])
    payload = json.loads(capsys.readouterr().out)

    assert {finding["file"] for finding in payload["findings"]} == {"app.py"}
    assert exit_code == 0


def test_main_errors_on_a_nonexistent_path():
    with pytest.raises(SystemExit):
        main(["/path/that/does/not/exist/at/all"])


def test_main_can_scan_a_single_file_instead_of_a_directory(capsys):
    main([str(FIXTURES_DIR / "clean_sample.py"), "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert payload["total"] == 0
