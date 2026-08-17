from pathlib import Path

from secret_scanner.ignore import IgnoreRules
from secret_scanner.scanner import ScanOptions, scan_directory, scan_file

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _line_of(path: Path, needle: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if needle in line:
            return number
    raise AssertionError(f"{needle!r} not found in {path}")


def test_scan_finds_known_secrets_in_dirty_sample():
    findings = scan_file(FIXTURES_DIR / "dirty_sample.py", FIXTURES_DIR)
    rules_found = {finding.rule for finding in findings}

    assert "aws-access-key-id" in rules_found
    assert "aws-secret-access-key" in rules_found
    assert "github-pat-classic" in rules_found
    assert "stripe-secret-key" in rules_found
    assert "generic-password-assignment" in rules_found
    assert "generic-api-key-assignment" in rules_found


def test_matched_text_is_just_the_secret_not_the_whole_assignment():
    # aws_secret_access_key = "..." needs the keyword to be *found*, but the
    # keyword and quotes aren't part of the secret and shouldn't end up in
    # the finding's matched_text (and therefore in the redacted report).
    findings = scan_file(FIXTURES_DIR / "dirty_sample.py", FIXTURES_DIR)
    aws_secret = next(f for f in findings if f.rule == "aws-secret-access-key")

    assert aws_secret.matched_text == "wJalrFAKEsecretFAKEkeyFAKEexampleFAKE01A"
    assert "aws_secret_access_key" not in aws_secret.matched_text


def test_scan_does_not_double_report_entropy_for_a_signature_match():
    path = FIXTURES_DIR / "dirty_sample.py"
    findings = scan_file(path, FIXTURES_DIR)

    api_key_line = _line_of(path, "api_key")
    rules_on_that_line = {f.rule for f in findings if f.line == api_key_line}

    assert rules_on_that_line == {"generic-api-key-assignment"}


def test_scan_finds_nothing_in_clean_sample():
    assert scan_file(FIXTURES_DIR / "clean_sample.py", FIXTURES_DIR) == []


def test_inline_ignore_marker_silences_a_line():
    assert scan_file(FIXTURES_DIR / "ignored_line.py", FIXTURES_DIR) == []


def test_scan_directory_skips_paths_matched_by_ignore_rules(tmp_path):
    (tmp_path / "keep.py").write_text('API_KEY = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")
    vendor_dir = tmp_path / "vendor"
    vendor_dir.mkdir()
    (vendor_dir / "secret.py").write_text('API_KEY = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")

    options = ScanOptions(root=tmp_path, ignore_rules=IgnoreRules(patterns=["vendor/*"]))
    findings = scan_directory(options)

    assert {finding.file for finding in findings} == {"keep.py"}


def test_scan_directory_skips_binary_files(tmp_path):
    (tmp_path / "image.bin").write_bytes(b"AKIAABCDEFGHIJKLMNOP\x00\x01\x02")

    options = ScanOptions(root=tmp_path, ignore_rules=IgnoreRules(patterns=[]))
    assert scan_directory(options) == []


def test_scan_directory_skips_default_excluded_dirs(tmp_path):
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text('token = "AKIAABCDEFGHIJKLMNOP"\n', encoding="utf-8")

    options = ScanOptions(root=tmp_path, ignore_rules=IgnoreRules(patterns=[]))
    assert scan_directory(options) == []
