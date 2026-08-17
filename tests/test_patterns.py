import pytest

from secret_scanner.patterns import PATTERNS

# One realistic (but fake) example per rule, used to prove the regex
# actually matches the shape it claims to detect.
EXAMPLES = {
    "aws-access-key-id": "AKIAABCDEFGHIJKLMNOP",
    "aws-secret-access-key": 'aws_secret_access_key = "wJalrFAKEsecretFAKEkeyFAKEexampleFAKE01A"',
    "github-pat-classic": "ghp_" + "a" * 36,
    "github-pat-fine-grained": "github_pat_" + "a" * 82,
    "github-oauth-token": "gho_" + "a" * 36,
    "slack-token": "xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx",
    "slack-webhook-url": "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
    "google-api-key": "AIza" + "a" * 35,
    "stripe-secret-key": "sk_test_" + "a" * 24,
    "private-key-block": "-----BEGIN RSA PRIVATE KEY-----",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "db-connection-string": "postgres://user:password@localhost:5432/db",
    "generic-api-key-assignment": 'api_key = "abcdefghijklmnopqrstuvwx"',
    "generic-password-assignment": 'password = "SuperSecret1"',
}


def test_every_pattern_has_a_matching_example():
    assert set(EXAMPLES) == {pattern.name for pattern in PATTERNS}


@pytest.mark.parametrize("pattern", PATTERNS, ids=lambda p: p.name)
def test_pattern_matches_its_example(pattern):
    assert pattern.regex.search(EXAMPLES[pattern.name])


def test_patterns_do_not_match_plain_english_prose():
    text = "This is just a normal sentence about deploying an application to production."
    for pattern in PATTERNS:
        assert not pattern.regex.search(text), f"{pattern.name} false-positived on plain prose"
