import re
from dataclasses import dataclass

from .models import Severity


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: Severity
    description: str


def matched_value(pattern: Pattern, match: re.Match) -> str:
    """The secret itself, for patterns like `aws_secret_access_key = "..."`
    where the surrounding keyword was needed to *find* the match but isn't
    part of the secret; falls back to the whole match for patterns where the
    match already *is* just the token (e.g. an `AKIA...` key)."""
    if "value" in pattern.regex.groupindex:
        return match.group("value")
    return match.group(0)


# Known secret formats, ordered roughly from most to least specific. Each
# regex is deliberately tied to a real provider's token *shape* (prefix,
# length, charset) rather than a bare "long random string" — that's what
# keeps the false-positive rate low enough to be usable; the entropy.py
# module covers the generic case these can't name.
PATTERNS: list[Pattern] = [
    Pattern(
        "aws-access-key-id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
        "AWS Access Key ID",
    ),
    Pattern(
        "aws-secret-access-key",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9/+=]{40})[\"']?"),
        Severity.CRITICAL,
        "AWS Secret Access Key",
    ),
    Pattern(
        "github-pat-classic",
        re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        Severity.CRITICAL,
        "GitHub Personal Access Token (classic)",
    ),
    Pattern(
        "github-pat-fine-grained",
        re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        Severity.CRITICAL,
        "GitHub Fine-grained Personal Access Token",
    ),
    Pattern(
        "github-oauth-token",
        re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
        Severity.HIGH,
        "GitHub OAuth Token",
    ),
    Pattern(
        "slack-token",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
        Severity.HIGH,
        "Slack Token",
    ),
    Pattern(
        "slack-webhook-url",
        re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"),
        Severity.MEDIUM,
        "Slack Incoming Webhook URL",
    ),
    Pattern(
        "google-api-key",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
        Severity.HIGH,
        "Google API Key",
    ),
    Pattern(
        "stripe-secret-key",
        re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{24,}\b"),
        Severity.CRITICAL,
        "Stripe Secret Key",
    ),
    Pattern(
        "private-key-block",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Private key block",
    ),
    Pattern(
        "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.MEDIUM,
        "JSON Web Token",
    ),
    Pattern(
        "db-connection-string",
        re.compile(r"(?i)\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s\"']+:[^@\s\"']+@"),
        Severity.HIGH,
        "Database connection string with embedded credentials",
    ),
    Pattern(
        "generic-api-key-assignment",
        re.compile(
            r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
            r"\s*[:=]\s*[\"'](?P<value>[A-Za-z0-9_\-/+=]{16,})[\"']"
        ),
        Severity.HIGH,
        "Generic API key/secret assignment",
    ),
    Pattern(
        "generic-password-assignment",
        re.compile(r"(?i)password\s*[:=]\s*[\"'](?P<value>[^\"'\s]{6,})[\"']"),
        Severity.LOW,
        "Generic password assignment (kept LOW severity: highest false-positive rate of all rules)",
    ),
]
