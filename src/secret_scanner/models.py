from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Lets callers compare severities ("is this finding >= high?") without
# hardcoding the enum's declaration order somewhere else.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


@dataclass
class Finding:
    file: str
    line: int
    column: int
    rule: str
    severity: Severity
    description: str
    # Kept as plain text only in memory; report.py redacts it before the
    # value ever reaches stdout, a file, or JSON — see redact().
    matched_text: str
