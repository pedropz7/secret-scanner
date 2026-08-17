from __future__ import annotations

import json
from dataclasses import asdict

from .models import Finding, Severity

_SEVERITY_COLOR = {
    Severity.CRITICAL: "\033[97;41m",  # white on red background
    Severity.HIGH: "\033[91m",  # red
    Severity.MEDIUM: "\033[93m",  # yellow
    Severity.LOW: "\033[94m",  # blue
}
_RESET = "\033[0m"


def redact(value: str) -> str:
    """Never print a real secret in full by default — a report is exactly
    the kind of file that ends up committed, pasted into a ticket, or
    screen-shared. Short values are fully masked; longer ones keep just
    enough of each end to be recognizable without being usable."""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]} ({len(value)} caracteres)"


def format_text(findings: list[Finding], *, reveal: bool = False, use_color: bool = True) -> str:
    if not findings:
        return "Nenhum segredo encontrado."

    findings_by_file: dict[str, list[Finding]] = {}
    for finding in findings:
        findings_by_file.setdefault(finding.file, []).append(finding)

    lines: list[str] = []
    for file, file_findings in sorted(findings_by_file.items()):
        lines.append(f"\n{file}")
        for finding in sorted(file_findings, key=lambda f: (f.line, f.column)):
            snippet = finding.matched_text if reveal else redact(finding.matched_text)
            color = _SEVERITY_COLOR[finding.severity] if use_color else ""
            reset = _RESET if use_color else ""
            lines.append(
                f"  {color}[{finding.severity.value.upper()}]{reset} "
                f"linha {finding.line}:{finding.column} — {finding.description} ({finding.rule})"
            )
            lines.append(f"      {snippet}")

    lines.append(f"\nTotal: {len(findings)} possível(is) segredo(s) encontrado(s).")
    return "\n".join(lines)


def format_json(findings: list[Finding], *, reveal: bool = False) -> str:
    payload = []
    for finding in findings:
        data = asdict(finding)
        data["severity"] = finding.severity.value
        if not reveal:
            data["matched_text"] = redact(finding.matched_text)
        payload.append(data)

    return json.dumps({"total": len(findings), "findings": payload}, indent=2, ensure_ascii=False)
