from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from .entropy import DEFAULT_MIN_LENGTH, find_high_entropy_strings
from .ignore import (
    DEFAULT_EXCLUDED_DIRS,
    DEFAULT_EXCLUDED_EXTENSIONS,
    INLINE_IGNORE_MARKER,
    IgnoreRules,
    is_probably_binary,
)
from .models import Finding, Severity
from .patterns import PATTERNS, matched_value


@dataclass
class ScanOptions:
    root: Path
    ignore_rules: IgnoreRules
    use_entropy: bool = True
    min_entropy_length: int = DEFAULT_MIN_LENGTH


def iter_scannable_files(options: ScanOptions) -> Iterator[Path]:
    for path in sorted(options.root.rglob("*")):
        if path.is_dir():
            continue
        if any(part in DEFAULT_EXCLUDED_DIRS for part in path.relative_to(options.root).parts):
            continue
        if path.suffix.lower() in DEFAULT_EXCLUDED_EXTENSIONS:
            continue

        relative = path.relative_to(options.root).as_posix()
        if options.ignore_rules.is_ignored(relative):
            continue
        if is_probably_binary(path):
            continue

        yield path


def scan_file(
    path: Path, root: Path, *, use_entropy: bool = True, min_entropy_length: int = DEFAULT_MIN_LENGTH
) -> list[Finding]:
    findings: list[Finding] = []
    relative = path.relative_to(root).as_posix()

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return findings

    for line_number, line in enumerate(text.splitlines(), start=1):
        if INLINE_IGNORE_MARKER in line:
            continue

        signature_spans: list[tuple[int, int]] = []

        for pattern in PATTERNS:
            for match in pattern.regex.finditer(line):
                signature_spans.append(match.span())
                findings.append(
                    Finding(
                        file=relative,
                        line=line_number,
                        column=match.start() + 1,
                        rule=pattern.name,
                        severity=pattern.severity,
                        description=pattern.description,
                        matched_text=matched_value(pattern, match),
                    )
                )

        if use_entropy:
            for start, value, value_entropy in find_high_entropy_strings(line, min_entropy_length):
                end = start + len(value)
                # A signature rule already explains this span (e.g. the
                # quoted value inside a "stripe_key = '...'" assignment) —
                # don't report the same secret twice under two rule names.
                overlaps_signature_match = any(
                    start < s_end and end > s_start for s_start, s_end in signature_spans
                )
                if overlaps_signature_match:
                    continue

                findings.append(
                    Finding(
                        file=relative,
                        line=line_number,
                        column=start + 1,
                        rule="high-entropy-string",
                        severity=Severity.MEDIUM,
                        description=f"String com alta entropia (entropia={value_entropy:.2f})",
                        matched_text=value,
                    )
                )

    return findings


def scan_directory(options: ScanOptions) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_scannable_files(options):
        findings.extend(
            scan_file(
                path,
                options.root,
                use_entropy=options.use_entropy,
                min_entropy_length=options.min_entropy_length,
            )
        )
    return findings
