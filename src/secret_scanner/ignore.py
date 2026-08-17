from __future__ import annotations

import fnmatch
from pathlib import Path

DEFAULT_EXCLUDED_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "coverage",
    ".idea",
    ".vscode",
}

DEFAULT_EXCLUDED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".webp",
    ".bmp",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".rar",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp3",
    ".mp4",
    ".mov",
    ".avi",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".pyc",
    ".lock",
}

# Put this marker as a comment on the same line as a known false positive
# (e.g. a fixture, an example, a rotated/dead credential) to silence it —
# the same idea as a linter's inline suppression comment.
INLINE_IGNORE_MARKER = "secret-scanner:ignore"


class IgnoreRules:
    """A deliberately simplified subset of .gitignore: one glob pattern per
    line, matched against the path relative to the scan root via fnmatch.
    No negation, no directory-only anchors — full gitignore semantics are
    surprisingly hairy, and this covers the common case ("ignore this path
    or anything under it") without pulling in a dependency for it."""

    def __init__(self, patterns: list[str]) -> None:
        self.patterns = patterns

    @classmethod
    def load(cls, ignore_file: Path | None) -> IgnoreRules:
        if ignore_file is None or not ignore_file.exists():
            return cls(patterns=[])

        patterns = []
        for raw_line in ignore_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line)
        return cls(patterns=patterns)

    def is_ignored(self, relative_path: str) -> bool:
        return any(
            fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(relative_path, f"{pattern}/*")
            for pattern in self.patterns
        )


def is_probably_binary(path: Path, sample_size: int = 8192) -> bool:
    """A file counts as binary if it can't be opened, or if a null byte
    shows up in the first chunk — the same heuristic Git itself uses."""
    try:
        with path.open("rb") as handle:
            chunk = handle.read(sample_size)
    except OSError:
        return True
    return b"\x00" in chunk
