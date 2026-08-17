import math
import re
from collections import Counter

# Only look inside quoted string literals — scanning every word on a line of
# prose would flag comments and English text constantly. This intentionally
# misses secrets assigned without quotes (e.g. some YAML/.env styles), which
# is a real limitation, documented in the README.
STRING_LITERAL_RE = re.compile(r"""['"]([A-Za-z0-9+/=_\-]{8,})['"]""")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

# Hex strings have a 16-symbol alphabet, so even a "random" one caps out
# around 4 bits/char of entropy; base64/mixed-charset strings can reach ~6.
# Thresholds follow the same split used by detect-secrets' entropy plugins.
HEX_ENTROPY_THRESHOLD = 3.0
GENERIC_ENTROPY_THRESHOLD = 4.5

DEFAULT_MIN_LENGTH = 20


def shannon_entropy(data: str) -> float:
    """Average bits of information per character. Higher = more random-looking."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def find_high_entropy_strings(
    line: str, min_length: int = DEFAULT_MIN_LENGTH
) -> list[tuple[int, str, float]]:
    """Returns (start_column, value, entropy) for each quoted literal in
    `line` that's long enough and random-looking enough to plausibly be a
    secret with no known format."""
    results: list[tuple[int, str, float]] = []
    for match in STRING_LITERAL_RE.finditer(line):
        value = match.group(1)
        if len(value) < min_length:
            continue

        threshold = HEX_ENTROPY_THRESHOLD if HEX_RE.match(value) else GENERIC_ENTROPY_THRESHOLD
        value_entropy = shannon_entropy(value)
        if value_entropy >= threshold:
            results.append((match.start(1), value, value_entropy))

    return results
