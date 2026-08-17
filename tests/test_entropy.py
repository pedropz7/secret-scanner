from secret_scanner.entropy import find_high_entropy_strings, shannon_entropy


def test_shannon_entropy_of_empty_string_is_zero():
    assert shannon_entropy("") == 0.0


def test_shannon_entropy_of_repeated_character_is_zero():
    assert shannon_entropy("aaaaaaaaaa") == 0.0


def test_shannon_entropy_of_random_looking_string_is_high():
    assert shannon_entropy("a1B2c3D4e5F6g7H8i9J0") > 3.5


def test_find_high_entropy_strings_flags_random_looking_literal():
    line = 'token = "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"'
    results = find_high_entropy_strings(line, min_length=20)

    assert len(results) == 1
    _, value, value_entropy = results[0]
    assert value == "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
    assert value_entropy > 4.0


def test_find_high_entropy_strings_ignores_literals_shorter_than_min_length():
    line = 'code = "abc123"'
    assert find_high_entropy_strings(line, min_length=20) == []


def test_find_high_entropy_strings_ignores_low_entropy_literal():
    line = 'code = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
    assert find_high_entropy_strings(line, min_length=20) == []


def test_find_high_entropy_strings_uses_lower_threshold_for_hex():
    # A 32-char hex string maxes out around 4 bits/char of entropy (16-symbol
    # alphabet) — the generic 4.5 threshold would always reject it.
    line = 'checksum = "d41d8cd98f00b204e9800998ecf8427e"'
    results = find_high_entropy_strings(line, min_length=20)
    assert len(results) == 1
