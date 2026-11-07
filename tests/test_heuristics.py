import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import (
    shannon_entropy,
    levenshtein,
    SUSPICIOUS_TLDS,
    POPULAR_BRANDS,
    SUSPICIOUS_KEYWORDS,
)


def test_entropy_empty():
    assert shannon_entropy("") == 0.0


def test_entropy_single_char():
    assert shannon_entropy("a") == 0.0


def test_entropy_uniform():
    result = shannon_entropy("abcd")
    assert abs(result - 2.0) < 0.01


def test_entropy_repeated():
    assert shannon_entropy("aaaa") == 0.0


def test_entropy_random_higher_than_english():
    random = shannon_entropy("xj3k9q2p7m4w")
    english = shannon_entropy("example")
    assert random > english


def test_levenshtein_identical():
    assert levenshtein("paypal", "paypal") == 0


def test_levenshtein_one_insert():
    assert levenshtein("paypal", "paypa1") == 1


def test_levenshtein_one_delete():
    assert levenshtein("google", "gogle") == 1


def test_levenshtein_completely_different():
    assert levenshtein("abc", "xyz") == 3


def test_suspicious_tlds_present():
    assert "tk" in SUSPICIOUS_TLDS
    assert "zip" in SUSPICIOUS_TLDS
    assert "xyz" in SUSPICIOUS_TLDS


def test_suspicious_tlds_safe_absent():
    assert "com" not in SUSPICIOUS_TLDS
    assert "org" not in SUSPICIOUS_TLDS


def test_popular_brands_contains_known():
    assert "google" in POPULAR_BRANDS
    assert "paypal" in POPULAR_BRANDS
    assert "microsoft" in POPULAR_BRANDS


def test_suspicious_keywords_contains_known():
    assert "login" in SUSPICIOUS_KEYWORDS
    assert "verify" in SUSPICIOUS_KEYWORDS
    assert "urgent" in SUSPICIOUS_KEYWORDS
