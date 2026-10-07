"""Unit tests for secret sanitization in logging and strings."""

import logging
from securechain.security.logging_sanitizer import SecretSanitizingFilter, sanitize_string, get_logger


def test_sanitize_wireguard_key():
    raw = "Interface config: PrivateKey = aGVsbG93b3JsZGFzZGYxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ="
    sanitized = sanitize_string(raw)
    assert "[REDACTED_KEY]" in sanitized
    assert "aGVsbG93b3JsZGFzZGYxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=" not in sanitized


def test_sanitize_password_and_token():
    raw = "Connecting with password=SuperSecretPassword123 and token='eyJhbGciOiJIUzI1NiJ9'"
    sanitized = sanitize_string(raw)
    assert "[REDACTED_PASSWORD]" in sanitized
    assert "[REDACTED_TOKEN]" in sanitized
    assert "SuperSecretPassword123" not in sanitized


def test_logger_filter_integration(caplog):
    logger = get_logger("test.sanitizer")
    logger.setLevel(logging.INFO)

    with caplog.at_level(logging.INFO):
        logger.info("Attempting login: password=SensitivePass999")

    assert "[REDACTED_PASSWORD]" in caplog.text
    assert "SensitivePass999" not in caplog.text
