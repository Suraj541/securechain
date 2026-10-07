"""Structured logging and secret sanitization for SecureChain."""

import logging
import re
from typing import Any

# Patterns matching sensitive data (WireGuard base64 keys, tokens, passwords, private keys)
REDACTION_PATTERNS = [
    # WireGuard base64 keys (32 bytes = 44 base64 chars, ending in =)
    (re.compile(r"(PrivateKey\s*=\s*)([A-Za-z0-9+/=]{32,64})", re.IGNORECASE), r"\1[REDACTED_KEY]"),
    (re.compile(r"(PresharedKey\s*=\s*)([A-Za-z0-9+/=]{32,64})", re.IGNORECASE), r"\1[REDACTED_KEY]"),
    # Generic password patterns in key-value or URI
    (re.compile(r'(password["\':\s=]+)(["\']?[^\s,"\'&]+["\']?)', re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r'(token["\':\s=]+)(["\']?[^\s,"\'&]+["\']?)', re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r'(secret["\':\s=]+)(["\']?[^\s,"\'&]+["\']?)', re.IGNORECASE), r"\1[REDACTED_SECRET]"),
    (re.compile(r'(auth-user-pass\s+)(\S+)', re.IGNORECASE), r"\1[REDACTED_AUTH]"),
    # RSA/EC private key blocks
    (re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+ PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
]


def sanitize_string(text: str) -> str:
    """Sanitize sensitive patterns from arbitrary string."""
    if not isinstance(text, str):
        return text
    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


class SecretSanitizingFilter(logging.Filter):
    """Logging filter that redacts credentials and keys from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_string(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_string(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_string(str(arg)) for arg in record.args)
        return True


def get_logger(name: str) -> logging.Logger:
    """Get a configured logger with the SecretSanitizingFilter attached."""
    logger = logging.getLogger(name)
    # Ensure filter is attached only once
    if not any(isinstance(f, SecretSanitizingFilter) for f in logger.filters):
        logger.addFilter(SecretSanitizingFilter())
    return logger
