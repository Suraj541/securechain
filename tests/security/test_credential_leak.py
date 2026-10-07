"""Security tests for Credential Management and Repository Secret Scanning (P11)."""

import os
import re
from pathlib import Path
import pytest
from pydantic import SecretStr

from securechain.security.credentials.dpapi_store import DpapiCredentialStore
from securechain.security.logging_sanitizer import sanitize_string


def test_dpapi_store_lifecycle(tmp_path: Path):
    store = DpapiCredentialStore(store_dir=tmp_path / "vault")
    secret_key = "vpn_peer_01_private_key"
    secret_val = "SuperSecretPrivateKeyPayloadThatMustNeverLeak12345"

    # 1. Store
    stored = store.store_secret(secret_key, SecretStr(secret_val))
    assert stored is True
    assert secret_key in store.list_keys()

    # 2. Verify file on disk is encrypted (ciphertext does NOT contain plaintext)
    vault_file = tmp_path / "vault" / f"{secret_key}.dpapi"
    assert vault_file.is_file()
    raw_disk_bytes = vault_file.read_bytes()
    assert secret_val.encode() not in raw_disk_bytes, "CRITICAL: Plaintext found in vault file!"

    # 3. Retrieve
    retrieved = store.get_secret(secret_key)
    assert retrieved is not None
    assert retrieved.get_secret_value() == secret_val
    # Representation does not reveal plaintext
    assert secret_val not in str(retrieved)

    # 4. Status
    stat = store.status()
    assert stat["backend"] == "Windows DPAPI (win32crypt)"
    assert stat["stored_keys_count"] == 1

    # 5. Delete
    deleted = store.delete_secret(secret_key)
    assert deleted is True
    assert secret_key not in store.list_keys()
    assert store.get_secret(secret_key) is None


def test_secret_redaction_in_exceptions_and_strings():
    sensitive = "interface wg0: PrivateKey = aGVsbG93b3JsZGFzZGYxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ="
    sanitized = sanitize_string(sensitive)
    assert "[REDACTED_KEY]" in sanitized
    assert "aGVsbG93b3JsZGFzZGYxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=" not in sanitized


def test_repository_wide_secret_scan():
    """P11 requirement: Automated repository scan for secrets. Must find 0 committed secrets."""
    repo_root = Path(__file__).resolve().parents[2]
    # Dangerous patterns indicating committed real secrets
    suspicious_patterns = [
        re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----"),
        re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS Access Key
        re.compile(r"ghp_[0-9a-zA-Z]{36}"), # GitHub Personal Access Token
    ]

    violations = []
    scanned_files = 0

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        # Skip git metadata, cache dirs, and temp dirs
        rel = path.relative_to(repo_root)
        if any(part in {".git", ".pytest_cache", "__pycache__", ".credentials_vault"} for part in rel.parts):
            continue
        if path.suffix in {".pyc", ".pyd", ".dpapi"}:
            continue

        scanned_files += 1
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for pat in suspicious_patterns:
                if pat.search(content):
                    violations.append(f"{rel}: matched {pat.pattern}")
        except Exception:
            continue

    assert scanned_files > 10, f"Expected scanned files > 10, got {scanned_files}"
    assert len(violations) == 0, f"Committed secrets detected in repository:\n" + "\n".join(violations)
