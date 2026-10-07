"""Windows DPAPI (Data Protection API) Credential Store."""

import base64
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import SecretStr

from securechain.core.exceptions import CredentialError
from securechain.security.credentials.store import CredentialStore
from securechain.security.logging_sanitizer import get_logger, sanitize_string

logger = get_logger("securechain.security.dpapi_store")

try:
    import win32crypt
    DPAPI_AVAILABLE = True
except ImportError:
    DPAPI_AVAILABLE = False


class DpapiCredentialStore(CredentialStore):
    """Secure credential store leveraging Windows DPAPI (CryptProtectData)."""

    def __init__(self, store_dir: Optional[Path] = None) -> None:
        if not DPAPI_AVAILABLE:
            raise CredentialError("Windows DPAPI (win32crypt) is not available on this system.")

        self.store_dir = store_dir or Path(".credentials_vault")
        self.store_dir.mkdir(parents=True, exist_ok=True)

    def _get_path_for_key(self, key: str) -> Path:
        safe_key = "".join(c if c.isalnum() or c in "-_" else "_" for c in key)
        return self.store_dir / f"{safe_key}.dpapi"

    def store_secret(self, key: str, secret: SecretStr) -> bool:
        try:
            raw_bytes = secret.get_secret_value().encode("utf-8")
            # CryptProtectData encrypts with Windows user session key
            encrypted_bytes = win32crypt.CryptProtectData(
                raw_bytes,
                f"SecureChain Secret {key}",
                None,
                None,
                None,
                0,
            )
            file_path = self._get_path_for_key(key)
            with open(file_path, "wb") as f:
                f.write(encrypted_bytes)
            logger.info(f"Secret '{key}' securely protected with Windows DPAPI.")
            return True
        except Exception as exc:
            logger.error(f"Failed to protect secret '{key}' via DPAPI: {sanitize_string(str(exc))}")
            raise CredentialError(f"DPAPI encryption error: {exc}") from exc

    def get_secret(self, key: str) -> Optional[SecretStr]:
        file_path = self._get_path_for_key(key)
        if not file_path.is_file():
            return None

        try:
            with open(file_path, "rb") as f:
                encrypted_bytes = f.read()
            # CryptUnprotectData decrypts with Windows user session key
            _, decrypted_bytes = win32crypt.CryptUnprotectData(
                encrypted_bytes,
                None,
                None,
                None,
                0,
            )
            return SecretStr(decrypted_bytes.decode("utf-8"))
        except Exception as exc:
            logger.error(f"Failed to decrypt secret '{key}' via DPAPI: {sanitize_string(str(exc))}")
            raise CredentialError(f"DPAPI decryption error: {exc}") from exc

    def delete_secret(self, key: str) -> bool:
        file_path = self._get_path_for_key(key)
        if file_path.is_file():
            try:
                file_path.unlink()
                logger.info(f"Secret '{key}' purged from DPAPI store.")
                return True
            except OSError as exc:
                logger.warning(f"Error purging secret '{key}': {exc}")
                return False
        return False

    def list_keys(self) -> List[str]:
        keys = []
        if self.store_dir.is_dir():
            for p in self.store_dir.glob("*.dpapi"):
                keys.append(p.stem)
        return sorted(keys)

    def status(self) -> Dict[str, Any]:
        return {
            "backend": "Windows DPAPI (win32crypt)",
            "available": DPAPI_AVAILABLE,
            "vault_path": str(self.store_dir.resolve()),
            "stored_keys_count": len(self.list_keys()),
        }
