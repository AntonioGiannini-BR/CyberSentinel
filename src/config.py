from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True)
class Config:
    secret_key: str
    username: str
    password_hash: str
    database_path: Path
    uploads_dir: Path
    reports_dir: Path
    audit_log_path: Path
    max_upload_bytes: int = 1_000_000
    allowed_extensions: tuple[str, ...] = ('.log', '.txt')
    session_cookie_secure: bool = False
    session_cookie_http_only: bool = True
    session_cookie_samesite: str = 'Lax'
    csrf_token: str | None = None

    @classmethod
    def from_env(cls) -> 'Config':
        secret_key = os.getenv('CYBERSENTINEL_SECRET_KEY')
        username = os.getenv('CYBERSENTINEL_USERNAME')
        password_hash = os.getenv('CYBERSENTINEL_PASSWORD_HASH')
        if not secret_key or len(secret_key) < 32:
            raise RuntimeError('CYBERSENTINEL_SECRET_KEY must be set with at least 32 characters.')
        if not username:
            raise RuntimeError('CYBERSENTINEL_USERNAME must be set.')
        if not password_hash:
            raise RuntimeError('CYBERSENTINEL_PASSWORD_HASH must be set. Generate it with Werkzeug or the helper in README.')

        return cls(
            secret_key=secret_key,
            username=username,
            password_hash=password_hash,
            database_path=Path(os.getenv('CYBERSENTINEL_DATABASE', BASE_DIR / 'instance' / 'cybersentinel.db')),
            uploads_dir=Path(os.getenv('CYBERSENTINEL_UPLOADS_DIR', BASE_DIR / 'uploads')),
            reports_dir=Path(os.getenv('CYBERSENTINEL_REPORTS_DIR', BASE_DIR / 'reports')),
            audit_log_path=Path(os.getenv('CYBERSENTINEL_AUDIT_LOG', BASE_DIR / 'logs' / 'audit.log')),
            max_upload_bytes=int(os.getenv('CYBERSENTINEL_MAX_UPLOAD_BYTES', '1000000')),
            session_cookie_secure=os.getenv('CYBERSENTINEL_COOKIE_SECURE', 'false').lower() == 'true',
        )


class ConfigForTests(Config):
    @classmethod
    def build(cls, base_dir: Path, password_hash: str) -> 'ConfigForTests':
        return cls(
            secret_key='test-secret-key-change-me-1234567890',
            username='admin',
            password_hash=password_hash,
            database_path=base_dir / 'test.db',
            uploads_dir=base_dir / 'uploads',
            reports_dir=base_dir / 'reports',
            audit_log_path=base_dir / 'audit.log',
            max_upload_bytes=500_000,
        )
