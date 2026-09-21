from __future__ import annotations

import secrets
from functools import wraps
from pathlib import Path
from typing import Callable

from flask import abort, redirect, request, session, url_for
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename


def is_allowed_filename(filename: str, allowed_extensions: tuple[str, ...]) -> bool:
    safe_name = secure_filename(filename or '')
    return bool(safe_name) and safe_name.lower().endswith(allowed_extensions)


def safe_upload_name(original_filename: str) -> str:
    safe_name = secure_filename(original_filename)
    token = secrets.token_hex(8)
    stem = Path(safe_name).stem[:60] or 'log'
    suffix = Path(safe_name).suffix.lower()
    return f'{stem}-{token}{suffix}'


def validate_upload(file: FileStorage, allowed_extensions: tuple[str, ...], max_bytes: int) -> bytes:
    if not file or not file.filename:
        raise ValueError('No file was uploaded.')
    if not is_allowed_filename(file.filename, allowed_extensions):
        raise ValueError('Only .log and .txt files are allowed.')
    data = file.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f'File is too large. Limit: {max_bytes} bytes.')
    if b'\x00' in data:
        raise ValueError('Binary files are not allowed.')
    return data


def login_required(view: Callable):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapped


def csrf_token() -> str:
    token = session.get('csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['csrf_token'] = token
    return token


def validate_csrf() -> None:
    form_token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    if not form_token or not secrets.compare_digest(form_token, session.get('csrf_token', '')):
        abort(400)
