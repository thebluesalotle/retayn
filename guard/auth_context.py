from __future__ import annotations

import contextvars
import hashlib
import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("RETAYN_DATA_DIR", str(BASE_DIR / "data"))).resolve()
_current_user_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "retayn_current_user_id", default=None
)


def set_current_user(user_id: str):
    return _current_user_id.set(user_id)


def reset_current_user(token) -> None:
    _current_user_id.reset(token)


def current_user_id() -> str:
    user_id = _current_user_id.get()
    if not user_id:
        raise RuntimeError("A signed-in Retayn user is required for this operation.")
    return user_id


def user_storage_key(user_id: str | None = None) -> str:
    value = user_id or current_user_id()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def user_data_dir(user_id: str | None = None) -> Path:
    path = DATA_DIR / "users" / user_storage_key(user_id)
    path.mkdir(parents=True, exist_ok=True)
    return path


def user_db_path(user_id: str | None = None) -> Path:
    return user_data_dir(user_id) / "retayn_guard.db"


def user_upload_dir(user_id: str | None = None) -> Path:
    path = user_data_dir(user_id) / "recovery_uploads"
    path.mkdir(parents=True, exist_ok=True)
    return path
