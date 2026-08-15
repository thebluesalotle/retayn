from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleAuthRequest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from auth import current_session, google_config, init_auth_db, router as auth_router, user_for_webhook_token
from auth_context import current_user_id, reset_current_user, set_current_user, user_db_path
from recovery_service import init_recovery_db, recovery_summary, router as recovery_router

try:
    from winotify import Notification
except ImportError:  # pragma: no cover
    Notification = None


BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2022-11-28"
SHOPIFY_API_VERSION = "2026-07"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

app = FastAPI(title="Retayn Guard")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
app.include_router(auth_router)
app.include_router(recovery_router)
templates = Jinja2Templates(directory=TEMPLATES_DIR)

running_tasks: dict[tuple[str, int], asyncio.Task[Any]] = {}
initialized_users: set[str] = set()
initialization_lock = asyncio.Lock()
SOFT_CONNECTION_ALERT_FAILURES = 6
HARD_CONNECTION_ALERT_FAILURES = 2

SYSTEM_CATEGORIES: dict[str, dict[str, Any]] = {
    "source_code": {
        "name": "Source code",
        "description": "Repositories and the people who can administer or remove them.",
        "examples": ["GitHub", "GitLab", "Bitbucket"],
    },
    "publisher_accounts": {
        "name": "Publisher accounts",
        "description": "Accounts required to publish packages, apps, and releases.",
        "examples": ["Apple Developer", "Google Play", "npm", "PyPI"],
    },
    "signing_materials": {
        "name": "Signing materials",
        "description": "Certificates, signing keys, and release credentials.",
        "examples": ["Apple certificates", "Android keystores", "Code-signing keys"],
    },
    "cloud_data": {
        "name": "Cloud and data",
        "description": "Hosting, databases, storage, and production infrastructure.",
        "examples": ["AWS", "Google Cloud", "Azure", "Vercel", "Supabase"],
    },
    "domains_billing": {
        "name": "Domains and billing",
        "description": "Domains, DNS, payment accounts, and payment methods.",
        "examples": ["Cloudflare", "GoDaddy", "Stripe", "Shopify"],
    },
    "release_pipeline": {
        "name": "Build and release",
        "description": "CI/CD and every step between source code and production.",
        "examples": ["GitHub Actions", "GitLab CI", "CircleCI", "Vercel"],
    },
    "identity_operations": {
        "name": "Identity and operations",
        "description": "Workforce identity and operational systems that can grant or recover access.",
        "examples": ["Google Workspace", "Slack", "Zendesk"],
    },
}

CONNECTORS: dict[str, dict[str, Any]] = {
    "github": {
        "name": "GitHub",
        "description": "Monitor repositories, collaborators, branch protection, deploy keys, and webhooks.",
        "categories": ["source_code", "release_pipeline"],
        "monitoring": ["Collaborators and roles", "Repository visibility", "Branch protection", "Deploy keys", "Webhooks"],
        "actions": ["Remove or downgrade users", "Restore repository controls", "Remove risky keys or webhooks"],
        "fields": [
            {
                "name": "repo",
                "label": "GitHub repository URL",
                "placeholder": "https://github.com/owner/repo",
                "secret": False,
                "help": "Open the repository in GitHub and copy the browser URL. Retayn checks whether its GitHub App is installed on that exact repo.",
            },
        ],
    },
    "shopify": {
        "name": "Shopify",
        "description": "Install Retayn on a store, then monitor staff-facing access signals and shop identity.",
        "coming_soon": True,
        "categories": ["cloud_data", "domains_billing"],
        "monitoring": ["Store identity", "Store domain", "Account reachability"],
        "actions": [],
        "fields": [
            {
                "name": "shop_domain",
                "label": "Shop domain",
                "placeholder": "your-store.myshopify.com",
                "secret": False,
                "help": "Use the store's myshopify.com address. You can find it in Shopify admin under Settings, Domains.",
            },
        ],
        "install_env": "SHOPIFY_INSTALL_URL",
    },
    "slack": {
        "name": "Slack",
        "description": "Install the Retayn Slack app, then monitor workspace identity and user baseline.",
        "categories": ["identity_operations"],
        "monitoring": ["Workspace members", "Administrators", "Owners", "Account removal"],
        "actions": [],
        "fields": [
            {
                "name": "workspace_hint",
                "label": "Workspace name or URL",
                "placeholder": "company.slack.com",
                "secret": False,
                "help": "Use the Slack workspace URL or name. Retayn confirms the real workspace after the Slack install finishes.",
            },
        ],
        "install_env": "SLACK_INSTALL_URL",
    },
    "google_workspace": {
        "name": "Google Workspace",
        "description": "Authorize Retayn in Google Workspace, then monitor domain users through Admin SDK.",
        "coming_soon": True,
        "categories": ["identity_operations"],
        "monitoring": ["Directory users", "Administrators", "Suspensions", "Organization units"],
        "actions": [],
        "fields": [
            {
                "name": "domain",
                "label": "Workspace domain",
                "placeholder": "example.com",
                "secret": False,
                "help": "Use the business email domain managed by Google Workspace, such as example.com.",
            },
        ],
        "install_env": "GOOGLE_WORKSPACE_INSTALL_URL",
    },
    "airtable": {
        "name": "Airtable",
        "description": "Authorize Retayn with Airtable, then monitor base collaborators, permissions, reachability, and schema changes.",
        "categories": ["cloud_data"],
        "monitoring": ["Base collaborators", "Permission changes", "Base reachability", "Tables", "Fields", "Schema changes"],
        "actions": [],
        "fields": [
            {
                "name": "base_id",
                "label": "Base ID or base URL",
                "placeholder": "https://airtable.com/appXXXXXXXXXXXXXX/...",
                "secret": False,
                "help": "Open the Airtable base and copy the browser URL. The base ID is the part that starts with app.",
            },
        ],
        "install_env": "AIRTABLE_INSTALL_URL",
    },
    "zendesk": {
        "name": "Zendesk",
        "description": "Authorize Retayn in Zendesk, then monitor Support account users and roles.",
        "categories": ["identity_operations"],
        "monitoring": ["Agents", "Administrators", "Role changes", "Account removal"],
        "actions": [],
        "fields": [
            {
                "name": "subdomain",
                "label": "Zendesk subdomain",
                "placeholder": "yourcompany",
                "secret": False,
                "help": "Use the first part of your Zendesk URL. For yourcompany.zendesk.com, enter yourcompany.",
            },
        ],
        "install_env": "ZENDESK_INSTALL_URL",
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ[key.strip()] = value.strip().strip('"').strip("'")


def env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().casefold() in {"1", "true", "yes", "y", "on"}


def env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None or value.strip() == "":
        return default
    return int(value)


def env_csv(name: str, default: list[str] | None = None) -> list[str]:
    value = os.getenv(name)
    if value is None:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]


def config() -> dict[str, Any]:
    load_env_file(BASE_DIR / ".env")
    return {
        "github_token": os.getenv("GITHUB_TOKEN", "").strip(),
        "github_app_slug": os.getenv("GITHUB_APP_SLUG", "").strip(),
        "github_app_id": os.getenv("GITHUB_APP_ID", "").strip(),
        "github_private_key_path": os.getenv("GITHUB_PRIVATE_KEY_PATH", "").strip(),
        "github_private_key": os.getenv("GITHUB_PRIVATE_KEY", "").strip(),
        "app_base_url": os.getenv("RETAYN_PUBLIC_BASE_URL", "").strip().rstrip("/"),
        "token_encryption_key": os.getenv("RETAYN_TOKEN_ENCRYPTION_KEY", "").strip(),
        "shopify_client_id": os.getenv("SHOPIFY_CLIENT_ID", "").strip(),
        "shopify_client_secret": os.getenv("SHOPIFY_CLIENT_SECRET", "").strip(),
        "shopify_install_url": os.getenv("SHOPIFY_INSTALL_URL", "").strip(),
        "shopify_admin_token": os.getenv("SHOPIFY_ADMIN_TOKEN", "").strip(),
        "slack_client_id": os.getenv("SLACK_CLIENT_ID", "").strip(),
        "slack_client_secret": os.getenv("SLACK_CLIENT_SECRET", "").strip(),
        "slack_install_url": os.getenv("SLACK_INSTALL_URL", "").strip(),
        "slack_bot_token": os.getenv("SLACK_BOT_TOKEN", "").strip(),
        "google_workspace_client_id": os.getenv("GOOGLE_WORKSPACE_CLIENT_ID", "").strip(),
        "google_workspace_client_secret": os.getenv("GOOGLE_WORKSPACE_CLIENT_SECRET", "").strip(),
        "google_workspace_install_url": os.getenv("GOOGLE_WORKSPACE_INSTALL_URL", "").strip(),
        "google_workspace_admin_email": os.getenv("GOOGLE_WORKSPACE_ADMIN_EMAIL", "").strip(),
        "google_workspace_service_account_json_path": os.getenv("GOOGLE_WORKSPACE_SERVICE_ACCOUNT_JSON_PATH", "").strip(),
        "airtable_client_id": os.getenv("AIRTABLE_CLIENT_ID", "").strip(),
        "airtable_client_secret": os.getenv("AIRTABLE_CLIENT_SECRET", "").strip(),
        "airtable_install_url": os.getenv("AIRTABLE_INSTALL_URL", "").strip(),
        "airtable_personal_access_token": os.getenv("AIRTABLE_PERSONAL_ACCESS_TOKEN", "").strip(),
        "zendesk_client_id": os.getenv("ZENDESK_CLIENT_ID", "").strip(),
        "zendesk_client_secret": os.getenv("ZENDESK_CLIENT_SECRET", "").strip(),
        "zendesk_install_url": os.getenv("ZENDESK_INSTALL_URL", "").strip(),
        "zendesk_email": os.getenv("ZENDESK_EMAIL", "").strip(),
        "zendesk_api_token": os.getenv("ZENDESK_API_TOKEN", "").strip(),
    }


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(user_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connector TEXT NOT NULL,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'connected',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                settings_json TEXT NOT NULL DEFAULT '{}',
                UNIQUE(connector, owner, repo)
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                account_id INTEGER NOT NULL,
                key TEXT NOT NULL,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(account_id, key)
            );

            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                account_id INTEGER,
                connector TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                title TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL,
                action_taken TEXT,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                FOREIGN KEY(account_id) REFERENCES accounts(id)
            );

            CREATE TABLE IF NOT EXISTS accepted_findings (
                account_id INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                unique_key TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY(account_id, event_type, unique_key)
            );

            CREATE TABLE IF NOT EXISTS oauth_states (
                state TEXT PRIMARY KEY,
                connector TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS connection_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connector TEXT NOT NULL,
                owner TEXT NOT NULL,
                repo TEXT NOT NULL DEFAULT '',
                access_token TEXT NOT NULL,
                refresh_token TEXT,
                token_type TEXT,
                scopes TEXT,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(connector, owner, repo)
            );

            CREATE TABLE IF NOT EXISTS protected_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT NOT NULL,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                url TEXT,
                criticality TEXT NOT NULL DEFAULT 'high',
                control_holders_json TEXT NOT NULL DEFAULT '[]',
                recovery_contact TEXT,
                recovery_method TEXT,
                backup_status TEXT NOT NULL DEFAULT 'unknown',
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'tracked',
                last_reviewed_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )


def settings_defaults() -> dict[str, Any]:
    return {
        "auto_action_enabled": False,
        "auto_action_delay_minutes": 30,
        "monitoring_poll_seconds": 30,
        "github_poll_seconds": 30,
        "allowed_identities": [],
        "github_allowed_users": [],
        "github_allowed_hook_urls": [],
        "github_allowed_write_deploy_keys": [],
        "allowed_identities_edited": False,
        "windows_notifications": True,
    }


def account_settings_defaults(account_id: int) -> dict[str, Any]:
    collaborators = snapshot_get(account_id, "collaborators", {})
    hooks = snapshot_get(account_id, "hooks", {})
    deploy_keys = snapshot_get(account_id, "deploy_keys", {})
    users = snapshot_get(account_id, "users", {})
    known_identities = [
        str(item.get("email") or item.get("name") or item.get("real_name") or item.get("id") or "")
        for item in users.values()
        if not item.get("deleted") and not item.get("suspended") and item.get("active") is not False
    ]
    return {
        "auto_action_enabled": False,
        "auto_action_delay_minutes": 30,
        "monitoring_poll_seconds": 30,
        "github_poll_seconds": 30,
        "allowed_identities": [item for item in known_identities if item],
        "github_allowed_users": [
            item.get("login") for item in collaborators.values() if item.get("login")
        ],
        "github_allowed_hook_urls": [
            item.get("url") for item in hooks.values() if item.get("url")
        ],
        "github_allowed_write_deploy_keys": [
            item.get("title") for item in deploy_keys.values()
            if item.get("title") and not item.get("read_only")
        ],
        "allowed_identities_edited": False,
        "windows_notifications": True,
    }


def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def row(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with db() as conn:
        result = conn.execute(query, params).fetchone()
        return dict(result) if result else None


def execute(query: str, params: tuple[Any, ...] = ()) -> int:
    with db() as conn:
        cur = conn.execute(query, params)
        return int(cur.lastrowid)


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def snapshot_get(account_id: int, key: str, default: Any) -> Any:
    item = row("SELECT value_json FROM snapshots WHERE account_id=? AND key=?", (account_id, key))
    return json.loads(item["value_json"]) if item else default


def snapshot_set(account_id: int, key: str, value: Any) -> None:
    execute(
        """
        INSERT INTO snapshots(account_id, key, value_json, updated_at)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(account_id, key)
        DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
        """,
        (account_id, key, json_dumps(value), utc_now()),
    )


def oauth_redirect_uri(connector: str) -> str:
    base_url = config()["app_base_url"] or "http://127.0.0.1:8787"
    return f"{base_url}/oauth/{connector_path(connector)}/callback"


def connector_path(connector: str) -> str:
    return connector.replace("_", "-")


def normalize_connector(value: str) -> str:
    return value.replace("-", "_")


def remember_oauth_state(connector: str, metadata: dict[str, Any]) -> str:
    state = secrets.token_urlsafe(24)
    execute(
        "INSERT INTO oauth_states(state, connector, metadata_json, created_at) VALUES(?, ?, ?, ?)",
        (state, connector, json_dumps(metadata), utc_now()),
    )
    return state


def consume_oauth_state(state: str, connector: str) -> dict[str, Any]:
    item = row("SELECT * FROM oauth_states WHERE state=? AND connector=?", (state, connector))
    if not item:
        raise HTTPException(400, "OAuth state was not recognized. Start the install again from Retayn.")
    execute("DELETE FROM oauth_states WHERE state=?", (state,))
    try:
        created_at = datetime.fromisoformat(item["created_at"])
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - created_at).total_seconds() > 600:
            raise HTTPException(400, "OAuth state expired. Start the install again from Retayn.")
    except ValueError as exc:
        raise HTTPException(400, "OAuth state was invalid. Start the install again from Retayn.") from exc
    return json.loads(item["metadata_json"])


def token_encryption_key() -> bytes | None:
    encoded = config()["token_encryption_key"]
    if not encoded:
        return None
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except Exception as exc:
        raise RuntimeError("RETAYN_TOKEN_ENCRYPTION_KEY must be URL-safe base64.") from exc
    if len(key) != 32:
        raise RuntimeError("RETAYN_TOKEN_ENCRYPTION_KEY must decode to exactly 32 bytes.")
    return key


def encrypt_connection_secret(value: str | None) -> str | None:
    if not value:
        return value
    key = token_encryption_key()
    if not key:
        if config()["app_base_url"].startswith("https://"):
            raise RuntimeError("RETAYN_TOKEN_ENCRYPTION_KEY is required in production.")
        return value
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(nonce, value.encode("utf-8"), b"retayn-connection-token-v1")
    return "enc:v1:" + base64.urlsafe_b64encode(nonce + encrypted).decode("ascii")


def decrypt_connection_secret(value: str | None) -> str | None:
    if not value or not value.startswith("enc:v1:"):
        return value
    key = token_encryption_key()
    if not key:
        raise RuntimeError("RETAYN_TOKEN_ENCRYPTION_KEY is required to read stored provider tokens.")
    payload = base64.urlsafe_b64decode(value.removeprefix("enc:v1:"))
    return AESGCM(key).decrypt(payload[:12], payload[12:], b"retayn-connection-token-v1").decode("utf-8")


def store_connection_token(
    connector: str,
    owner: str,
    repo: str,
    access_token: str,
    refresh_token: str | None = None,
    token_type: str | None = None,
    scopes: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    now = utc_now()
    execute(
        """
        INSERT INTO connection_tokens(connector, owner, repo, access_token, refresh_token, token_type, scopes, metadata_json, created_at, updated_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(connector, owner, repo)
        DO UPDATE SET access_token=excluded.access_token, refresh_token=excluded.refresh_token,
            token_type=excluded.token_type, scopes=excluded.scopes, metadata_json=excluded.metadata_json,
            updated_at=excluded.updated_at
        """,
        (
            connector, owner, repo,
            encrypt_connection_secret(access_token), encrypt_connection_secret(refresh_token),
            token_type, scopes, json_dumps(metadata or {}), now, now,
        ),
    )


def connection_token(connector: str, owner: str | None = None, repo: str | None = None) -> dict[str, Any] | None:
    if owner is not None:
        item = row(
            "SELECT * FROM connection_tokens WHERE connector=? AND owner=? AND repo=?",
            (connector, owner, repo or ""),
        )
    else:
        item = row(
            "SELECT * FROM connection_tokens WHERE connector=? ORDER BY updated_at DESC LIMIT 1",
            (connector,),
        )
    if item:
        item["access_token"] = decrypt_connection_secret(item.get("access_token"))
        item["refresh_token"] = decrypt_connection_secret(item.get("refresh_token"))
    return item


def connection_token_expiring(token: dict[str, Any]) -> bool:
    metadata = json.loads(token.get("metadata_json") or "{}")
    expires_in = metadata.get("expires_in")
    if not expires_in:
        return False
    try:
        updated_at = datetime.fromisoformat(token["updated_at"])
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - updated_at).total_seconds() >= max(0, int(expires_in) - 120)
    except (TypeError, ValueError):
        return False


async def refresh_connection_token(token: dict[str, Any]) -> dict[str, Any]:
    refresh_token = str(token.get("refresh_token") or "").strip()
    if not refresh_token:
        return token
    connector = token["connector"]
    cfg = config()
    if connector == "google_workspace":
        url = "https://oauth2.googleapis.com/token"
        kwargs = {
            "data": {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": require_config_value(cfg, "google_workspace_client_id", "GOOGLE_WORKSPACE_CLIENT_ID"),
                "client_secret": require_config_value(cfg, "google_workspace_client_secret", "GOOGLE_WORKSPACE_CLIENT_SECRET"),
            }
        }
    elif connector == "airtable":
        url = "https://airtable.com/oauth2/v1/token"
        client_id = require_config_value(cfg, "airtable_client_id", "AIRTABLE_CLIENT_ID")
        client_secret = require_config_value(cfg, "airtable_client_secret", "AIRTABLE_CLIENT_SECRET")
        kwargs = {"data": {"grant_type": "refresh_token", "refresh_token": refresh_token}, "auth": (client_id, client_secret)}
    elif connector == "zendesk":
        url = f"https://{token['owner']}.zendesk.com/oauth/tokens"
        kwargs = {
            "json": {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": require_config_value(cfg, "zendesk_client_id", "ZENDESK_CLIENT_ID"),
                "client_secret": require_config_value(cfg, "zendesk_client_secret", "ZENDESK_CLIENT_SECRET"),
            }
        }
    else:
        return token

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(url, **kwargs)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"{CONNECTORS[connector]['name']} token refresh failed: {response.text[:500]}")
    payload = response.json()
    metadata = json.loads(token.get("metadata_json") or "{}")
    metadata["expires_in"] = payload.get("expires_in") or metadata.get("expires_in")
    store_connection_token(
        connector,
        token["owner"],
        token["repo"],
        payload["access_token"],
        refresh_token=payload.get("refresh_token") or refresh_token,
        token_type=payload.get("token_type") or token.get("token_type"),
        scopes=payload.get("scope") or token.get("scopes"),
        metadata=metadata,
    )
    return connection_token(connector, token["owner"], token["repo"])


async def active_connection_token(connector: str, owner: str | None = None, repo: str | None = None) -> dict[str, Any] | None:
    token = connection_token(connector, owner, repo)
    if token and connection_token_expiring(token):
        return await refresh_connection_token(token)
    return token


def require_config_value(cfg: dict[str, Any], key: str, label: str) -> str:
    value = str(cfg.get(key) or "").strip()
    if not value:
        raise HTTPException(400, f"Set {label} in guard/.env before completing this install.")
    return value


def oauth_success_page(connector_name: str) -> HTMLResponse:
    return HTMLResponse(
        f"""
        <!doctype html>
        <html>
          <head><title>Retayn connected</title></head>
          <body style="font-family: system-ui; max-width: 640px; margin: 56px auto; line-height: 1.5;">
            <h1>{connector_name} authorized</h1>
            <p>Retayn saved the authorization. You can close this tab, return to Retayn, and click Finish connection.</p>
          </body>
        </html>
        """
    )


def get_settings() -> dict[str, Any]:
    defaults = settings_defaults()
    with db() as conn:
        existing = {
            item["key"]: json.loads(item["value_json"])
            for item in conn.execute("SELECT key, value_json FROM app_settings").fetchall()
            if item["key"] in defaults
        }
    return defaults | existing


def get_account_settings(account: dict[str, Any]) -> dict[str, Any]:
    account_values = json.loads(account.get("settings_json") or "{}")
    defaults = account_settings_defaults(account["id"])
    values = defaults | account_values
    if not values.get("allowed_identities_edited"):
        if account["connector"] == "github" and not values.get("github_allowed_users"):
            values["github_allowed_users"] = defaults.get("github_allowed_users", [])
            values["allowed_identities"] = defaults.get("github_allowed_users", [])
        elif account["connector"] != "github" and not values.get("allowed_identities"):
            values["allowed_identities"] = defaults.get("allowed_identities", [])
    return values


def connector_definitions() -> list[dict[str, Any]]:
    cfg = config()
    output = []
    for connector_id, item in CONNECTORS.items():
        if connector_id == "github":
            install_url = github_install_url()
            install_ready = bool(install_url)
        else:
            configured_url = cfg.get(str(item.get("install_env", "")).lower(), "")
            install_url = f"/oauth/{connector_path(connector_id)}/start" if oauth_connector_ready(connector_id) else configured_url
            install_ready = bool(install_url)
        output.append(
            {
                "id": connector_id,
                "name": item["name"],
                "description": item["description"],
                "fields": item["fields"],
                "install_url": install_url,
                "install_ready": install_ready,
                "coming_soon": bool(item.get("coming_soon")),
                "categories": item.get("categories", []),
                "monitoring": item.get("monitoring", []),
                "actions": item.get("actions", []),
                "action_support": bool(item.get("actions")),
            }
        )
    return output


def oauth_connector_ready(connector: str) -> bool:
    cfg = config()
    if connector == "shopify":
        return bool(cfg["shopify_client_id"])
    if connector == "slack":
        return bool(cfg["slack_client_id"])
    if connector == "google_workspace":
        return bool(cfg["google_workspace_client_id"])
    if connector == "airtable":
        return bool(cfg["airtable_client_id"])
    if connector == "zendesk":
        return bool(cfg["zendesk_client_id"])
    return False


def account_display(account: dict[str, Any]) -> str:
    if account["connector"] == "github":
        return f"{account['owner']}/{account['repo']}"
    if account["connector"] == "shopify":
        return account["owner"]
    if account["connector"] == "slack":
        return account["repo"] or account["owner"]
    if account["connector"] == "google_workspace":
        return account["owner"]
    if account["connector"] == "airtable":
        return account["repo"] or account["owner"]
    if account["connector"] == "zendesk":
        return f"{account['owner']}.zendesk.com"
    return f"{account['owner']}/{account['repo']}".strip("/")


def enrich_account(account: dict[str, Any]) -> dict[str, Any]:
    account["settings"] = get_account_settings(account)
    account["baseline"] = account_baseline(account["id"])
    account["display_name"] = account_display(account)
    definition = CONNECTORS.get(account["connector"], {})
    account["connector_name"] = definition.get("name", account["connector"])
    account["categories"] = definition.get("categories", [])
    account["monitoring"] = definition.get("monitoring", [])
    account["action_support"] = bool(definition.get("actions"))
    return account


def enrich_asset(asset: dict[str, Any]) -> dict[str, Any]:
    asset["control_holders"] = json.loads(asset.pop("control_holders_json") or "[]")
    asset["category_name"] = SYSTEM_CATEGORIES.get(asset["category"], {}).get("name", asset["category"])
    risks: list[str] = []
    if not asset["control_holders"]:
        risks.append("No control holder recorded")
    if not str(asset.get("recovery_contact") or "").strip():
        risks.append("No recovery contact")
    if not str(asset.get("recovery_method") or "").strip():
        risks.append("No recovery path documented")
    if asset.get("backup_status") in {"unknown", "missing"}:
        risks.append("Backup not confirmed")
    asset["risks"] = risks
    asset["risk_status"] = "at_risk" if risks else "ready"
    return asset


def list_assets() -> list[dict[str, Any]]:
    return [enrich_asset(item) for item in rows("SELECT * FROM protected_assets ORDER BY criticality DESC, created_at DESC")]


def build_protection_map(
    accounts: list[dict[str, Any]],
    assets: list[dict[str, Any]],
    open_events: list[dict[str, Any]],
) -> dict[str, Any]:
    alert_account_ids = {item.get("account_id") for item in open_events if item.get("account_id")}
    categories: list[dict[str, Any]] = []
    uncovered = 0
    at_risk_assets = 0
    for category_id, definition in SYSTEM_CATEGORIES.items():
        connected = [item for item in accounts if category_id in item.get("categories", [])]
        tracked = [item for item in assets if item["category"] == category_id]
        category_alerts = [item for item in connected if item["id"] in alert_account_ids]
        risky = [item for item in tracked if item["risk_status"] == "at_risk"]
        at_risk_assets += len(risky)
        if not connected and not tracked:
            status = "gap"
            uncovered += 1
        elif category_alerts or risky or any(item["status"] == "error" for item in connected):
            status = "needs_review"
        else:
            status = "covered"
        categories.append(
            {
                "id": category_id,
                "name": definition["name"],
                "description": definition["description"],
                "examples": definition["examples"],
                "status": status,
                "connections": [
                    {"id": item["id"], "name": item["display_name"], "provider": item["connector_name"], "status": item["status"]}
                    for item in connected
                ],
                "assets": tracked,
            }
        )

    score = 100 - uncovered * 12 - at_risk_assets * 4
    score -= sum(20 if item["severity"] == "critical" else 10 if item["severity"] == "high" else 4 for item in open_events)
    score -= sum(8 for item in accounts if item["status"] == "error")
    score = max(0, min(100, score))
    return {
        "categories": categories,
        "score": score,
        "covered": len(SYSTEM_CATEGORIES) - uncovered,
        "total": len(SYSTEM_CATEGORIES),
        "gaps": uncovered,
        "at_risk_assets": at_risk_assets,
    }


def update_account_settings(account_id: int, values: dict[str, Any]) -> dict[str, Any]:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not account:
        raise HTTPException(404, "Connection not found")
    defaults = account_settings_defaults(account_id)
    existing_values = json.loads(account.get("settings_json") or "{}")
    previous = defaults | existing_values
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key not in defaults:
            continue
        if key in {"auto_action_enabled", "windows_notifications", "allowed_identities_edited"}:
            cleaned[key] = bool(value)
        elif key in {"github_poll_seconds", "monitoring_poll_seconds", "auto_action_delay_minutes"}:
            cleaned[key] = max(1 if key == "auto_action_delay_minutes" else 10, int(value))
        else:
            cleaned[key] = [str(item).strip() for item in value if str(item).strip()]
    identity_key = identity_settings_key(account)
    if identity_key in values or "allowed_identities" in values:
        cleaned["allowed_identities_edited"] = True
    previous_allowed = {str(item).strip().casefold() for item in previous.get(identity_key, []) if str(item).strip()}
    next_allowed = {str(item).strip().casefold() for item in cleaned.get(identity_key, previous.get(identity_key, [])) if str(item).strip()}
    removed_allowed = previous_allowed - next_allowed
    removed_identities = prune_baseline_for_removed_allowed(account, removed_allowed)
    execute(
        "UPDATE accounts SET settings_json=?, updated_at=? WHERE id=?",
        (json_dumps(existing_values | defaults | cleaned), utc_now(), account_id),
    )
    for identity in removed_identities:
        label = identity_label(identity)
        unique = f"trusted_identity_removed:{hashlib.sha256((label + utc_now()).encode('utf-8')).hexdigest()[:16]}"
        create_event(
            account_id,
            "trusted_identity_removed",
            "medium",
            "Trusted person removed",
            f"{label} was removed from the trusted list for {account_display(account)}.",
            {
                "unique_key": unique,
                "identity": identity,
                "removed_from_allowed": True,
                "supported_action": None,
            },
        )
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    return get_account_settings(account)


def update_settings(values: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = set(settings_defaults())
    cleaned: dict[str, Any] = {}
    for key, value in values.items():
        if key not in allowed_keys:
            continue
        if key in {"auto_action_enabled", "windows_notifications", "allowed_identities_edited"}:
            cleaned[key] = bool(value)
        elif key in {"github_poll_seconds", "monitoring_poll_seconds"}:
            cleaned[key] = max(10, int(value))
        elif key == "auto_action_delay_minutes":
            cleaned[key] = max(1, int(value))
        else:
            cleaned[key] = [str(item).strip() for item in value if str(item).strip()]

    with db() as conn:
        for key, value in cleaned.items():
            conn.execute(
                """
                INSERT INTO app_settings(key, value_json, updated_at)
                VALUES(?, ?, ?)
                ON CONFLICT(key)
                DO UPDATE SET value_json=excluded.value_json, updated_at=excluded.updated_at
                """,
                (key, json_dumps(value), utc_now()),
            )
    return get_settings()


def send_notification(message: str, title: str = "Retayn security notification") -> None:
    if Notification is None:
        return
    try:
        Notification(
            app_id="Retayn Guard",
            title=title,
            msg=message[:220],
            duration="long",
        ).show()
    except Exception:
        logging.exception("Could not send Windows notification")


def create_event(
    account_id: int | None,
    event_type: str,
    severity: str,
    title: str,
    summary: str,
    details: dict[str, Any],
    status: str = "open",
    action_taken: str | None = None,
) -> int:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,)) if account_id else None
    connector = account["connector"] if account else "inventory"
    event_id = execute(
        """
        INSERT INTO events(account_id, connector, event_type, severity, status, title, summary, details_json, action_taken, created_at, resolved_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            account_id,
            connector,
            event_type,
            severity,
            status,
            title,
            summary,
            json_dumps(details),
            action_taken,
            utc_now(),
            utc_now() if status != "open" else None,
        ),
    )
    if not account or get_account_settings(account).get("windows_notifications", True):
        send_notification(f"{title}. {summary}")
    return event_id


def disconnect_instructions(account: dict[str, Any]) -> dict[str, Any]:
    connector = account["connector"]
    if connector == "github":
        return {
            "provider": "GitHub",
            "message": "Retayn removed the local connection. To fully disconnect, open GitHub, go to Settings > Applications > Installed GitHub Apps, choose Retayn, and remove this repository or uninstall the app.",
        }
    if connector == "slack":
        return {
            "provider": "Slack",
            "message": "Retayn removed the local connection. To fully disconnect, open Slack App Management, choose Retayn, and remove the app from the workspace.",
        }
    if connector == "google_workspace":
        return {
            "provider": "Google Workspace",
            "message": "Retayn removed the local connection. To fully disconnect, open your Google Account or Google Admin OAuth app access page and remove Retayn's access.",
        }
    if connector == "airtable":
        return {
            "provider": "Airtable",
            "message": "Retayn removed the local connection. To fully disconnect, open Airtable account integrations and revoke Retayn's OAuth access.",
        }
    if connector == "zendesk":
        return {
            "provider": "Zendesk",
            "message": "Retayn removed the local connection. To fully disconnect, open Zendesk Admin Center > Apps and integrations > APIs > OAuth clients and revoke or disable Retayn.",
        }
    if connector == "shopify":
        return {
            "provider": "Shopify",
            "message": "Retayn removed the local connection. To fully disconnect, open Shopify admin Apps settings and uninstall Retayn from the store.",
        }
    return {
        "provider": CONNECTORS.get(connector, {}).get("name", connector),
        "message": "Retayn removed the local connection. Open the connected app and revoke Retayn's access there too.",
    }


def event_age_minutes(created_at: str) -> float:
    created = datetime.fromisoformat(created_at)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - created).total_seconds() / 60


class GitHubClient:
    def __init__(self, token: str):
        self.client = httpx.AsyncClient(
            base_url=GITHUB_API,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "retayn-guard",
            },
            timeout=20,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        response = await self.client.request(method, path, **kwargs)
        if response.status_code >= 400:
            detail = response.text[:500]
            raise HTTPException(response.status_code, f"GitHub API error for {method} {path}: {detail}")
        return response

    async def get_json(self, path: str, **kwargs: Any) -> Any:
        return (await self.request("GET", path, **kwargs)).json()

    async def paged(self, path: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        page = 1
        output: list[dict[str, Any]] = []
        while True:
            data = await self.get_json(path, params={**(params or {}), "per_page": 100, "page": page})
            if not data:
                return output
            output.extend(data)
            if len(data) < 100:
                return output
            page += 1

    async def repo(self, owner: str, repo: str) -> dict[str, Any]:
        return await self.get_json(f"/repos/{owner}/{repo}")

    async def collaborators(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return await self.paged(f"/repos/{owner}/{repo}/collaborators", {"affiliation": "all"})

    async def branches(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return await self.paged(f"/repos/{owner}/{repo}/branches")

    async def branch_protection(self, owner: str, repo: str, branch: str) -> dict[str, Any] | None:
        response = await self.client.get(f"/repos/{owner}/{repo}/branches/{branch}/protection")
        if response.status_code == 404:
            return None
        if response.status_code == 403:
            body = response.text.casefold()
            if "upgrade to github pro" in body or "make this repository public" in body:
                return {
                    "unsupported": True,
                    "reason": "GitHub plan does not expose branch protection for this repository.",
                    "status_code": 403,
                }
        if response.status_code >= 400:
            raise HTTPException(response.status_code, response.text[:500])
        return response.json()

    async def deploy_keys(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return await self.paged(f"/repos/{owner}/{repo}/keys")

    async def hooks(self, owner: str, repo: str) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
        response = await self.client.get(f"/repos/{owner}/{repo}/hooks", params={"per_page": 100})
        if response.status_code == 403:
            accepted_permissions = response.headers.get("X-Accepted-GitHub-Permissions")
            return [], {
                "unsupported": True,
                "reason": "GitHub token cannot read repository webhooks.",
                "status_code": 403,
                "accepted_github_permissions": accepted_permissions,
                "response": response.text[:500],
            }
        if response.status_code >= 400:
            raise HTTPException(response.status_code, response.text[:500])
        return response.json(), None

    async def repository_events(self, owner: str, repo: str) -> list[dict[str, Any]]:
        return await self.paged(f"/repos/{owner}/{repo}/events")

    async def remove_collaborator(self, owner: str, repo: str, username: str) -> None:
        await self.request("DELETE", f"/repos/{owner}/{repo}/collaborators/{username}")

    async def downgrade_collaborator(self, owner: str, repo: str, username: str) -> None:
        await self.request("PUT", f"/repos/{owner}/{repo}/collaborators/{username}", json={"permission": "pull"})

    async def remove_deploy_key(self, owner: str, repo: str, key_id: int) -> None:
        await self.request("DELETE", f"/repos/{owner}/{repo}/keys/{key_id}")

    async def remove_hook(self, owner: str, repo: str, hook_id: int) -> None:
        await self.request("DELETE", f"/repos/{owner}/{repo}/hooks/{hook_id}")

    async def make_private(self, owner: str, repo: str) -> None:
        await self.request("PATCH", f"/repos/{owner}/{repo}", json={"private": True})

    async def protect_branch(self, owner: str, repo: str, branch: str) -> None:
        await self.request(
            "PUT",
            f"/repos/{owner}/{repo}/branches/{branch}/protection",
            json={
                "required_status_checks": None,
                "enforce_admins": True,
                "required_pull_request_reviews": {"required_approving_review_count": 1},
                "restrictions": None,
            },
        )


def repo_name(value: str) -> tuple[str, str] | None:
    value = value.strip().strip("/")
    match = re.match(r"^(?:https://github\.com/)?([^/\s]+)/([^/\s]+?)(?:\.git)?$", value)
    if match:
        return match.group(1), match.group(2)
    return None


def b64url(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).rstrip(b"=").decode("ascii")


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def github_app_ready() -> bool:
    cfg = config()
    return bool(
        cfg["github_app_id"]
        and (cfg["github_private_key"] or cfg["github_private_key_path"])
    )


def load_github_private_key() -> bytes:
    cfg = config()
    if cfg["github_private_key"]:
        return cfg["github_private_key"].replace("\\n", "\n").encode("utf-8")
    if cfg["github_private_key_path"]:
        key_path = Path(cfg["github_private_key_path"])
        if not key_path.is_absolute():
            key_path = BASE_DIR / key_path
        return key_path.read_bytes()
    raise HTTPException(400, "Set GITHUB_PRIVATE_KEY_PATH or GITHUB_PRIVATE_KEY in guard/.env.")


def github_app_jwt() -> str:
    cfg = config()
    if not cfg["github_app_id"]:
        raise HTTPException(400, "Set GITHUB_APP_ID in guard/.env.")

    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT"}
    payload = {"iat": now - 60, "exp": now + 540, "iss": cfg["github_app_id"]}
    signing_input = f"{b64url(json_dumps(header).encode('utf-8'))}.{b64url(json_dumps(payload).encode('utf-8'))}"
    private_key = serialization.load_pem_private_key(load_github_private_key(), password=None)
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(signature)}"


async def github_installation_token(owner: str, repo: str) -> str:
    jwt_token = github_app_jwt()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {jwt_token}",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
        "User-Agent": "retayn-guard",
    }
    async with httpx.AsyncClient(base_url=GITHUB_API, headers=headers, timeout=20) as client:
        installation_response = await client.get(f"/repos/{owner}/{repo}/installation")
        if installation_response.status_code == 404:
            raise HTTPException(
                404,
                f"Retayn is not installed on {owner}/{repo}. Open GitHub install, select this repo, then try again.",
            )
        if installation_response.status_code in {401, 403}:
            raise HTTPException(
                installation_response.status_code,
                f"Retayn cannot verify its GitHub App installation for {owner}/{repo}. Check GITHUB_APP_ID and private key.",
            )
        if installation_response.status_code >= 400:
            raise HTTPException(installation_response.status_code, installation_response.text[:500])

        installation_id = installation_response.json()["id"]
        token_response = await client.post(f"/app/installations/{installation_id}/access_tokens")
        if token_response.status_code >= 400:
            raise HTTPException(token_response.status_code, token_response.text[:500])
        return token_response.json()["token"]


async def github_client(owner: str | None = None, repo: str | None = None) -> GitHubClient:
    if owner and repo and github_app_ready():
        return GitHubClient(await github_installation_token(owner, repo))

    token = config()["github_token"]
    if not token or token in {"ghp_demo", "github_token_here"}:
        if github_app_ready():
            raise HTTPException(400, "GitHub App auth needs a repo owner/name before it can mint an installation token.")
        raise HTTPException(400, "Set GitHub App credentials or GITHUB_TOKEN in guard/.env first.")
    return GitHubClient(token)


def github_install_url() -> str | None:
    slug = config()["github_app_slug"]
    if not slug:
        return None
    return f"https://github.com/apps/{slug}/installations/new"


def github_error_message(exc: HTTPException, owner: str, repo: str) -> str:
    if exc.status_code in {401, 403, 404}:
        install_url = github_install_url()
        if install_url:
            return f"Retayn cannot access {owner}/{repo} yet. Make sure the GitHub App is installed on that exact repo and GITHUB_APP_ID plus the private key are set."
        return f"You do not have access to {owner}/{repo} with the current Retayn GitHub connection."
    return str(exc.detail)


def clean_shopify_domain(value: str) -> str:
    domain = value.strip().replace("https://", "").replace("http://", "").strip("/")
    if "." not in domain:
        domain = f"{domain}.myshopify.com"
    return domain


def airtable_base_id(value: str) -> str | None:
    match = re.search(r"\b(app[A-Za-z0-9]{10,})\b", value.strip())
    return match.group(1) if match else None


async def shopify_get(shop_domain: str, token: str, path: str) -> Any:
    async with httpx.AsyncClient(
        base_url=f"https://{clean_shopify_domain(shop_domain)}/admin/api/{SHOPIFY_API_VERSION}",
        headers={"X-Shopify-Access-Token": token, "Accept": "application/json"},
        timeout=20,
    ) as client:
        response = await client.get(path)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Shopify API error: {response.text[:500]}")
    return response.json()


async def slack_get(token: str, path: str, params: dict[str, Any] | None = None) -> Any:
    async with httpx.AsyncClient(
        base_url="https://slack.com/api",
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    ) as client:
        response = await client.get(path, params=params or {})
    data = response.json()
    if response.status_code >= 400 or not data.get("ok"):
        raise HTTPException(response.status_code if response.status_code >= 400 else 400, f"Slack API error: {data.get('error') or response.text[:500]}")
    return data


async def airtable_get(token: str, path: str, params: dict[str, Any] | None = None) -> Any:
    async with httpx.AsyncClient(
        base_url="https://api.airtable.com/v0",
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    ) as client:
        response = await client.get(path, params=params or {})
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Airtable API error: {response.text[:500]}")
    return response.json()


async def zendesk_get(subdomain: str, email: str, token: str, path: str) -> Any:
    auth = (f"{email}/token", token)
    async with httpx.AsyncClient(
        base_url=f"https://{subdomain.strip()}.zendesk.com/api/v2",
        auth=auth,
        timeout=20,
    ) as client:
        response = await client.get(path)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Zendesk API error: {response.text[:500]}")
    return response.json()


async def zendesk_get_oauth(subdomain: str, token: str, path: str) -> Any:
    async with httpx.AsyncClient(
        base_url=f"https://{subdomain.strip()}.zendesk.com/api/v2",
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    ) as client:
        response = await client.get(path)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Zendesk API error: {response.text[:500]}")
    return response.json()


async def zendesk_role_users(subdomain: str, email: str | None = None, api_token: str | None = None, access_token: str | None = None) -> list[dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for role in ("admin", "agent"):
        page = 1
        while True:
            path = f"/users.json?role={role}&per_page=100&page={page}"
            if access_token:
                data = await zendesk_get_oauth(subdomain, access_token, path)
            else:
                data = await zendesk_get(subdomain, email or "", api_token or "", path)
            for user in data.get("users", []):
                if user.get("id"):
                    output[str(user["id"])] = user
            if not data.get("next_page") or not data.get("users"):
                break
            page += 1
    return list(output.values())


def google_access_token(admin_email: str, service_account_json_path: str) -> str:
    key_path = Path(service_account_json_path)
    if not key_path.is_absolute():
        key_path = BASE_DIR / key_path
    if not key_path.exists():
        raise HTTPException(400, f"Google service account file was not found: {key_path}")
    credentials = service_account.Credentials.from_service_account_file(
        str(key_path),
        scopes=["https://www.googleapis.com/auth/admin.directory.user.readonly"],
    ).with_subject(admin_email.strip())
    credentials.refresh(GoogleAuthRequest())
    return credentials.token


async def google_workspace_get(admin_email: str, service_account_json_path: str, path: str, params: dict[str, Any]) -> Any:
    token = google_access_token(admin_email, service_account_json_path)
    async with httpx.AsyncClient(
        base_url="https://admin.googleapis.com/admin/directory/v1",
        headers={"Authorization": f"Bearer {token}"},
        timeout=20,
    ) as client:
        response = await client.get(path, params=params)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Google Workspace API error: {response.text[:500]}")
    return response.json()


async def google_workspace_get_oauth(access_token: str, path: str, params: dict[str, Any]) -> Any:
    async with httpx.AsyncClient(
        base_url="https://admin.googleapis.com/admin/directory/v1",
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=20,
    ) as client:
        response = await client.get(path, params=params)
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Google Workspace API error: {response.text[:500]}")
    return response.json()


async def baseline_google_workspace_oauth(account_id: int, domain: str, access_token: str) -> None:
    data = await google_workspace_get_oauth(
        access_token,
        "/users",
        {"domain": domain.strip(), "maxResults": 200, "orderBy": "email"},
    )
    snapshot_set(account_id, "workspace", {"domain": domain.strip(), "auth": "OAuth"})
    snapshot_set(account_id, "users", simplify_google_users(data.get("users", [])))


async def exchange_slack_code(code: str) -> dict[str, Any]:
    cfg = config()
    client_secret = require_config_value(cfg, "slack_client_secret", "SLACK_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://slack.com/api/oauth.v2.access",
            data={
                "client_id": cfg["slack_client_id"],
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": oauth_redirect_uri("slack"),
            },
        )
    data = response.json()
    if response.status_code >= 400 or not data.get("ok"):
        raise HTTPException(400, f"Slack OAuth error: {data.get('error') or response.text[:500]}")
    return data


async def exchange_google_code(code: str) -> dict[str, Any]:
    cfg = config()
    client_secret = require_config_value(cfg, "google_workspace_client_secret", "GOOGLE_WORKSPACE_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": cfg["google_workspace_client_id"],
                "client_secret": client_secret,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": oauth_redirect_uri("google_workspace"),
            },
        )
    data = response.json()
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Google OAuth error: {response.text[:500]}")
    return data


async def exchange_airtable_code(code: str, code_verifier: str) -> dict[str, Any]:
    cfg = config()
    client_secret = require_config_value(cfg, "airtable_client_secret", "AIRTABLE_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://airtable.com/oauth2/v1/token",
            auth=(cfg["airtable_client_id"], client_secret),
            data={
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": oauth_redirect_uri("airtable"),
                "code_verifier": code_verifier,
            },
        )
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Airtable OAuth error: {response.text[:500]}")
    return response.json()


async def exchange_shopify_code(shop_domain: str, code: str) -> dict[str, Any]:
    cfg = config()
    client_secret = require_config_value(cfg, "shopify_client_secret", "SHOPIFY_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            f"https://{clean_shopify_domain(shop_domain)}/admin/oauth/access_token",
            json={
                "client_id": cfg["shopify_client_id"],
                "client_secret": client_secret,
                "code": code,
            },
        )
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Shopify OAuth error: {response.text[:500]}")
    return response.json()


async def exchange_zendesk_code(subdomain: str, code: str) -> dict[str, Any]:
    cfg = config()
    client_secret = require_config_value(cfg, "zendesk_client_secret", "ZENDESK_CLIENT_SECRET")
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            f"https://{subdomain.strip()}.zendesk.com/oauth/tokens",
            json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": cfg["zendesk_client_id"],
                "client_secret": client_secret,
                "redirect_uri": oauth_redirect_uri("zendesk"),
                "scope": "read",
            },
        )
    if response.status_code >= 400:
        raise HTTPException(response.status_code, f"Zendesk OAuth error: {response.text[:500]}")
    return response.json()


async def baseline_repo(account_id: int, owner: str, repo: str) -> None:
    gh = await github_client(owner, repo)
    try:
        repo_info = await gh.repo(owner, repo)
        collaborators = await gh.collaborators(owner, repo)
        branches = await gh.branches(owner, repo)
        default_branch = repo_info.get("default_branch")
        protection = await gh.branch_protection(owner, repo, default_branch) if default_branch else None
        keys = await gh.deploy_keys(owner, repo)
        hooks, hooks_error = await gh.hooks(owner, repo)
        repo_events = await gh.repository_events(owner, repo)
    finally:
        await gh.close()

    snapshot_set(account_id, "repo", repo_info)
    snapshot_set(account_id, "collaborators", simplify_collaborators(collaborators))
    snapshot_set(account_id, "default_branch", default_branch)
    snapshot_set(account_id, "branch_protection", protection)
    snapshot_set(account_id, "deploy_keys", simplify_deploy_keys(keys))
    snapshot_set(account_id, "hooks", simplify_hooks(hooks))
    snapshot_set(account_id, "hooks_error", hooks_error)
    snapshot_set(account_id, "repository_events", simplify_repository_events(repo_events))


async def baseline_shopify(account_id: int, shop_domain: str, admin_token: str) -> None:
    shop = (await shopify_get(shop_domain, admin_token, "/shop.json")).get("shop", {})
    snapshot_set(account_id, "shop", {
        "name": shop.get("name"),
        "domain": shop.get("domain"),
        "myshopify_domain": shop.get("myshopify_domain"),
        "email": shop.get("email"),
        "plan_name": shop.get("plan_name"),
    })
    snapshot_set(account_id, "access", [{"name": "Admin API token", "status": "validated"}])


async def baseline_slack(account_id: int, bot_token: str) -> tuple[str, str]:
    auth = await slack_get(bot_token, "/auth.test")
    users: list[dict[str, Any]] = []
    cursor = ""
    while True:
        data = await slack_get(bot_token, "/users.list", {"limit": 200, "cursor": cursor})
        users.extend(data.get("members", []))
        cursor = (data.get("response_metadata") or {}).get("next_cursor") or ""
        if not cursor:
            break
    snapshot_set(account_id, "workspace", {
        "team": auth.get("team"),
        "team_id": auth.get("team_id"),
        "bot_user_id": auth.get("user_id"),
    })
    snapshot_set(account_id, "users", simplify_slack_users(users))
    return auth.get("team_id") or "slack", auth.get("team") or "Slack workspace"


async def baseline_google_workspace(account_id: int, domain: str, admin_email: str, service_account_json_path: str) -> None:
    data = await google_workspace_get(
        admin_email,
        service_account_json_path,
        "/users",
        {"domain": domain.strip(), "maxResults": 200, "orderBy": "email"},
    )
    snapshot_set(account_id, "workspace", {"domain": domain.strip(), "admin_email": admin_email.strip()})
    snapshot_set(account_id, "users", simplify_google_users(data.get("users", [])))


async def baseline_airtable(account_id: int, base_id: str, personal_access_token: str) -> None:
    base_id = airtable_base_id(base_id) or base_id.strip()
    schema = await airtable_get(personal_access_token, f"/meta/bases/{base_id}/tables")
    collaborators = await airtable_get(
        personal_access_token,
        f"/meta/bases/{base_id}",
        {"include": ["collaborators", "inviteLinks", "interfaces"]},
    )
    snapshot_set(account_id, "base", {
        "id": base_id,
        "name": collaborators.get("name") or schema.get("name"),
        "workspace_id": collaborators.get("workspaceId") or collaborators.get("workspace_id"),
        "permission_level": collaborators.get("permissionLevel") or collaborators.get("permission_level"),
    })
    snapshot_set(account_id, "tables", [
        {
            "id": table.get("id"),
            "name": table.get("name"),
            "fields": [field.get("name") for field in table.get("fields", [])],
        }
        for table in schema.get("tables", [])
    ])
    snapshot_set(account_id, "users", simplify_airtable_collaborators(collaborators, base_id))


async def baseline_zendesk(account_id: int, subdomain: str, email: str, api_token: str) -> None:
    current = await zendesk_get(subdomain, email, api_token, "/users/me.json")
    users = await zendesk_role_users(subdomain, email=email, api_token=api_token)
    snapshot_set(account_id, "account", {"subdomain": subdomain.strip(), "current_user": (current.get("user") or {}).get("email")})
    snapshot_set(account_id, "users", simplify_zendesk_users(users))


async def baseline_zendesk_oauth(account_id: int, subdomain: str, access_token: str) -> None:
    current = await zendesk_get_oauth(subdomain, access_token, "/users/me.json")
    users = await zendesk_role_users(subdomain, access_token=access_token)
    snapshot_set(account_id, "account", {"subdomain": subdomain.strip(), "current_user": (current.get("user") or {}).get("email")})
    snapshot_set(account_id, "users", simplify_zendesk_users(users))


def simplify_collaborators(collaborators: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        item["login"].casefold(): {
            "login": item["login"],
            "role_name": item.get("role_name"),
            "permissions": item.get("permissions", {}),
            "type": item.get("type"),
        }
        for item in collaborators
    }


def simplify_deploy_keys(keys: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        str(item["id"]): {
            "id": item["id"],
            "title": item.get("title"),
            "read_only": item.get("read_only"),
        }
        for item in keys
    }


def simplify_hooks(hooks: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        str(item["id"]): {
            "id": item["id"],
            "name": item.get("name"),
            "active": item.get("active"),
            "url": (item.get("config") or {}).get("url"),
            "events": item.get("events", []),
        }
        for item in hooks
    }


def simplify_slack_users(users: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        item["id"]: {
            "id": item.get("id"),
            "name": item.get("name"),
            "real_name": item.get("real_name"),
            "team_id": item.get("team_id"),
            "is_admin": item.get("is_admin"),
            "is_owner": item.get("is_owner"),
            "is_bot": item.get("is_bot"),
            "deleted": item.get("deleted"),
        }
        for item in users
        if item.get("id") and not item.get("deleted")
    }


def simplify_google_users(users: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        item["primaryEmail"].casefold(): {
            "email": item.get("primaryEmail"),
            "name": (item.get("name") or {}).get("fullName"),
            "is_admin": item.get("isAdmin"),
            "suspended": item.get("suspended"),
            "org_unit_path": item.get("orgUnitPath"),
            "created_at": item.get("creationTime"),
        }
        for item in users
        if item.get("primaryEmail") and not item.get("suspended")
    }


def nested_list(value: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    return current if isinstance(current, list) else []


def airtable_permission(item: dict[str, Any]) -> str:
    return str(item.get("permissionLevel") or item.get("permission_level") or item.get("role") or "unknown")


def simplify_airtable_collaborators(data: dict[str, Any], base_id: str) -> dict[str, Any]:
    output: dict[str, Any] = {}

    def add_person(item: dict[str, Any], source: str) -> None:
        user_id = str(item.get("userId") or item.get("user_id") or item.get("id") or item.get("email") or "")
        if not user_id:
            return
        output[f"user:{user_id}".casefold()] = {
            "id": user_id,
            "email": item.get("email"),
            "name": item.get("name"),
            "permission_level": airtable_permission(item),
            "source": source,
            "type": "person",
            "base_id": item.get("baseId") or item.get("base_id") or base_id,
            "granted_by_user_id": item.get("grantedByUserId") or item.get("granted_by_user_id"),
            "created_at": item.get("createdTime") or item.get("created_time"),
        }

    def add_group(item: dict[str, Any], source: str) -> None:
        group_id = str(item.get("groupId") or item.get("group_id") or item.get("id") or item.get("name") or "")
        if not group_id:
            return
        output[f"group:{group_id}".casefold()] = {
            "id": group_id,
            "name": item.get("name") or f"Airtable group {group_id}",
            "permission_level": airtable_permission(item),
            "source": source,
            "type": "group",
            "base_id": item.get("baseId") or item.get("base_id") or base_id,
            "granted_by_user_id": item.get("grantedByUserId") or item.get("granted_by_user_id"),
            "created_at": item.get("createdTime") or item.get("created_time"),
        }

    individuals = data.get("individualCollaborators") or data.get("individual_collaborators") or {}
    groups = data.get("groupCollaborators") or data.get("group_collaborators") or {}
    for item in nested_list(individuals, "baseCollaborators") + nested_list(individuals, "base_collaborators"):
        add_person(item, "base")
    for item in nested_list(individuals, "workspaceCollaborators") + nested_list(individuals, "workspace_collaborators"):
        add_person(item, "workspace")
    for item in nested_list(groups, "baseCollaborators") + nested_list(groups, "base_collaborators"):
        add_group(item, "base")
    for item in nested_list(groups, "workspaceCollaborators") + nested_list(groups, "workspace_collaborators"):
        add_group(item, "workspace")

    # Some API clients flatten these lists. Keep this as a tolerant fallback.
    for item in data.get("baseCollaborators", []):
        add_person(item, "base")
    for item in data.get("workspaceCollaborators", []):
        add_person(item, "workspace")
    return output


def simplify_zendesk_users(users: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        str(item["id"]): {
            "id": item.get("id"),
            "name": item.get("name"),
            "email": item.get("email"),
            "role": item.get("role"),
            "suspended": item.get("suspended"),
            "active": item.get("active"),
        }
        for item in users
        if item.get("id") and not item.get("suspended") and item.get("active") is not False
    }


def simplify_repository_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        str(item["id"]): {
            "id": item["id"],
            "type": item.get("type"),
            "actor": (item.get("actor") or {}).get("login"),
            "created_at": item.get("created_at"),
            "payload": item.get("payload") or {},
        }
        for item in events
    }


def identity_label(identity: dict[str, Any]) -> str:
    return str(
        identity.get("email")
        or identity.get("real_name")
        or identity.get("name")
        or identity.get("login")
        or identity.get("id")
        or "Unknown user"
    )


def identity_rank(connector: str, identity: dict[str, Any]) -> int:
    if connector == "slack":
        if identity.get("is_owner"):
            return 3
        return 2 if identity.get("is_admin") else 0
    if connector == "google_workspace":
        return 2 if identity.get("is_admin") else 0
    if connector == "zendesk":
        return {"end-user": 0, "agent": 1, "admin": 2}.get(str(identity.get("role") or "").casefold(), 0)
    if connector == "airtable":
        permission = str(identity.get("permission_level") or identity.get("permissionLevel") or "").casefold().replace("_", "").replace("-", "")
        return {
            "readonly": 0,
            "read": 0,
            "commenter": 1,
            "comment": 1,
            "editor": 2,
            "edit": 2,
            "creator": 3,
            "create": 3,
            "owner": 4,
        }.get(permission, 0)
    return 0


def identity_inactive(connector: str, identity: dict[str, Any]) -> bool:
    if connector == "slack":
        return bool(identity.get("deleted"))
    return bool(identity.get("suspended"))


def identity_aliases(identity: dict[str, Any]) -> set[str]:
    aliases = {
        identity.get("email"),
        identity.get("real_name"),
        identity.get("name"),
        identity.get("login"),
        identity.get("id"),
    }
    return {str(item).strip().casefold() for item in aliases if str(item or "").strip()}


def identity_allowed(identity: dict[str, Any], allowed: set[str]) -> bool:
    return bool(identity_aliases(identity) & allowed)


def identity_snapshot_key(account: dict[str, Any]) -> str:
    return "collaborators" if account["connector"] == "github" else "users"


def identity_settings_key(account: dict[str, Any]) -> str:
    return "github_allowed_users" if account["connector"] == "github" else "allowed_identities"


def snapshot_remove_identities(account: dict[str, Any], identities: list[dict[str, Any]]) -> None:
    if not identities:
        return
    snapshot_key = identity_snapshot_key(account)
    baseline = snapshot_get(account["id"], snapshot_key, {})
    aliases_to_remove: set[str] = set()
    for identity in identities:
        aliases_to_remove |= identity_aliases(identity)
    if not aliases_to_remove:
        return
    filtered = {
        key: identity
        for key, identity in baseline.items()
        if not (identity_aliases(identity) & aliases_to_remove or str(key).casefold() in aliases_to_remove)
    }
    if filtered != baseline:
        snapshot_set(account["id"], snapshot_key, filtered)


def update_allowed_identity(account: dict[str, Any], identity: dict[str, Any], allow: bool) -> None:
    fresh_account = row("SELECT * FROM accounts WHERE id=?", (account["id"],)) or account
    settings = get_account_settings(fresh_account)
    key = identity_settings_key(account)
    aliases = identity_aliases(identity)
    if not aliases:
        return
    values = [str(item).strip() for item in settings.get(key, []) if str(item).strip()]
    value_keys = {item.casefold() for item in values}
    if allow:
        label = identity_label(identity)
        if label.casefold() not in value_keys:
            values.append(label)
    else:
        values = [item for item in values if item.casefold() not in aliases]
    settings[key] = values
    if account["connector"] == "github":
        settings["allowed_identities"] = values
    settings["allowed_identities_edited"] = True
    execute(
        "UPDATE accounts SET settings_json=?, updated_at=? WHERE id=?",
        (json_dumps(settings), utc_now(), account["id"]),
    )


def prune_baseline_for_removed_allowed(account: dict[str, Any], removed_values: set[str]) -> list[dict[str, Any]]:
    if not removed_values:
        return []
    snapshot_key = identity_snapshot_key(account)
    baseline = snapshot_get(account["id"], snapshot_key, {})
    removed: list[dict[str, Any]] = []
    kept: dict[str, Any] = {}
    for key, identity in baseline.items():
        aliases = identity_aliases(identity) | {str(key).casefold()}
        if aliases & removed_values:
            removed.append(identity)
        else:
            kept[key] = identity
    if removed:
        snapshot_set(account["id"], snapshot_key, kept)
    return removed


def detect_identity_changes(account: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> None:
    settings = get_account_settings(account)
    allowed = {str(item).casefold() for item in settings.get("allowed_identities", [])}
    if account["connector"] == "github":
        allowed |= {str(item).casefold() for item in settings.get("github_allowed_users", [])}
    connector_name = CONNECTORS[account["connector"]]["name"]
    for key, identity in after.items():
        label = identity_label(identity)
        if key not in before and not identity_allowed(identity, allowed) and not identity_inactive(account["connector"], identity):
            rank = identity_rank(account["connector"], identity)
            unique = f"new_identity:{key}"
            if not suppressible_event_exists(account["id"], "new_identity", unique):
                role_text = " with administrator access" if rank >= 2 else ""
                create_event(
                    account["id"],
                    "new_identity",
                    "high" if rank >= 2 else "medium",
                    f"New {connector_name} user",
                    f"{label} appeared in {account_display(account)}{role_text}.",
                    {"unique_key": unique, "identity": identity, "supported_action": None},
                )
            continue

        old = before.get(key)
        if not old:
            continue
        old_rank = identity_rank(account["connector"], old)
        new_rank = identity_rank(account["connector"], identity)
        if new_rank > old_rank:
            unique = f"identity_escalation:{key}:{new_rank}"
            if not suppressible_event_exists(account["id"], "identity_escalation", unique):
                create_event(
                    account["id"],
                    "identity_escalation",
                    "high",
                    f"{connector_name} access escalated",
                    f"{label} gained a more powerful role in {account_display(account)}.",
                    {"unique_key": unique, "before": old, "after": identity, "supported_action": None},
                )
        if new_rank < old_rank:
            unique = f"identity_role_downgrade:{key}:{old_rank}:{new_rank}"
            if not suppressible_event_exists(account["id"], "identity_role_downgrade", unique):
                create_event(
                    account["id"],
                    "identity_role_downgrade",
                    "high" if old_rank >= 2 else "medium",
                    f"{connector_name} access reduced",
                    f"{label} lost a powerful role in {account_display(account)}.",
                    {"unique_key": unique, "before": old, "after": identity, "supported_action": None},
                )
        if identity_inactive(account["connector"], old) and not identity_inactive(account["connector"], identity):
            unique = f"identity_reactivated:{key}"
            if not suppressible_event_exists(account["id"], "identity_reactivated", unique):
                create_event(
                    account["id"],
                    "identity_reactivated",
                    "high" if new_rank >= 2 else "medium",
                    f"{connector_name} account reactivated",
                    f"{label} is active again in {account_display(account)}.",
                    {"unique_key": unique, "before": old, "after": identity, "supported_action": None},
                )
        if not identity_inactive(account["connector"], old) and identity_inactive(account["connector"], identity):
            unique = f"identity_deactivated:{key}"
            if not suppressible_event_exists(account["id"], "identity_deactivated", unique):
                create_event(
                    account["id"],
                    "identity_deactivated",
                    "high" if old_rank >= 2 else "medium",
                    f"{connector_name} account deactivated",
                    f"{label} was suspended, deactivated, or removed from active access in {account_display(account)}.",
                    {"unique_key": unique, "before": old, "after": identity, "identity": identity, "supported_action": None},
                )

    for key, identity in before.items():
        if key in after:
            continue
        label = identity_label(identity)
        old_rank = identity_rank(account["connector"], identity)
        unique = f"identity_removed:{key}"
        if not suppressible_event_exists(account["id"], "identity_removed", unique):
            create_event(
                account["id"],
                "identity_removed",
                "high" if old_rank >= 2 else "medium",
                f"{connector_name} account removed",
                f"{label} no longer has active access in {account_display(account)}.",
                {"unique_key": unique, "identity": identity, "supported_action": None},
            )


def detect_shopify_changes(account: dict[str, Any], before: dict[str, Any], after: dict[str, Any]) -> None:
    important = {"domain", "myshopify_domain", "email", "plan_name"}
    changes = {key: {"before": before.get(key), "after": after.get(key)} for key in important if before.get(key) != after.get(key)}
    if not before or not changes:
        return
    unique = "shop_identity:" + hashlib.sha256(json_dumps(changes).encode("utf-8")).hexdigest()[:16]
    if not open_event_exists(account["id"], "shop_identity_changed", unique):
        create_event(
            account["id"],
            "shop_identity_changed",
            "high" if any(key in changes for key in {"domain", "myshopify_domain", "email"}) else "medium",
            "Shopify store identity changed",
            f"Important account details changed for {account_display(account)}.",
            {"unique_key": unique, "changes": changes, "supported_action": None},
        )


def detect_airtable_changes(account: dict[str, Any], before: list[dict[str, Any]], after: list[dict[str, Any]]) -> None:
    old = {str(item.get("id")): item for item in before}
    new = {str(item.get("id")): item for item in after}
    added = [item for key, item in new.items() if key not in old]
    removed = [item for key, item in old.items() if key not in new]
    changed = [new[key] for key in old.keys() & new.keys() if old[key] != new[key]]
    if not before or not (added or removed or changed):
        return
    fingerprint = hashlib.sha256(json_dumps({"added": added, "removed": removed, "changed": changed}).encode("utf-8")).hexdigest()[:16]
    unique = f"airtable_schema:{fingerprint}"
    if not open_event_exists(account["id"], "airtable_schema_changed", unique):
        create_event(
            account["id"],
            "airtable_schema_changed",
            "high" if removed else "medium",
            "Airtable schema changed",
            f"Tables or fields changed in {account_display(account)}.",
            {"unique_key": unique, "added": added, "removed": removed, "changed": changed, "supported_action": None},
        )


def is_privileged(collab: dict[str, Any]) -> bool:
    role = str(collab.get("role_name") or "").casefold()
    perms = collab.get("permissions") or {}
    return role in {"admin", "maintain", "write"} or perms.get("admin") or perms.get("maintain") or perms.get("push")


def is_admin(collab: dict[str, Any]) -> bool:
    role = str(collab.get("role_name") or "").casefold()
    perms = collab.get("permissions") or {}
    return role == "admin" or bool(perms.get("admin"))


def find_membership_actor(repository_events: dict[str, Any], login: str) -> dict[str, Any] | None:
    login_key = login.casefold()
    for event in sorted(repository_events.values(), key=lambda item: item.get("created_at") or "", reverse=True):
        if event.get("type") != "MemberEvent":
            continue
        payload = event.get("payload") or {}
        member = payload.get("member") or {}
        if str(member.get("login") or "").casefold() != login_key:
            continue
        actor = event.get("actor")
        if not actor:
            continue
        return {
            "login": actor,
            "event_id": event.get("id"),
            "event_type": event.get("type"),
            "action": payload.get("action"),
            "created_at": event.get("created_at"),
        }
    return None


def open_event_exists(account_id: int, event_type: str, unique_key: str) -> bool:
    existing = row(
        """
        SELECT id FROM events
        WHERE account_id=? AND event_type=? AND status IN ('open', 'blocked', 'auto_actioned')
          AND json_extract(details_json, '$.unique_key')=?
        """,
        (account_id, event_type, unique_key),
    )
    return bool(existing)


def finding_accepted(account_id: int, event_type: str, unique_key: str) -> bool:
    return bool(row(
        "SELECT 1 FROM accepted_findings WHERE account_id=? AND event_type=? AND unique_key=?",
        (account_id, event_type, unique_key),
    ))


def suppressible_event_exists(account_id: int, event_type: str, unique_key: str) -> bool:
    return open_event_exists(account_id, event_type, unique_key) or finding_accepted(account_id, event_type, unique_key)


def remember_accepted_finding(account_id: int, event_type: str, details: dict[str, Any]) -> None:
    unique_key = details.get("unique_key")
    if not unique_key:
        return
    execute(
        """
        INSERT INTO accepted_findings(account_id, event_type, unique_key, accepted_at)
        VALUES(?, ?, ?, ?)
        ON CONFLICT(account_id, event_type, unique_key)
        DO UPDATE SET accepted_at=excluded.accepted_at
        """,
        (account_id, event_type, str(unique_key), utc_now()),
    )


def apply_event_approval_to_trust(account: dict[str, Any], event_type: str, details: dict[str, Any]) -> None:
    if event_type in {"new_identity", "identity_escalation", "identity_role_downgrade", "identity_reactivated"}:
        identity = details.get("after") or details.get("identity") or {}
        if identity:
            update_allowed_identity(account, identity, True)
        return
    if event_type in {"identity_removed", "identity_deactivated", "privileged_identity_removed", "trusted_identity_removed"}:
        identities = [
            item for item in [details.get("identity"), details.get("after"), details.get("before")]
            if isinstance(item, dict) and item
        ]
        for identity in identities:
            update_allowed_identity(account, identity, False)
        snapshot_remove_identities(account, identities)


async def scan_repo(account: dict[str, Any]) -> None:
    owner, repo = account["owner"], account["repo"]
    settings = get_account_settings(account)
    gh = await github_client(owner, repo)
    try:
        repo_info = await gh.repo(owner, repo)
        collaborators = simplify_collaborators(await gh.collaborators(owner, repo))
        branches = await gh.branches(owner, repo)
        default_branch = repo_info.get("default_branch")
        protection = await gh.branch_protection(owner, repo, default_branch) if default_branch else None
        keys = simplify_deploy_keys(await gh.deploy_keys(owner, repo))
        raw_hooks, hooks_error = await gh.hooks(owner, repo)
        hooks = simplify_hooks(raw_hooks)
        repo_events = simplify_repository_events(await gh.repository_events(owner, repo))

        await detect_repo_visibility(account, gh, repo_info)
        await detect_collaborators(account, gh, collaborators, settings, repo_events)
        await detect_branch_protection(account, gh, branches, default_branch, protection)
        await detect_deploy_keys(account, gh, keys, settings)
        await detect_hooks(account, gh, hooks, hooks_error, settings)

        snapshot_set(account["id"], "repo", repo_info)
        snapshot_set(account["id"], "collaborators", collaborators)
        snapshot_set(account["id"], "default_branch", default_branch)
        snapshot_set(account["id"], "branch_protection", protection)
        snapshot_set(account["id"], "deploy_keys", keys)
        snapshot_set(account["id"], "hooks", hooks)
        snapshot_set(account["id"], "hooks_error", hooks_error)
        snapshot_set(account["id"], "repository_events", repo_events)
        execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account["id"]))
    finally:
        await gh.close()


async def detect_repo_visibility(account: dict[str, Any], gh: GitHubClient, repo_info: dict[str, Any]) -> None:
    baseline = snapshot_get(account["id"], "repo", {})
    if baseline and baseline.get("private") and not repo_info.get("private"):
        unique = "visibility_public"
        if open_event_exists(account["id"], "repo_visibility", unique):
            return
        details = {
            "unique_key": unique,
            "from_private": True,
            "to_private": False,
            "supported_action": "make_private",
        }
        create_event(
            account["id"],
            "repo_visibility",
            "critical",
            "Repository made public",
            f"{account['owner']}/{account['repo']} changed from private to public.",
            details,
        )


async def detect_collaborators(
    account: dict[str, Any],
    gh: GitHubClient,
    collaborators: dict[str, Any],
    settings: dict[str, Any],
    repository_events: dict[str, Any],
) -> None:
    baseline = snapshot_get(account["id"], "collaborators", {})
    trusted = set(baseline.keys()) | {user.casefold() for user in settings["github_allowed_users"]}
    for login_key, collab in collaborators.items():
        actor = find_membership_actor(repository_events, collab["login"])
        if login_key not in trusted:
            unique = f"new_collaborator:{login_key}"
            if open_event_exists(account["id"], "new_collaborator", unique):
                continue
            supported_actions = [{"id": "remove_collaborator", "label": "Remove collaborator"}]
            if actor and actor["login"].casefold() != login_key:
                supported_actions.extend(
                    [
                        {"id": "downgrade_actor", "label": "Downgrade appointer"},
                        {"id": "remove_actor", "label": "Remove appointer"},
                    ]
                )
            actor_text = f" by {actor['login']}" if actor else ""
            title = "GitHub admin appointed" if is_admin(collab) else "New GitHub collaborator"
            summary = (
                f"{collab['login']} is now an admin on {account['owner']}/{account['repo']}{actor_text}."
                if is_admin(collab)
                else f"{collab['login']} gained access to {account['owner']}/{account['repo']}{actor_text}."
            )
            create_event(
                account["id"],
                "new_collaborator",
                "high",
                title,
                summary,
                {
                    "unique_key": unique,
                    "collaborator": collab,
                    "appointed_by": actor,
                    "supported_action": "remove_collaborator",
                    "supported_actions": supported_actions,
                },
            )
            continue

        old = baseline.get(login_key)
        if old and not is_privileged(old) and is_privileged(collab):
            unique = f"role_escalation:{login_key}:{collab.get('role_name')}"
            if open_event_exists(account["id"], "role_escalation", unique):
                continue
            supported_actions = [{"id": "downgrade_collaborator", "label": "Downgrade promoted user"}]
            if actor and actor["login"].casefold() != login_key:
                supported_actions.extend(
                    [
                        {"id": "downgrade_actor", "label": "Downgrade appointer"},
                        {"id": "remove_actor", "label": "Remove appointer"},
                    ]
                )
            if is_admin(collab):
                title = "GitHub admin appointed"
                actor_text = f" by {actor['login']}" if actor else ""
                summary = f"{collab['login']} is now an admin{actor_text}."
            else:
                title = "GitHub permission escalated"
                summary = f"{collab['login']} changed from {old.get('role_name')} to {collab.get('role_name')}."
            create_event(
                account["id"],
                "role_escalation",
                "high",
                title,
                summary,
                {
                    "unique_key": unique,
                    "before": old,
                    "after": collab,
                    "appointed_by": actor,
                    "supported_action": "downgrade_collaborator",
                    "supported_actions": supported_actions,
                },
            )


async def detect_branch_protection(
    account: dict[str, Any],
    gh: GitHubClient,
    branches: list[dict[str, Any]],
    default_branch: str | None,
    protection: dict[str, Any] | None,
) -> None:
    baseline = snapshot_get(account["id"], "branch_protection", None)
    branch_names = {item.get("name") for item in branches}
    if default_branch and default_branch not in branch_names:
        unique = f"default_branch_missing:{default_branch}"
        if not open_event_exists(account["id"], "default_branch_missing", unique):
            create_event(
                account["id"],
                "default_branch_missing",
                "critical",
                "Default branch missing",
                f"{default_branch} is no longer present in {account['owner']}/{account['repo']}.",
                {"unique_key": unique, "default_branch": default_branch},
            )
    if isinstance(protection, dict) and protection.get("unsupported"):
        unique = f"branch_protection_unsupported:{default_branch}"
        if baseline and not suppressible_event_exists(account["id"], "branch_protection_unsupported", unique):
            create_event(
                account["id"],
                "branch_protection_unsupported",
                "medium",
                "Branch protection unavailable",
                f"GitHub does not expose branch protection for {account['owner']}/{account['repo']} on the current plan.",
                {"unique_key": unique, "branch": default_branch, "supported_action": None, "reason": protection.get("reason")},
            )
        return
    if baseline and protection is None and default_branch:
        unique = f"branch_protection_removed:{default_branch}"
        if open_event_exists(account["id"], "branch_protection_removed", unique):
            return
        create_event(
            account["id"],
            "branch_protection_removed",
            "critical",
            "Branch protection removed",
            f"Protection disappeared from {default_branch}.",
            {"unique_key": unique, "branch": default_branch, "supported_action": "protect_branch"},
        )


async def detect_deploy_keys(account: dict[str, Any], gh: GitHubClient, keys: dict[str, Any], settings: dict[str, Any]) -> None:
    baseline = snapshot_get(account["id"], "deploy_keys", {})
    for key_id, key in keys.items():
        title_key = str(key.get("title") or "").casefold()
        allowed_keys = {item.casefold() for item in settings["github_allowed_write_deploy_keys"]}
        if key_id not in baseline and not key.get("read_only") and title_key not in allowed_keys:
            unique = f"write_deploy_key:{key_id}"
            if open_event_exists(account["id"], "write_deploy_key", unique):
                continue
            create_event(
                account["id"],
                "write_deploy_key",
                "high",
                "Write deploy key added",
                f"A write-capable deploy key was added to {account['repo']}.",
                {"unique_key": unique, "deploy_key": key, "supported_action": "remove_deploy_key"},
            )


async def detect_hooks(
    account: dict[str, Any],
    gh: GitHubClient,
    hooks: dict[str, Any],
    hooks_error: dict[str, Any] | None,
    settings: dict[str, Any],
) -> None:
    if hooks_error:
        unique = "webhooks_inaccessible"
        if not suppressible_event_exists(account["id"], "webhooks_inaccessible", unique):
            create_event(
                account["id"],
                "webhooks_inaccessible",
                "medium",
                "Webhook monitoring unavailable",
                f"Retayn cannot read webhooks for {account['owner']}/{account['repo']} with the current token.",
                {"unique_key": unique, "supported_action": None, "github_error": hooks_error},
            )
        return

    baseline = snapshot_get(account["id"], "hooks", {})
    for hook_id, hook in hooks.items():
        hook_url = str(hook.get("url") or "").casefold()
        allowed_hooks = {item.casefold() for item in settings["github_allowed_hook_urls"]}
        if hook_id not in baseline and hook_url not in allowed_hooks:
            unique = f"new_hook:{hook_id}"
            if open_event_exists(account["id"], "new_webhook", unique):
                continue
            create_event(
                account["id"],
                "new_webhook",
                "medium",
                "New GitHub webhook",
                f"A new webhook was added to {account['repo']}.",
                {"unique_key": unique, "webhook": hook, "supported_action": "remove_webhook"},
            )


async def scan_connected_service(account: dict[str, Any]) -> None:
    connector = account["connector"]
    cfg = config()
    if connector == "shopify":
        before = snapshot_get(account["id"], "shop", {})
        token = await active_connection_token("shopify", account["owner"], "")
        await baseline_shopify(account["id"], account["owner"], token["access_token"] if token else cfg["shopify_admin_token"])
        detect_shopify_changes(account, before, snapshot_get(account["id"], "shop", {}))
    elif connector == "slack":
        before = snapshot_get(account["id"], "users", {})
        token = await active_connection_token("slack", account["owner"], account["repo"]) or await active_connection_token("slack")
        await baseline_slack(account["id"], token["access_token"] if token else cfg["slack_bot_token"])
        detect_identity_changes(account, before, snapshot_get(account["id"], "users", {}))
    elif connector == "google_workspace":
        before = snapshot_get(account["id"], "users", {})
        token = await active_connection_token("google_workspace", account["owner"], "")
        if token:
            await baseline_google_workspace_oauth(account["id"], account["owner"], token["access_token"])
        else:
            await baseline_google_workspace(account["id"], account["owner"], cfg["google_workspace_admin_email"], cfg["google_workspace_service_account_json_path"])
        detect_identity_changes(account, before, snapshot_get(account["id"], "users", {}))
    elif connector == "airtable":
        before_tables = snapshot_get(account["id"], "tables", [])
        before_users = snapshot_get(account["id"], "users", {})
        token = await active_connection_token("airtable", "airtable", account["repo"])
        await baseline_airtable(account["id"], account["repo"], token["access_token"] if token else cfg["airtable_personal_access_token"])
        detect_identity_changes(account, before_users, snapshot_get(account["id"], "users", {}))
        detect_airtable_changes(account, before_tables, snapshot_get(account["id"], "tables", []))
    elif connector == "zendesk":
        before = snapshot_get(account["id"], "users", {})
        token = await active_connection_token("zendesk", account["owner"], "")
        if token:
            await baseline_zendesk_oauth(account["id"], account["owner"], token["access_token"])
        else:
            await baseline_zendesk(account["id"], account["owner"], cfg["zendesk_email"], cfg["zendesk_api_token"])
        detect_identity_changes(account, before, snapshot_get(account["id"], "users", {}))
    snapshot_set(account["id"], "last_scan", {"at": utc_now(), "status": "ok"})


def resolve_connection_errors(account_id: int) -> None:
    open_event = row("SELECT id FROM events WHERE account_id=? AND event_type='connection_error' AND status='open' LIMIT 1", (account_id,))
    execute(
        """
        UPDATE events SET status='restored', action_taken='connection restored', resolved_at=?
        WHERE account_id=? AND event_type='connection_error' AND status='open'
        """,
        (utc_now(), account_id),
    )
    current = snapshot_get(account_id, "scan_health", {})
    snapshot_set(
        account_id,
        "scan_health",
        {
            **current,
            "consecutive_failures": 0,
            "last_success_at": utc_now(),
            "last_restored_event_at": utc_now() if open_event else current.get("last_restored_event_at"),
        },
    )


def connection_error_is_hard(exc: Exception) -> bool:
    if isinstance(exc, HTTPException):
        return exc.status_code in {401, 404}
    return False


def friendly_connection_error(exc: Exception) -> str:
    text = str(exc)
    if isinstance(exc, HTTPException):
        if exc.status_code == 401:
            return "GitHub rejected Retayn's credentials. Reconnect the GitHub app or token."
        if exc.status_code == 403:
            if "rate limit" in text.casefold():
                return "GitHub rate limited the monitoring check. Retayn will try again automatically."
            return "GitHub blocked part of the monitoring check. Check the GitHub app permissions if this continues."
        if exc.status_code == 404:
            return "GitHub could not find this repository for Retayn. The repo may have moved, been deleted, or the GitHub app may no longer be installed."
        if exc.status_code >= 500:
            return "GitHub had a temporary service problem. Retayn will try again automatically."
    if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError, httpx.TransportError)):
        return "A temporary network problem interrupted the monitoring check. Retayn will try again automatically."
    return text[:240] or "Retayn could not complete a monitoring check."


def record_connection_error(account: dict[str, Any], exc: Exception) -> None:
    health = snapshot_get(account["id"], "scan_health", {})
    failures = int(health.get("consecutive_failures") or 0) + 1
    hard_failure = connection_error_is_hard(exc)
    friendly_error = friendly_connection_error(exc)
    snapshot_set(account["id"], "scan_health", {"consecutive_failures": failures, "last_error_at": utc_now(), "hard_failure": hard_failure})
    snapshot_set(account["id"], "last_scan", {"at": utc_now(), "status": "error", "message": friendly_error, "consecutive_failures": failures})


async def monitor_account(account_id: int) -> None:
    while True:
        account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
        if not account:
            return
        try:
            if account["connector"] == "github":
                await scan_repo(account)
            else:
                await scan_connected_service(account)
            resolve_connection_errors(account_id)
            execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account_id))
            await process_due_actions(account)
        except Exception as exc:
            logging.exception("Scan failed for account %s", account_id)
            record_connection_error(account, exc)
            health = snapshot_get(account_id, "scan_health", {})
            failures = int(health.get("consecutive_failures") or 0)
            if bool(health.get("hard_failure")) or failures >= 3:
                execute("UPDATE accounts SET status='error', updated_at=? WHERE id=?", (utc_now(), account_id))
            else:
                execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account_id))
        settings = get_account_settings(account)
        poll_seconds = settings.get("monitoring_poll_seconds") or settings.get("github_poll_seconds") or 30
        await asyncio.sleep(max(10, int(poll_seconds)))


async def apply_github_action(event: dict[str, Any], account: dict[str, Any], action_id: str | None = None) -> str:
    details = json.loads(event["details_json"])
    requested_action = action_id or details.get("supported_action")
    gh = await github_client(account["owner"], account["repo"])
    try:
        if event["event_type"] == "new_collaborator" and requested_action == "remove_collaborator":
            await gh.remove_collaborator(account["owner"], account["repo"], details["collaborator"]["login"])
            return "removed collaborator"
        if event["event_type"] == "role_escalation" and requested_action == "downgrade_collaborator":
            await gh.downgrade_collaborator(account["owner"], account["repo"], details["after"]["login"])
            return "downgraded promoted user to read"
        if event["event_type"] in {"new_collaborator", "role_escalation"} and requested_action == "downgrade_actor":
            actor = details.get("appointed_by") or {}
            if not actor.get("login"):
                raise HTTPException(400, "GitHub did not expose who appointed this user.")
            await gh.downgrade_collaborator(account["owner"], account["repo"], actor["login"])
            return "downgraded appointer to read"
        if event["event_type"] in {"new_collaborator", "role_escalation"} and requested_action == "remove_actor":
            actor = details.get("appointed_by") or {}
            if not actor.get("login"):
                raise HTTPException(400, "GitHub did not expose who appointed this user.")
            await gh.remove_collaborator(account["owner"], account["repo"], actor["login"])
            return "removed appointer"
        if event["event_type"] == "repo_visibility" and requested_action == "make_private":
            await gh.make_private(account["owner"], account["repo"])
            return "made repository private"
        if event["event_type"] == "branch_protection_removed" and requested_action == "protect_branch":
            await gh.protect_branch(account["owner"], account["repo"], details["branch"])
            return "restored branch protection"
        if event["event_type"] == "write_deploy_key" and requested_action == "remove_deploy_key":
            await gh.remove_deploy_key(account["owner"], account["repo"], int(details["deploy_key"]["id"]))
            return "removed write deploy key"
        if event["event_type"] == "new_webhook" and requested_action == "remove_webhook":
            await gh.remove_hook(account["owner"], account["repo"], int(details["webhook"]["id"]))
            return "removed webhook"
    finally:
        await gh.close()
    raise HTTPException(400, "This app does not support that action for this notification.")


async def process_due_actions(account: dict[str, Any]) -> None:
    settings = get_account_settings(account)
    if not settings["auto_action_enabled"]:
        return
    delay_minutes = settings["auto_action_delay_minutes"]
    candidates = rows(
        """
        SELECT events.*, accounts.owner, accounts.repo
        FROM events JOIN accounts ON accounts.id=events.account_id
        WHERE events.status='open' AND events.account_id=?
        ORDER BY events.created_at ASC
        """,
        (account["id"],),
    )
    for event in candidates:
        details = json.loads(event["details_json"])
        if not details.get("supported_action"):
            continue
        if event.get("connector") != "github":
            continue
        if event_age_minutes(event["created_at"]) < delay_minutes:
            continue
        account = {"id": event["account_id"], "owner": event["owner"], "repo": event["repo"]}
        try:
            action = await apply_github_action(event, account)
            execute(
                "UPDATE events SET status='auto_actioned', action_taken=?, resolved_at=? WHERE id=?",
                (f"automatic after {delay_minutes} minutes: {action}", utc_now(), event["id"]),
            )
            send_notification(f"Retayn took automatic action on {event['title']}: {action}")
        except Exception as exc:
            logging.exception("Automatic action failed for event %s", event["id"])
            execute(
                "UPDATE events SET action_taken=? WHERE id=?",
                (f"automatic action failed: {exc!s}", event["id"]),
            )


async def start_monitor(account_id: int) -> None:
    task_key = (current_user_id(), account_id)
    old = running_tasks.get(task_key)
    if old and not old.done():
        return
    running_tasks[task_key] = asyncio.create_task(monitor_account(account_id))


async def ensure_user_runtime(user_id: str) -> None:
    if user_id in initialized_users:
        return
    async with initialization_lock:
        if user_id in initialized_users:
            return
        init_db()
        init_recovery_db()
        for account in rows("SELECT id FROM accounts"):
            await start_monitor(account["id"])
        initialized_users.add(user_id)


@app.on_event("startup")
async def startup() -> None:
    load_env_file(BASE_DIR / ".env")
    cfg = config()
    if cfg["app_base_url"].startswith("https://"):
        identity = google_config()
        if not identity["client_id"] or not identity["client_secret"]:
            raise RuntimeError("GOOGLE_AUTH_CLIENT_ID and GOOGLE_AUTH_CLIENT_SECRET are required in production.")
        if not cfg["token_encryption_key"]:
            raise RuntimeError("RETAYN_TOKEN_ENCRYPTION_KEY is required in production.")
        token_encryption_key()
    init_auth_db()


@app.middleware("http")
async def authenticate_dashboard(request: Request, call_next):
    path = request.url.path
    public_path = (
        path.startswith("/auth/")
        or path.startswith("/static/")
        or path == "/health"
    )
    if public_path:
        response = await call_next(request)
        return secure_response(response, request)

    webhook_match = re.fullmatch(r"/webhooks/recovery/([^/]+)/(telegram|whatsapp)", path)
    if webhook_match:
        webhook_user = user_for_webhook_token(webhook_match.group(1))
        if not webhook_user:
            return JSONResponse({"detail": "Unknown webhook destination."}, status_code=404)
        context_token = set_current_user(webhook_user["id"])
        try:
            await ensure_user_runtime(webhook_user["id"])
            response = await call_next(request)
            return secure_response(response, request)
        finally:
            reset_current_user(context_token)

    session = current_session(request)
    if not session:
        if path.startswith("/api/") or path.startswith("/oauth/") or path.startswith("/webhooks/"):
            return JSONResponse({"detail": "Sign in with Google to continue."}, status_code=401)
        return RedirectResponse(f"/auth/signin?{urlencode({'return_to': path})}", status_code=303)

    if request.method not in {"GET", "HEAD", "OPTIONS"} and not path.startswith("/webhooks/"):
        supplied = request.headers.get("x-csrf-token", "")
        if not supplied or not hmac.compare_digest(supplied, session["csrf_token"]):
            return JSONResponse({"detail": "Security check failed. Refresh the page and try again."}, status_code=403)

    request.state.user = session
    context_token = set_current_user(session["id"])
    try:
        await ensure_user_runtime(session["id"])
        response = await call_next(request)
        return secure_response(response, request)
    finally:
        reset_current_user(context_token)


def secure_response(response, request: Request):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' https: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https://accounts.google.com"
    if request.url.path.startswith("/auth/") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-store"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"ok": True})


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request,
        "index.html",
        {"user": request.state.user, "csrf_token": request.state.user["csrf_token"]},
    )


@app.get("/api/overview")
async def overview() -> JSONResponse:
    accounts = rows("SELECT * FROM accounts ORDER BY created_at DESC")
    for account in accounts:
        enrich_account(account)
    open_events = rows(
        """
        SELECT events.*, accounts.owner, accounts.repo
        FROM events LEFT JOIN accounts ON accounts.id=events.account_id
        WHERE events.status='open'
        ORDER BY events.created_at DESC LIMIT 100
        """
    )
    recent_events = rows(
        """
        SELECT events.*, accounts.owner, accounts.repo
        FROM events LEFT JOIN accounts ON accounts.id=events.account_id
        ORDER BY events.created_at DESC LIMIT 50
        """
    )
    for item in open_events + recent_events:
        item["details"] = json.loads(item.pop("details_json"))
        item["connector_name"] = CONNECTORS.get(item["connector"], {}).get("name", item["connector"].replace("_", " ").title())
    assets = list_assets()
    protection = build_protection_map(accounts, assets, open_events)
    critical_open = sum(1 for item in open_events if item["severity"] == "critical")
    high_open = sum(1 for item in open_events if item["severity"] == "high")
    posture = "critical" if critical_open else "needs review" if high_open or open_events or protection["gaps"] else "healthy"
    any_auto_action = any(get_account_settings(account)["auto_action_enabled"] for account in accounts)
    return JSONResponse(
        {
            "accounts": accounts,
            "assets": assets,
            "protection": protection,
            "open_events": open_events,
            "recent_events": recent_events,
            "stats": {
                "accounts": len(accounts),
                "open_events": len(open_events),
                "protected_connectors": ["github"],
                "prepared_connectors": [item for item in CONNECTORS if item != "github"],
                "overall_security": posture,
                "security_score": protection["score"],
                "coverage": f"{protection['covered']}/{protection['total']}",
                "auto_action_enabled": any_auto_action,
            },
            "settings": get_settings(),
            "recovery": recovery_summary(),
            "connectors": connector_definitions(),
            "system_categories": [dict(id=key, **value) for key, value in SYSTEM_CATEGORIES.items()],
        }
    )


@app.get("/api/connectors")
async def connectors() -> JSONResponse:
    return JSONResponse({"connectors": connector_definitions()})


def clean_asset_payload(payload: dict[str, Any]) -> dict[str, Any]:
    category = str(payload.get("category") or "").strip()
    if category not in SYSTEM_CATEGORIES:
        raise HTTPException(400, "Choose a valid protection category.")
    provider = str(payload.get("provider") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not provider or not name:
        raise HTTPException(400, "Provider and system name are required.")
    criticality = str(payload.get("criticality") or "high").strip().casefold()
    if criticality not in {"low", "medium", "high", "critical"}:
        raise HTTPException(400, "Choose a valid criticality.")
    backup_status = str(payload.get("backup_status") or "unknown").strip().casefold()
    if backup_status not in {"independent", "provider_only", "missing", "unknown", "not_applicable"}:
        raise HTTPException(400, "Choose a valid backup status.")
    holders = payload.get("control_holders") or []
    if isinstance(holders, str):
        holders = re.split(r"\r?\n|,", holders)
    return {
        "category": category,
        "provider": provider,
        "name": name,
        "url": str(payload.get("url") or "").strip(),
        "criticality": criticality,
        "control_holders_json": json_dumps([str(item).strip() for item in holders if str(item).strip()]),
        "recovery_contact": str(payload.get("recovery_contact") or "").strip(),
        "recovery_method": str(payload.get("recovery_method") or "").strip(),
        "backup_status": backup_status,
        "notes": str(payload.get("notes") or "").strip(),
    }


@app.post("/api/assets")
async def add_asset(request: Request) -> JSONResponse:
    values = clean_asset_payload(await request.json())
    now = utc_now()
    asset_id = execute(
        """
        INSERT INTO protected_assets(
            category, provider, name, url, criticality, control_holders_json,
            recovery_contact, recovery_method, backup_status, notes, status,
            last_reviewed_at, created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'tracked', ?, ?, ?)
        """,
        (
            values["category"], values["provider"], values["name"], values["url"], values["criticality"],
            values["control_holders_json"], values["recovery_contact"], values["recovery_method"],
            values["backup_status"], values["notes"], now, now, now,
        ),
    )
    return JSONResponse({"ok": True, "asset": enrich_asset(row("SELECT * FROM protected_assets WHERE id=?", (asset_id,)))})


@app.post("/api/assets/{asset_id}")
async def update_asset(asset_id: int, request: Request) -> JSONResponse:
    if not row("SELECT id FROM protected_assets WHERE id=?", (asset_id,)):
        raise HTTPException(404, "Protected system not found")
    values = clean_asset_payload(await request.json())
    execute(
        """
        UPDATE protected_assets SET category=?, provider=?, name=?, url=?, criticality=?,
            control_holders_json=?, recovery_contact=?, recovery_method=?, backup_status=?,
            notes=?, updated_at=? WHERE id=?
        """,
        (
            values["category"], values["provider"], values["name"], values["url"], values["criticality"],
            values["control_holders_json"], values["recovery_contact"], values["recovery_method"],
            values["backup_status"], values["notes"], utc_now(), asset_id,
        ),
    )
    return JSONResponse({"ok": True, "asset": enrich_asset(row("SELECT * FROM protected_assets WHERE id=?", (asset_id,)))})


@app.post("/api/assets/{asset_id}/review")
async def review_asset(asset_id: int) -> JSONResponse:
    if not row("SELECT id FROM protected_assets WHERE id=?", (asset_id,)):
        raise HTTPException(404, "Protected system not found")
    execute("UPDATE protected_assets SET last_reviewed_at=?, updated_at=? WHERE id=?", (utc_now(), utc_now(), asset_id))
    return JSONResponse({"ok": True})


@app.post("/api/assets/{asset_id}/delete")
async def delete_asset(asset_id: int) -> JSONResponse:
    execute("DELETE FROM protected_assets WHERE id=?", (asset_id,))
    return JSONResponse({"ok": True})


@app.get("/oauth/{connector}/start")
async def oauth_start(connector: str, request: Request) -> RedirectResponse:
    connector = normalize_connector(connector)
    cfg = config()
    if connector not in CONNECTORS or connector == "github":
        raise HTTPException(404, "OAuth install is not available for this connector.")
    if not oauth_connector_ready(connector):
        raise HTTPException(400, f"Set the {CONNECTORS[connector]['name']} client ID in guard/.env first.")

    query = request.query_params
    metadata = {
        "shop_domain": clean_shopify_domain(query.get("shop_domain", "")) if query.get("shop_domain") else "",
        "workspace_hint": query.get("workspace_hint", ""),
        "domain": query.get("domain", ""),
        "base_id": airtable_base_id(query.get("base_id", "")) or query.get("base_id", ""),
        "subdomain": (query.get("subdomain", "") or "").replace(".zendesk.com", ""),
    }
    if connector == "airtable":
        metadata["code_verifier"] = secrets.token_urlsafe(64)
    state = remember_oauth_state(connector, metadata)
    redirect_uri = oauth_redirect_uri(connector)

    if connector == "shopify":
        shop_domain = clean_shopify_domain(query.get("shop_domain", ""))
        if not shop_domain:
            raise HTTPException(400, "Enter the Shopify shop domain before opening install.")
        params = {
            "client_id": cfg["shopify_client_id"],
            "scope": "read_locations",
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return RedirectResponse(f"https://{shop_domain}/admin/oauth/authorize?{urlencode(params)}")

    if connector == "slack":
        params = {
            "client_id": cfg["slack_client_id"],
            "scope": "team:read,users:read,users:read.email",
            "redirect_uri": redirect_uri,
            "state": state,
        }
        return RedirectResponse(f"https://slack.com/oauth/v2/authorize?{urlencode(params)}")

    if connector == "google_workspace":
        if not query.get("domain"):
            raise HTTPException(400, "Enter the Google Workspace domain before opening install.")
        params = {
            "client_id": cfg["google_workspace_client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "https://www.googleapis.com/auth/admin.directory.user.readonly",
            "access_type": "offline",
            "prompt": "consent",
            "state": state,
        }
        return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}")

    if connector == "airtable":
        if not metadata["base_id"]:
            raise HTTPException(400, "Enter the Airtable base URL or base ID before opening install.")
        params = {
            "client_id": cfg["airtable_client_id"],
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "schema.bases:read",
            "code_challenge": pkce_challenge(metadata["code_verifier"]),
            "code_challenge_method": "S256",
            "state": state,
        }
        return RedirectResponse(f"https://airtable.com/oauth2/v1/authorize?{urlencode(params)}")

    if connector == "zendesk":
        subdomain = (query.get("subdomain", "") or "").replace(".zendesk.com", "")
        if not subdomain:
            raise HTTPException(400, "Enter the Zendesk subdomain before opening install.")
        params = {
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "client_id": cfg["zendesk_client_id"],
            "scope": "read",
            "state": state,
        }
        return RedirectResponse(f"https://{subdomain}.zendesk.com/oauth/authorizations/new?{urlencode(params)}")

    raise HTTPException(404, "OAuth install is not available for this connector.")


@app.get("/oauth/{connector}/callback")
async def oauth_callback(connector: str, request: Request) -> HTMLResponse:
    connector = normalize_connector(connector)
    if connector not in CONNECTORS:
        raise HTTPException(404, "Unknown connector.")
    error = request.query_params.get("error")
    if error:
        raise HTTPException(400, f"{CONNECTORS[connector]['name']} authorization failed: {error}")
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        start_path = f"/oauth/{connector_path(connector)}/start"
        raise HTTPException(
            400,
            f"OAuth callback did not include code and state. Start the install from Retayn using {start_path}, not by opening this callback URL directly.",
        )
    metadata = consume_oauth_state(state, connector)

    if connector == "shopify":
        shop_domain = clean_shopify_domain(request.query_params.get("shop") or metadata.get("shop_domain", ""))
        token = await exchange_shopify_code(shop_domain, code)
        store_connection_token(
            "shopify",
            shop_domain,
            "",
            token["access_token"],
            scopes=token.get("scope"),
            metadata={"shop_domain": shop_domain},
        )
        return oauth_success_page("Shopify")

    if connector == "slack":
        token = await exchange_slack_code(code)
        team = token.get("team") or {}
        owner = team.get("id") or metadata.get("workspace_hint") or "slack"
        repo = team.get("name") or metadata.get("workspace_hint") or "Slack workspace"
        store_connection_token(
            "slack",
            owner,
            repo,
            token["access_token"],
            token_type=token.get("token_type"),
            scopes=token.get("scope"),
            metadata={"team": team, "authed_user": token.get("authed_user")},
        )
        return oauth_success_page("Slack")

    if connector == "google_workspace":
        domain = metadata.get("domain") or "google-workspace"
        token = await exchange_google_code(code)
        store_connection_token(
            "google_workspace",
            domain,
            "",
            token["access_token"],
            refresh_token=token.get("refresh_token"),
            token_type=token.get("token_type"),
            scopes=token.get("scope"),
            metadata={"domain": domain, "expires_in": token.get("expires_in")},
        )
        return oauth_success_page("Google Workspace")

    if connector == "airtable":
        base_id = metadata.get("base_id") or "airtable"
        code_verifier = metadata.get("code_verifier")
        if not code_verifier:
            raise HTTPException(400, "Airtable OAuth state did not include PKCE data. Start the install again from Retayn.")
        token = await exchange_airtable_code(code, code_verifier)
        store_connection_token(
            "airtable",
            "airtable",
            base_id,
            token["access_token"],
            refresh_token=token.get("refresh_token"),
            token_type=token.get("token_type"),
            scopes=token.get("scope"),
            metadata={"base_id": base_id, "expires_in": token.get("expires_in")},
        )
        return oauth_success_page("Airtable")

    if connector == "zendesk":
        subdomain = metadata.get("subdomain")
        if not subdomain:
            raise HTTPException(400, "Zendesk subdomain was missing. Start the install again from Retayn.")
        token = await exchange_zendesk_code(subdomain, code)
        store_connection_token(
            "zendesk",
            subdomain,
            "",
            token["access_token"],
            refresh_token=token.get("refresh_token"),
            token_type=token.get("token_type"),
            scopes=token.get("scope"),
            metadata={"subdomain": subdomain, "expires_in": token.get("expires_in")},
        )
        return oauth_success_page("Zendesk")

    raise HTTPException(404, "OAuth callback is not available for this connector.")


@app.post("/api/settings")
async def save_settings(request: Request) -> JSONResponse:
    payload = await request.json()
    return JSONResponse({"ok": True, "settings": update_settings(payload)})


@app.post("/api/accounts/start")
async def add_account(request: Request) -> JSONResponse:
    form = await request.form()
    connector = str(form.get("connector") or "github")
    cfg = config()
    if connector not in CONNECTORS:
        raise HTTPException(400, "That connector is not available yet.")

    owner = ""
    name = ""
    secret_settings: dict[str, Any] = {}
    if connector == "github":
        parsed = repo_name(str(form.get("repo") or ""))
        if not parsed:
            raise HTTPException(400, "Enter a repo as owner/name or https://github.com/owner/name.")
        owner, name = parsed
        gh = await github_client(owner, name)
        try:
            await gh.repo(owner, name)
        except HTTPException as exc:
            raise HTTPException(exc.status_code, github_error_message(exc, owner, name)) from exc
        finally:
            await gh.close()
    elif connector == "shopify":
        owner = clean_shopify_domain(str(form.get("shop_domain") or ""))
        name = "store"
        secret_settings = {}
        if not owner:
            raise HTTPException(400, "Enter the Shopify shop domain.")
        if not connection_token("shopify", owner, "") and not cfg["shopify_admin_token"]:
            raise HTTPException(400, "Install Retayn in this Shopify store first, then click Finish connection.")
    elif connector == "slack":
        secret_settings = {}
        owner = str(form.get("workspace_hint") or "slack").strip() or "slack"
        name = "workspace"
        if not connection_token("slack") and not cfg["slack_bot_token"]:
            raise HTTPException(400, "Install Retayn in Slack first, then click Finish connection.")
    elif connector == "google_workspace":
        owner = str(form.get("domain") or "").strip()
        name = "workspace"
        secret_settings = {}
        if not owner:
            raise HTTPException(400, "Enter the Workspace domain.")
        if not connection_token("google_workspace", owner, "") and not (cfg["google_workspace_admin_email"] and cfg["google_workspace_service_account_json_path"]):
            raise HTTPException(400, "Authorize Retayn in Google Workspace first, then click Finish connection.")
    elif connector == "airtable":
        owner = "airtable"
        name = airtable_base_id(str(form.get("base_id") or "")) or str(form.get("base_id") or "").strip()
        secret_settings = {}
        if not name:
            raise HTTPException(400, "Enter the Airtable base URL or the base ID that starts with app.")
        if not connection_token("airtable", "airtable", name) and not cfg["airtable_personal_access_token"]:
            raise HTTPException(400, "Authorize Retayn in Airtable first, then click Finish connection.")
    elif connector == "zendesk":
        owner = str(form.get("subdomain") or "").strip().replace(".zendesk.com", "")
        name = "support"
        secret_settings = {}
        if not owner:
            raise HTTPException(400, "Enter the Zendesk subdomain.")
        if not connection_token("zendesk", owner, "") and not (cfg["zendesk_email"] and cfg["zendesk_api_token"]):
            raise HTTPException(400, "Authorize Retayn in Zendesk first, then click Finish connection.")

    now = utc_now()
    account_id = execute(
        """
        INSERT INTO accounts(connector, owner, repo, status, created_at, updated_at, settings_json)
        VALUES(?, ?, ?, 'baselining', ?, ?, ?)
        ON CONFLICT(connector, owner, repo)
        DO UPDATE SET status='baselining', updated_at=excluded.updated_at, settings_json=excluded.settings_json
        """,
        (connector, owner, name, now, now, json_dumps(settings_defaults() | secret_settings)),
    )
    existing = row("SELECT id FROM accounts WHERE connector=? AND owner=? AND repo=?", (connector, owner, name))
    account_id = int(existing["id"]) if existing else account_id

    if connector == "github":
        await baseline_repo(account_id, owner, name)
    elif connector == "shopify":
        token = await active_connection_token("shopify", owner, "")
        await baseline_shopify(account_id, owner, token["access_token"] if token else cfg["shopify_admin_token"])
    elif connector == "slack":
        token = await active_connection_token("slack")
        owner, name = await baseline_slack(account_id, token["access_token"] if token else cfg["slack_bot_token"])
        execute("UPDATE accounts SET owner=?, repo=? WHERE id=?", (owner, name, account_id))
    elif connector == "google_workspace":
        token = await active_connection_token("google_workspace", owner, "")
        if token:
            await baseline_google_workspace_oauth(account_id, owner, token["access_token"])
        else:
            await baseline_google_workspace(account_id, owner, cfg["google_workspace_admin_email"], cfg["google_workspace_service_account_json_path"])
    elif connector == "airtable":
        token = await active_connection_token("airtable", "airtable", name)
        await baseline_airtable(account_id, name, token["access_token"] if token else cfg["airtable_personal_access_token"])
    elif connector == "zendesk":
        token = await active_connection_token("zendesk", owner, "")
        if token:
            await baseline_zendesk_oauth(account_id, owner, token["access_token"])
        else:
            await baseline_zendesk(account_id, owner, cfg["zendesk_email"], cfg["zendesk_api_token"])

    execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account_id))
    await start_monitor(account_id)
    account = enrich_account(row("SELECT * FROM accounts WHERE id=?", (account_id,)))
    return JSONResponse({"ok": True, "account_id": account_id, "repo": account["display_name"], "connector": connector})


@app.get("/api/accounts")
async def list_accounts() -> JSONResponse:
    accounts = rows("SELECT * FROM accounts ORDER BY created_at DESC")
    for account in accounts:
        enrich_account(account)
    return JSONResponse({"accounts": accounts})


def account_baseline(account_id: int) -> dict[str, Any]:
    collaborators = snapshot_get(account_id, "collaborators", {})
    hooks = snapshot_get(account_id, "hooks", {})
    deploy_keys = snapshot_get(account_id, "deploy_keys", {})
    users = snapshot_get(account_id, "users", {})
    workspace = snapshot_get(account_id, "workspace", {})
    shop = snapshot_get(account_id, "shop", {})
    base = snapshot_get(account_id, "base", {})
    tables = snapshot_get(account_id, "tables", [])
    account = snapshot_get(account_id, "account", {})
    access = snapshot_get(account_id, "access", [])
    last_scan = snapshot_get(account_id, "last_scan", {})
    return {
        "users": [item for item in collaborators.values()],
        "workspace_users": [item for item in users.values()],
        "webhooks": [item for item in hooks.values()],
        "write_deploy_keys": [
            item for item in deploy_keys.values() if not item.get("read_only")
        ],
        "workspace": workspace,
        "shop": shop,
        "base": base,
        "tables": tables,
        "account": account,
        "access": access,
        "last_scan": last_scan,
    }


@app.post("/api/accounts/{account_id}/refresh")
async def refresh_account(account_id: int) -> JSONResponse:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not account:
        raise HTTPException(404, "Connection not found")
    cfg = config()
    if account["connector"] == "github":
        await baseline_repo(account["id"], account["owner"], account["repo"])
    elif account["connector"] == "shopify":
        token = await active_connection_token("shopify", account["owner"], "")
        await baseline_shopify(account["id"], account["owner"], token["access_token"] if token else cfg["shopify_admin_token"])
    elif account["connector"] == "slack":
        token = await active_connection_token("slack", account["owner"], account["repo"]) or await active_connection_token("slack")
        await baseline_slack(account["id"], token["access_token"] if token else cfg["slack_bot_token"])
    elif account["connector"] == "google_workspace":
        token = await active_connection_token("google_workspace", account["owner"], "")
        if token:
            await baseline_google_workspace_oauth(account["id"], account["owner"], token["access_token"])
        else:
            await baseline_google_workspace(account["id"], account["owner"], cfg["google_workspace_admin_email"], cfg["google_workspace_service_account_json_path"])
    elif account["connector"] == "airtable":
        token = await active_connection_token("airtable", "airtable", account["repo"])
        await baseline_airtable(account["id"], account["repo"], token["access_token"] if token else cfg["airtable_personal_access_token"])
    elif account["connector"] == "zendesk":
        token = await active_connection_token("zendesk", account["owner"], "")
        if token:
            await baseline_zendesk_oauth(account["id"], account["owner"], token["access_token"])
        else:
            await baseline_zendesk(account["id"], account["owner"], cfg["zendesk_email"], cfg["zendesk_api_token"])
    if account["connector"] in CONNECTORS:
        execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account_id))
    return JSONResponse({"ok": True})


@app.post("/api/accounts/{account_id}/edit")
async def edit_account(account_id: int, repo: str = Form(...)) -> JSONResponse:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not account:
        raise HTTPException(404, "Connection not found")
    if account["connector"] != "github":
        raise HTTPException(400, "Editing this connector's identity is not supported yet. Delete and reconnect it.")
    parsed = repo_name(repo)
    if not parsed:
        raise HTTPException(400, "Enter a repo as owner/name or https://github.com/owner/name.")
    owner, name = parsed
    if account["connector"] != "github":
        raise HTTPException(400, "Editing is not supported for this connector yet.")
    execute(
        "UPDATE accounts SET owner=?, repo=?, status='baselining', updated_at=? WHERE id=?",
        (owner, name, utc_now(), account_id),
    )
    await baseline_repo(account_id, owner, name)
    execute("UPDATE accounts SET status='connected', updated_at=? WHERE id=?", (utc_now(), account_id))
    await start_monitor(account_id)
    return JSONResponse({"ok": True, "repo": f"{owner}/{name}"})


@app.get("/api/accounts/{account_id}")
async def get_account(account_id: int) -> JSONResponse:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not account:
        raise HTTPException(404, "Connection not found")
    return JSONResponse({"account": enrich_account(account)})


@app.post("/api/accounts/{account_id}/settings")
async def save_account_settings(account_id: int, request: Request) -> JSONResponse:
    payload = await request.json()
    return JSONResponse({"ok": True, "settings": update_account_settings(account_id, payload)})


@app.post("/api/accounts/{account_id}/delete")
async def delete_account(account_id: int) -> JSONResponse:
    account = row("SELECT * FROM accounts WHERE id=?", (account_id,))
    if not account:
        raise HTTPException(404, "Connection not found")
    manual_disconnect = disconnect_instructions(account)
    task = running_tasks.pop((current_user_id(), account_id), None)
    if task:
        task.cancel()
    with db() as conn:
        conn.execute("DELETE FROM accepted_findings WHERE account_id=?", (account_id,))
        conn.execute("DELETE FROM snapshots WHERE account_id=?", (account_id,))
        conn.execute("DELETE FROM events WHERE account_id=?", (account_id,))
        conn.execute(
            "DELETE FROM connection_tokens WHERE connector=? AND owner=? AND (repo=? OR repo='')",
            (account["connector"], account["owner"], account["repo"]),
        )
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    return JSONResponse({"ok": True, "manual_disconnect": manual_disconnect})


@app.post("/api/events/{event_id}/me")
async def approve_event(event_id: int) -> JSONResponse:
    event = row("SELECT * FROM events WHERE id=?", (event_id,))
    if not event:
        raise HTTPException(404, "Event not found")
    details = json.loads(event["details_json"])
    account = row("SELECT * FROM accounts WHERE id=?", (event["account_id"],))
    remember_accepted_finding(event["account_id"], event["event_type"], details)
    if account:
        apply_event_approval_to_trust(account, event["event_type"], details)
        if details.get("supported_action"):
            await baseline_repo(account["id"], account["owner"], account["repo"])
    execute(
        "UPDATE events SET status='trusted', action_taken=?, resolved_at=? WHERE id=?",
        ("approved and baseline updated" if details.get("supported_action") else "approved and suppressed", utc_now(), event_id),
    )
    return JSONResponse({"ok": True})


@app.post("/api/events/{event_id}/not-me")
async def reject_event(event_id: int) -> JSONResponse:
    event = row("SELECT * FROM events WHERE id=?", (event_id,))
    if not event:
        raise HTTPException(404, "Event not found")
    details = json.loads(event["details_json"])
    if not details.get("supported_action"):
        raise HTTPException(400, "This app does not support an action for this notification.")
    account = row("SELECT * FROM accounts WHERE id=?", (event["account_id"],))
    if not account:
        raise HTTPException(404, "Account not found")

    action = await apply_github_action(event, account)

    execute(
        "UPDATE events SET status='blocked', action_taken=?, resolved_at=? WHERE id=?",
        (action, utc_now(), event_id),
    )
    return JSONResponse({"ok": True, "action": action})


@app.post("/api/events/{event_id}/actions/{action_id}")
async def run_event_action(event_id: int, action_id: str) -> JSONResponse:
    event = row("SELECT * FROM events WHERE id=?", (event_id,))
    if not event:
        raise HTTPException(404, "Event not found")
    details = json.loads(event["details_json"])
    supported_actions = {item.get("id") for item in details.get("supported_actions", [])}
    if action_id != details.get("supported_action") and action_id not in supported_actions:
        raise HTTPException(400, "This app does not support that action for this notification.")
    account = row("SELECT * FROM accounts WHERE id=?", (event["account_id"],))
    if not account:
        raise HTTPException(404, "Account not found")

    action = await apply_github_action(event, account, action_id)
    execute(
        "UPDATE events SET status='blocked', action_taken=?, resolved_at=? WHERE id=?",
        (action, utc_now(), event_id),
    )
    return JSONResponse({"ok": True, "action": action})


@app.post("/api/events/{event_id}/ignore")
async def ignore_event(event_id: int) -> JSONResponse:
    event = row("SELECT * FROM events WHERE id=?", (event_id,))
    if event:
        remember_accepted_finding(event["account_id"], event["event_type"], json.loads(event["details_json"]))
    execute(
        "UPDATE events SET status='ignored', action_taken='ignored', resolved_at=? WHERE id=?",
        (utc_now(), event_id),
    )
    return JSONResponse({"ok": True})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("retayn_app:app", host="127.0.0.1", port=8787, reload=False)
