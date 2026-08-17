from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import id_token

from auth_context import DATA_DIR


router = APIRouter()
AUTH_DB_PATH = DATA_DIR / "auth.db"
COOKIE_NAME = "retayn_session"
SESSION_SECONDS = 60 * 60 * 24 * max(1, int(os.getenv("RETAYN_SESSION_DAYS", "180")))
OAUTH_STATE_SECONDS = 10 * 60
SIGNED_COOKIE_VERSION = "v1"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(AUTH_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_auth_db() -> None:
    with _db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                name TEXT,
                picture TEXT,
                webhook_token TEXT UNIQUE,
                created_at TEXT NOT NULL,
                last_login_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                csrf_token TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS oauth_states (
                state_hash TEXT PRIMARY KEY,
                nonce TEXT NOT NULL,
                code_verifier TEXT NOT NULL,
                return_to TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_id ON sessions(user_id);
            """
        )
        columns = {item["name"] for item in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "webhook_token" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN webhook_token TEXT")
        for item in conn.execute("SELECT id FROM users WHERE webhook_token IS NULL OR webhook_token='' ").fetchall():
            conn.execute("UPDATE users SET webhook_token=? WHERE id=?", (secrets.token_urlsafe(32), item["id"]))
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_webhook_token ON users(webhook_token)")
        now = int(time.time())
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        conn.execute("DELETE FROM oauth_states WHERE expires_at < ?", (now,))


def google_config() -> dict[str, str]:
    return {
        "client_id": os.getenv("GOOGLE_AUTH_CLIENT_ID", "").strip(),
        "client_secret": os.getenv("GOOGLE_AUTH_CLIENT_SECRET", "").strip(),
        "base_url": os.getenv("RETAYN_PUBLIC_BASE_URL", "http://127.0.0.1:8787").strip().rstrip("/"),
        "allowed_domains": os.getenv("RETAYN_ALLOWED_GOOGLE_DOMAINS", "").strip(),
    }


def _token_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _session_signing_key() -> bytes:
    secret = (
        os.getenv("RETAYN_SESSION_SECRET", "").strip()
        or os.getenv("RETAYN_TOKEN_ENCRYPTION_KEY", "").strip()
        or os.getenv("GOOGLE_AUTH_CLIENT_SECRET", "").strip()
    )
    if not secret:
        secret = "retayn-local-development-session-secret"
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _sign_session_payload(payload: dict) -> str:
    body = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(_session_signing_key(), body.encode("ascii"), hashlib.sha256).digest()
    return f"{SIGNED_COOKIE_VERSION}.{body}.{_b64url(signature)}"


def _read_signed_session(raw_token: str, now: int) -> dict | None:
    parts = raw_token.split(".")
    if len(parts) != 3 or parts[0] != SIGNED_COOKIE_VERSION:
        return None
    expected = _b64url(hmac.new(_session_signing_key(), parts[1].encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(expected, parts[2]):
        return None
    try:
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8"))
    except Exception:
        return None
    if int(payload.get("expires_at") or 0) < now:
        return None
    user_id = str(payload.get("id") or "")
    email = str(payload.get("email") or "")
    csrf = str(payload.get("csrf_token") or "")
    if not user_id or not email or not csrf:
        return None
    return {
        "csrf_token": csrf,
        "expires_at": int(payload["expires_at"]),
        "id": user_id,
        "email": email,
        "name": str(payload.get("name") or ""),
        "picture": str(payload.get("picture") or ""),
    }


def _safe_return_to(value: str | None) -> str:
    if not value or not value.startswith("/") or value.startswith("//"):
        return "/"
    parsed = urlparse(value)
    return value if not parsed.scheme and not parsed.netloc else "/"


def _cookie_secure() -> bool:
    return google_config()["base_url"].startswith("https://")


def current_session(request: Request) -> dict | None:
    raw_token = request.cookies.get(COOKIE_NAME)
    if not raw_token:
        return None
    now = int(time.time())
    signed = _read_signed_session(raw_token, now)
    if signed:
        return signed
    with _db() as conn:
        item = conn.execute(
            """
            SELECT sessions.csrf_token, sessions.expires_at,
                   users.id, users.email, users.name, users.picture
            FROM sessions JOIN users ON users.id=sessions.user_id
            WHERE sessions.token_hash=? AND sessions.expires_at>=?
            """,
            (_token_hash(raw_token), now),
        ).fetchone()
    return dict(item) if item else None


def user_for_webhook_token(token: str) -> dict | None:
    if len(token) < 32:
        return None
    with _db() as conn:
        item = conn.execute("SELECT id,email,name FROM users WHERE webhook_token=?", (token,)).fetchone()
    return dict(item) if item else None


def _signin_html(configured: bool, error: str = "", return_to: str = "/") -> str:
    disabled = "" if configured else " disabled aria-disabled=\"true\""
    action = f"/auth/google/start?{urlencode({'return_to': _safe_return_to(return_to)})}" if configured else "#"
    note = (
        "Use your Google account to create a free Retayn account or sign back in."
        if configured
        else "Google sign-in needs to be configured by the site owner before accounts can be created."
    )
    error_html = f'<p class="error">{html.escape(error)}</p>' if error else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#07131d"><title>Sign in | Retayn</title>
<link rel="icon" href="/static/retaynlogologo.png"><style>
*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:#07131d;color:#edf8fb;font-family:Inter,ui-sans-serif,system-ui,sans-serif}}main{{width:min(440px,100%);padding:38px;border:1px solid #27404c;border-radius:12px;background:#0d1e28;box-shadow:0 28px 80px #02070a80}}.brand{{display:flex;align-items:center;gap:12px;color:#fff;text-decoration:none;font-size:28px;font-weight:800}}.brand img{{width:38px;height:38px;object-fit:contain}}h1{{margin:40px 0 10px;font-size:32px;line-height:1.08}}p{{color:#abc0ca;line-height:1.6}}.google{{width:100%;min-height:52px;margin-top:24px;display:flex;align-items:center;justify-content:center;gap:12px;border:1px solid #cad3d8;border-radius:7px;background:#fff;color:#17262e;font-size:15px;font-weight:800;text-decoration:none}}.google span{{font-size:20px;color:#4285f4}}.google[disabled]{{pointer-events:none;opacity:.55}}.fine{{margin:18px 0 0;font-size:12px;text-align:center}}.error{{padding:10px 12px;border-radius:6px;background:#56222b;color:#ffdce2;font-size:13px}}</style></head>
<body><main><a class="brand" href="/"><img src="/static/retaynlogologo.png" alt="">retayn</a>
<h1>Protect what you built.</h1><p>{html.escape(note)}</p>{error_html}
<a class="google" href="{action}"{disabled}><span>G</span> Continue with Google</a>
<p class="fine">No payment required. Retayn uses your email and profile name only to identify your account.</p></main></body></html>"""


@router.get("/auth/signin", response_class=HTMLResponse)
async def signin(request: Request) -> HTMLResponse:
    if current_session(request):
        return RedirectResponse(_safe_return_to(request.query_params.get("return_to")), status_code=303)
    cfg = google_config()
    return HTMLResponse(_signin_html(bool(cfg["client_id"] and cfg["client_secret"]), request.query_params.get("error", ""), request.query_params.get("return_to", "/")))


@router.get("/auth/google/start")
async def google_start(request: Request) -> RedirectResponse:
    cfg = google_config()
    if not cfg["client_id"] or not cfg["client_secret"]:
        return RedirectResponse("/auth/signin?error=Google+sign-in+is+not+configured", status_code=303)
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    now = int(time.time())
    with _db() as conn:
        conn.execute(
            "INSERT INTO oauth_states VALUES(?,?,?,?,?,?)",
            (_token_hash(state), nonce, verifier, _safe_return_to(request.query_params.get("return_to")), now, now + OAUTH_STATE_SECONDS),
        )
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": f'{cfg["base_url"]}/auth/google/callback',
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "prompt": "select_account",
    }
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/v2/auth?{urlencode(params)}", status_code=302)


@router.get("/auth/google/callback")
async def google_callback(request: Request) -> RedirectResponse:
    cfg = google_config()
    if request.query_params.get("error"):
        return RedirectResponse("/auth/signin?error=Google+sign-in+was+cancelled", status_code=303)
    state = request.query_params.get("state", "")
    code = request.query_params.get("code", "")
    now = int(time.time())
    with _db() as conn:
        saved = conn.execute(
            "SELECT * FROM oauth_states WHERE state_hash=? AND expires_at>=?",
            (_token_hash(state), now),
        ).fetchone()
        conn.execute("DELETE FROM oauth_states WHERE state_hash=?", (_token_hash(state),))
    if not saved or not code:
        return RedirectResponse("/auth/signin?error=That+sign-in+link+expired.+Please+try+again", status_code=303)
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": cfg["client_id"], "client_secret": cfg["client_secret"],
                "code": code, "code_verifier": saved["code_verifier"],
                "grant_type": "authorization_code", "redirect_uri": f'{cfg["base_url"]}/auth/google/callback',
            },
        )
    if response.status_code != 200:
        return RedirectResponse("/auth/signin?error=Google+could+not+complete+sign-in", status_code=303)
    token_payload = response.json()
    try:
        claims = id_token.verify_oauth2_token(token_payload["id_token"], GoogleAuthRequest(), cfg["client_id"])
    except Exception as exc:
        raise HTTPException(401, "Google identity verification failed.") from exc
    if not hmac.compare_digest(str(claims.get("nonce", "")), str(saved["nonce"])):
        raise HTTPException(401, "Google sign-in nonce validation failed.")
    if not claims.get("email_verified") or not claims.get("sub") or not claims.get("email"):
        raise HTTPException(401, "A verified Google email is required.")
    email = str(claims["email"]).casefold()
    allowed = {item.strip().casefold() for item in cfg["allowed_domains"].split(",") if item.strip()}
    if allowed and email.rsplit("@", 1)[-1] not in allowed:
        return RedirectResponse("/auth/signin?error=This+Google+account+is+not+allowed", status_code=303)
    user_id = str(claims["sub"])
    now_iso = utc_now()
    raw_session = secrets.token_urlsafe(48)
    csrf = secrets.token_urlsafe(32)
    expires_at = now + SESSION_SECONDS
    with _db() as conn:
        conn.execute(
            """INSERT INTO users(id,email,name,picture,webhook_token,created_at,last_login_at) VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET email=excluded.email,name=excluded.name,picture=excluded.picture,last_login_at=excluded.last_login_at""",
            (user_id, email, str(claims.get("name", ""))[:200], str(claims.get("picture", ""))[:1000], secrets.token_urlsafe(32), now_iso, now_iso),
        )
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        conn.execute(
            "INSERT INTO sessions VALUES(?,?,?,?,?)",
            (_token_hash(raw_session), user_id, csrf, now, expires_at),
        )
    destination = _safe_return_to(saved["return_to"])
    result = RedirectResponse(destination, status_code=303)
    signed_session = _sign_session_payload(
        {
            "id": user_id,
            "email": email,
            "name": str(claims.get("name", ""))[:200],
            "picture": str(claims.get("picture", ""))[:1000],
            "csrf_token": csrf,
            "created_at": now,
            "expires_at": expires_at,
        }
    )
    result.set_cookie(COOKIE_NAME, signed_session, max_age=SESSION_SECONDS, httponly=True, secure=_cookie_secure(), samesite="lax", path="/")
    return result


@router.post("/auth/signout")
async def signout(request: Request) -> RedirectResponse:
    raw_token = request.cookies.get(COOKIE_NAME)
    if raw_token:
        with _db() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(raw_token),))
    response = RedirectResponse("/auth/signin", status_code=303)
    response.delete_cookie(COOKIE_NAME, path="/")
    return response
