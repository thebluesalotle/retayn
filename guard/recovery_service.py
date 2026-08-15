from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from auth_context import user_db_path, user_upload_dir

try:
    from winotify import Notification
except ImportError:  # pragma: no cover
    Notification = None


BASE_DIR = Path(__file__).resolve().parent
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
router = APIRouter()

RECOVERY_STATUSES = {
    "draft",
    "message_review",
    "outreach_active",
    "needs_owner",
    "action_required",
    "recovered",
    "closed",
}
CONTACT_CHANNELS = {"email", "telegram", "whatsapp", "support_portal", "phone", "other"}
RESPONSE_CLASSIFICATIONS = {
    "proof_request",
    "account_info_request",
    "case_fact_request",
    "generic",
    "access_offer",
    "files_shared",
    "rejection",
    "other",
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
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def recovery_config() -> dict[str, Any]:
    load_env_file(BASE_DIR / ".env")
    return {
        "ai_api_key": os.getenv("AI_API_KEY", "").strip(),
        "ai_base_url": os.getenv("AI_BASE_URL", "https://api.deepseek.com").strip().rstrip("/"),
        "ai_model": os.getenv("AI_MODEL", "deepseek-chat").strip(),
        "smtp_host": os.getenv("RECOVERY_SMTP_HOST", "").strip(),
        "smtp_port": int(os.getenv("RECOVERY_SMTP_PORT", "587") or 587),
        "smtp_username": os.getenv("RECOVERY_SMTP_USERNAME", "").strip(),
        "smtp_password": os.getenv("RECOVERY_SMTP_PASSWORD", "").strip(),
        "smtp_from": os.getenv("RECOVERY_SMTP_FROM_EMAIL", "").strip(),
        "smtp_tls": os.getenv("RECOVERY_SMTP_USE_TLS", "true").strip().casefold() in {"1", "true", "yes", "on"},
        "telegram_bot_token": os.getenv("RECOVERY_TELEGRAM_BOT_TOKEN", "").strip(),
        "telegram_webhook_secret": os.getenv("RECOVERY_TELEGRAM_WEBHOOK_SECRET", "").strip(),
        "telegram_mtproto_api_id": os.getenv("RECOVERY_TELEGRAM_MTPROTO_API_ID", "").strip(),
        "telegram_mtproto_api_hash": os.getenv("RECOVERY_TELEGRAM_MTPROTO_API_HASH", "").strip(),
        "telegram_mtproto_session": os.getenv("RECOVERY_TELEGRAM_MTPROTO_SESSION", "").strip(),
        "telegram_mtproto_session_path": os.getenv("RECOVERY_TELEGRAM_MTPROTO_SESSION_PATH", "").strip(),
        "whatsapp_token": os.getenv("RECOVERY_WHATSAPP_ACCESS_TOKEN", "").strip(),
        "whatsapp_phone_id": os.getenv("RECOVERY_WHATSAPP_PHONE_NUMBER_ID", "").strip(),
        "whatsapp_verify_token": os.getenv("RECOVERY_WHATSAPP_VERIFY_TOKEN", "").strip(),
        "whatsapp_app_secret": os.getenv("RECOVERY_WHATSAPP_APP_SECRET", "").strip(),
        "whatsapp_api_version": os.getenv("RECOVERY_WHATSAPP_API_VERSION", "v23.0").strip(),
        "whatsapp_template": os.getenv("RECOVERY_WHATSAPP_TEMPLATE_NAME", "").strip(),
        "whatsapp_template_language": os.getenv("RECOVERY_WHATSAPP_TEMPLATE_LANGUAGE", "en_US").strip(),
    }


def db():
    import sqlite3

    conn = sqlite3.connect(user_db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(item) for item in conn.execute(query, params).fetchall()]


def row(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    with db() as conn:
        item = conn.execute(query, params).fetchone()
        return dict(item) if item else None


def execute(query: str, params: tuple[Any, ...] = ()) -> int:
    with db() as conn:
        cursor = conn.execute(query, params)
        return int(cursor.lastrowid)


def init_recovery_db() -> None:
    user_upload_dir()
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS recovery_cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                owner_email TEXT,
                business_name TEXT,
                asset_type TEXT NOT NULL,
                platform_name TEXT NOT NULL,
                account_identifier TEXT,
                recovery_goal TEXT NOT NULL,
                lockout_story TEXT NOT NULL,
                lockout_date TEXT,
                ownership_proof TEXT,
                additional_context TEXT,
                urgency TEXT NOT NULL DEFAULT 'normal',
                status TEXT NOT NULL DEFAULT 'draft',
                draft_message TEXT,
                approved_message TEXT,
                cancellation_reason TEXT,
                auto_reply_generic INTEGER NOT NULL DEFAULT 1,
                share_evidence_initially INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS recovery_contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                role TEXT,
                organization TEXT,
                channel TEXT NOT NULL,
                address TEXT NOT NULL,
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'queued',
                external_thread_id TEXT,
                last_contacted_at TEXT,
                last_response_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES recovery_cases(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS recovery_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                contact_id INTEGER NOT NULL,
                direction TEXT NOT NULL,
                sender_type TEXT NOT NULL,
                body TEXT NOT NULL,
                classification TEXT,
                status TEXT NOT NULL,
                external_id TEXT,
                delivery_note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES recovery_cases(id) ON DELETE CASCADE,
                FOREIGN KEY(contact_id) REFERENCES recovery_contacts(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS recovery_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                contact_id INTEGER,
                message_id INTEGER,
                source TEXT NOT NULL,
                label TEXT,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                content_type TEXT,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES recovery_cases(id) ON DELETE CASCADE,
                FOREIGN KEY(contact_id) REFERENCES recovery_contacts(id) ON DELETE SET NULL,
                FOREIGN KEY(message_id) REFERENCES recovery_messages(id) ON DELETE SET NULL
            );

            CREATE INDEX IF NOT EXISTS recovery_contacts_case_idx ON recovery_contacts(case_id);
            CREATE INDEX IF NOT EXISTS recovery_messages_contact_idx ON recovery_messages(contact_id, created_at);
            CREATE INDEX IF NOT EXISTS recovery_files_case_idx ON recovery_files(case_id);
            """
        )
        existing_columns = {item["name"] for item in conn.execute("PRAGMA table_info(recovery_cases)").fetchall()}
        if "cancellation_reason" not in existing_columns:
            conn.execute("ALTER TABLE recovery_cases ADD COLUMN cancellation_reason TEXT")


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True)


def clean_text(value: Any, limit: int = 10000) -> str:
    return str(value or "").strip()[:limit]


def bool_value(value: Any) -> bool:
    return str(value or "").strip().casefold() in {"1", "true", "yes", "on"}


def normalize_address(channel: str, value: str) -> str:
    value = clean_text(value, 500)
    if channel == "email":
        return value.casefold()
    if channel == "telegram":
        return telegram_target(value)
    if channel == "whatsapp":
        return re.sub(r"\D", "", value)
    return value


def recovery_summary() -> dict[str, Any]:
    counts = row(
        """
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status IN ('outreach_active', 'needs_owner', 'action_required') THEN 1 ELSE 0 END) AS active,
          SUM(CASE WHEN status='needs_owner' THEN 1 ELSE 0 END) AS needs_owner,
          SUM(CASE WHEN status='recovered' THEN 1 ELSE 0 END) AS recovered
        FROM recovery_cases
        """
    ) or {}
    return {key: int(counts.get(key) or 0) for key in ("total", "active", "needs_owner", "recovered")}


def list_recovery_cases() -> list[dict[str, Any]]:
    cleanup_premature_telegram_sync()
    output = rows(
        """
        SELECT recovery_cases.*,
          (SELECT COUNT(*) FROM recovery_contacts WHERE case_id=recovery_cases.id) AS contact_count,
          (SELECT COUNT(*) FROM recovery_files WHERE case_id=recovery_cases.id) AS file_count,
          (SELECT COUNT(*) FROM recovery_contacts WHERE case_id=recovery_cases.id AND status IN ('responded','needs_info','success')) AS response_count
        FROM recovery_cases
        ORDER BY updated_at DESC
        """
    )
    for item in output:
        item["auto_reply_generic"] = bool(item["auto_reply_generic"])
        item["share_evidence_initially"] = bool(item["share_evidence_initially"])
    return output


def get_recovery_case(case_id: int) -> dict[str, Any]:
    cleanup_premature_telegram_sync(case_id)
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    case["auto_reply_generic"] = bool(case["auto_reply_generic"])
    case["share_evidence_initially"] = bool(case["share_evidence_initially"])
    case["contacts"] = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at", (case_id,))
    case["files"] = rows("SELECT * FROM recovery_files WHERE case_id=? ORDER BY created_at DESC", (case_id,))
    messages = rows("SELECT * FROM recovery_messages WHERE case_id=? ORDER BY created_at", (case_id,))
    files_by_message: dict[int, list[dict[str, Any]]] = {}
    for item in case["files"]:
        if item.get("message_id"):
            files_by_message.setdefault(int(item["message_id"]), []).append(item)
    for message in messages:
        message["files"] = files_by_message.get(int(message["id"]), [])
    messages_by_contact: dict[int, list[dict[str, Any]]] = {}
    for message in messages:
        messages_by_contact.setdefault(int(message["contact_id"]), []).append(message)
    for contact in case["contacts"]:
        contact["messages"] = messages_by_contact.get(int(contact["id"]), [])
    return case


def notify_owner(title: str, message: str) -> None:
    if Notification is None:
        return
    try:
        Notification(app_id="Retayn Guard", title=title, msg=message[:220], duration="long").show()
    except Exception:
        logging.exception("Could not send recovery notification")


def create_recovery_event(case_id: int, event_type: str, severity: str, title: str, summary: str, details: dict[str, Any]) -> int:
    event_id = execute(
        """
        INSERT INTO events(account_id, connector, event_type, severity, status, title, summary, details_json, action_taken, created_at, resolved_at)
        VALUES(NULL, 'recovery', ?, ?, 'open', ?, ?, ?, NULL, ?, NULL)
        """,
        (event_type, severity, title, summary, json_dumps({"case_id": case_id, **details}), utc_now()),
    )
    notify_owner(title, summary)
    return event_id


def case_fact_record(case: dict[str, Any]) -> dict[str, Any]:
    evidence = rows(
        "SELECT label, original_name, source FROM recovery_files WHERE case_id=? AND source='owner' ORDER BY created_at",
        (case["id"],),
    )
    return {
        "owner_name": case.get("owner_name") or "",
        "owner_email": case.get("owner_email") or "",
        "business_name": case.get("business_name") or "",
        "asset_type": case.get("asset_type") or "",
        "platform_name": case.get("platform_name") or "",
        "account_identifier": case.get("account_identifier") or "",
        "recovery_goal": case.get("recovery_goal") or "",
        "lockout_story": case.get("lockout_story") or "",
        "lockout_date": case.get("lockout_date") or "",
        "ownership_proof": case.get("ownership_proof") or "",
        "additional_context": case.get("additional_context") or "",
        "evidence_files": [item.get("label") or item.get("original_name") for item in evidence],
    }


def remove_emoji_and_emdash(value: str) -> str:
    value = value.replace("\u2014", "-").replace("\u2013", "-")
    emoji_ranges = re.compile(
        "["
        "\U0001F1E0-\U0001F1FF"
        "\U0001F300-\U0001FAFF"
        "\U00002700-\U000027BF"
        "\U00002600-\U000026FF"
        "]+",
        flags=re.UNICODE,
    )
    return emoji_ranges.sub("", value).strip()


async def call_ai_json(system_prompt: str, user_payload: dict[str, Any], max_tokens: int = 1000) -> dict[str, Any] | None:
    cfg = recovery_config()
    if not cfg["ai_api_key"]:
        return None
    payload = {
        "model": cfg["ai_model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json_dumps(user_payload)},
        ],
        "response_format": {"type": "json_object"},
        "max_tokens": max_tokens,
        "temperature": 0.2,
    }
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            response = await client.post(
                f"{cfg['ai_base_url']}/chat/completions",
                headers={"Authorization": f"Bearer {cfg['ai_api_key']}", "Content-Type": "application/json"},
                json=payload,
            )
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
        result = parse_ai_json(content)
        return result if isinstance(result, dict) else None
    except Exception:
        logging.exception("Recovery AI request failed")
        return None


def parse_ai_json(content: str) -> dict[str, Any] | None:
    text = clean_text(content, 50000)
    if not text:
        return None
    candidates = [text]
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.IGNORECASE | re.DOTALL)
    if fenced:
        candidates.insert(0, fenced.group(1))
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        candidates.append(text[start : end + 1])
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def sentence(value: str) -> str:
    text = clean_text(value, 5000)
    if not text:
        return ""
    return text if text.endswith((".", "!", "?")) else f"{text}."


def natural_lockout_story(value: str) -> str:
    text = clean_text(value, 5000)
    lowered = text.casefold()
    if lowered in {"i got hacked", "got hacked", "hacked"}:
        return "I believe the account was compromised and I no longer have access"
    if lowered in {"forgot password", "i forgot password", "i forgot my password"}:
        return "I forgot my password and got locked out of the account"
    return text


def fallback_recovery_draft(case: dict[str, Any], contact: dict[str, Any] | None = None) -> str:
    name = clean_text((contact or {}).get("name")) or "Support team"
    role = clean_text((contact or {}).get("role")).casefold()
    channel = clean_text((contact or {}).get("channel")).casefold()
    owner = clean_text(case.get("owner_name")) or "the account owner"
    business = clean_text(case.get("business_name"))
    platform = clean_text(case.get("platform_name"))
    asset = clean_text(case.get("asset_type"))
    identifier = clean_text(case.get("account_identifier"))
    parts = [f"Hello {name},", ""]
    identity = f"I am {owner}"
    if business:
        identity += f", the owner or authorized representative of {business}"
    target = f"our {asset} on {platform}" if platform else f"our {asset}"
    if identifier:
        target += f", identified as {identifier}"
    developer_contact = any(term in role for term in ("developer", "engineer", "agency", "contractor", "freelancer", "admin"))
    lockout = natural_lockout_story(case.get("lockout_story"))
    goal = clean_text(case.get("recovery_goal"))
    proof = clean_text(case.get("ownership_proof"))
    if developer_contact:
        parts.append(f"{sentence(identity)} I am contacting you because you may still have access to {target}.")
    else:
        parts.append(f"{sentence(identity)} I am requesting help recovering access to {target}.")
    if lockout:
        parts.extend(["", sentence(lockout[0].upper() + lockout[1:] if len(lockout) > 1 else lockout)])
    if goal:
        plain_goal = goal
        if developer_contact and goal.casefold() in {"everything", "all", "all of it"}:
            plain_goal = "send me a copy of the repository files and help restore my owner or admin access"
        if developer_contact:
            parts.extend(["", f"Please {plain_goal.rstrip('.')}."])
        else:
            parts.extend(["", f"I need help to {plain_goal.rstrip('.')}."])
    if proof and not re.search(r"\b(no proof|dont have any proof|don't have any proof|do not have proof|none)\b", proof, flags=re.IGNORECASE):
        parts.extend(["", f"I can share ownership context if needed: {proof}"])
    if developer_contact:
        parts.extend(
            [
                "",
                "Please reply with what you can hand over, or tell me the exact step you need from me so we can get access restored.",
            ]
        )
    elif channel in {"support_portal", "email"}:
        parts.extend(["", "Please let me know the verified steps and any additional evidence required to restore access."])
    else:
        parts.extend(["", "Please let me know the next step to restore access."])
    parts.extend(["", f"Regards,", owner])
    if clean_text(case.get("owner_email")):
        parts.append(clean_text(case["owner_email"]))
    return remove_emoji_and_emdash("\n".join(parts))


async def verify_fact_locked_message(message: str, facts: dict[str, Any]) -> bool:
    result = await call_ai_json(
        "You are a factual claims auditor. Compare the proposed recovery message with the supplied record. "
        "Do not treat greetings, requests, or generic process language as factual claims. Return JSON exactly as "
        "{\"supported\": true, \"unsupported_claims\": []}. Set supported to false when the message states any "
        "name, date, event, ownership fact, amount, identifier, relationship, or evidence that is not in the record.",
        {"record": facts, "proposed_message": message},
        max_tokens=500,
    )
    return bool(result and result.get("supported") is True and not result.get("unsupported_claims"))


def enforce_contact_greeting(message: str, contact: dict[str, Any] | None) -> str:
    name = clean_text((contact or {}).get("name"), 120)
    if not name:
        return message
    lines = message.splitlines()
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return f"Hello {name},"
    first = lines[0].strip()
    if re.match(r"^(hello|hi|dear)\b", first, flags=re.IGNORECASE):
        lines[0] = f"Hello {name},"
    else:
        lines.insert(0, f"Hello {name},")
    return remove_emoji_and_emdash("\n".join(lines))


def meaningful_recovery_message(message: str) -> bool:
    lines = [line.strip() for line in clean_text(message, 12000).splitlines() if line.strip()]
    body = " ".join(line for line in lines if not re.match(r"^(hello|hi|dear)\b", line, flags=re.IGNORECASE))
    return len(body) >= 80 and len(body.split()) >= 16


def heuristic_outbound_message_review(message: str) -> dict[str, Any]:
    text = message.casefold()
    blocked_terms = (
        "spam",
        "troll",
        "prank",
        "harass",
        "threaten",
        "blackmail",
        "extort",
        "ddos",
        "malware",
        "virus",
        "keylogger",
        "stealer",
        "phishing",
        "credential harvest",
        "crypto giveaway",
        "limited time offer",
        "buy now",
    )
    suspicious_links = re.findall(r"https?://\\S+", message)
    if any(term in text for term in blocked_terms):
        return {
            "decision": "block",
            "owner_message": "This message looks like spam, harassment, phishing, malware, or abusive outreach. Retayn did not save or send it.",
        }
    if len(suspicious_links) > 3:
        return {
            "decision": "block",
            "owner_message": "This message contains too many links for a recovery request. Retayn did not save or send it.",
        }
    return {"decision": "allow", "owner_message": ""}


async def review_outbound_message_safety(message: str, case: dict[str, Any] | None = None, contact: dict[str, Any] | None = None) -> dict[str, Any]:
    heuristic = heuristic_outbound_message_review(message)
    if heuristic["decision"] == "block":
        return heuristic
    result = await call_ai_json(
        "You are Retayn's outbound safety reviewer. Review this owner-editable recovery message before it is saved "
        "or sent. Be permissive for legitimate access recovery, even if the owner is frustrated. Block only "
        "high-confidence spam, trolling, harassment, threats, extortion, phishing, malware, credential theft, mass "
        "solicitation, or messages likely to get the sending account banned. Return JSON exactly as "
        "{\"decision\":\"allow|block\",\"owner_message\":\"...\"}.",
        {
            "message": message,
            "case": case_fact_record(case or {}) if case else {},
            "contact": {
                "name": clean_text((contact or {}).get("name")),
                "role": clean_text((contact or {}).get("role")),
                "organization": clean_text((contact or {}).get("organization")),
                "channel": clean_text((contact or {}).get("channel")),
                "address": clean_text((contact or {}).get("address")),
            } if contact else {},
        },
        max_tokens=350,
    )
    decision = clean_text((result or {}).get("decision"), 20).casefold()
    if decision == "block":
        return {
            "decision": "block",
            "owner_message": clean_text((result or {}).get("owner_message"), 700) or "Retayn blocked this message because it looks unsafe to send.",
        }
    return heuristic


async def ensure_outbound_message_safe(message: str, case: dict[str, Any] | None = None, contact: dict[str, Any] | None = None) -> None:
    review = await review_outbound_message_safety(message, case, contact)
    if review["decision"] == "block":
        raise HTTPException(400, review["owner_message"])


async def generate_initial_draft(case: dict[str, Any], contact: dict[str, Any] | None = None) -> str:
    facts = case_fact_record(case)
    contact_record = {
        "name": clean_text((contact or {}).get("name")),
        "role": clean_text((contact or {}).get("role")),
        "organization": clean_text((contact or {}).get("organization")),
        "channel": clean_text((contact or {}).get("channel")),
        "address": clean_text((contact or {}).get("address")),
        "notes": clean_text((contact or {}).get("notes")),
    } if contact else {}
    message_facts = {**facts, "contact": contact_record}
    result = await call_ai_json(
        "Draft a professional first recovery request to the supplied contact using only the supplied record. "
        "Address the contact by their actual name when provided. Do not address the platform support team unless "
        "the contact name itself is that support team. Never invent a fact, document, "
        "relationship, date, ownership claim, or action already taken. Do not use em dashes or emojis. Do not sound "
        "like AI. Write in natural short paragraphs, not labels like 'What happened' or 'What we need'. If the "
        "contact role is developer, agency, contractor, engineer, admin, or similar, ask for the practical handoff "
        "they can provide instead of sounding like a support ticket. Turn terse owner notes into professional wording "
        "without changing their meaning, for example 'I got hacked' can become 'I believe the account was compromised "
        "and I no longer have access.' Ask for a clear next step. Return JSON exactly "
        "as {\"message\": \"...\"}.",
        {"recovery_record": facts, "contact": contact_record},
        max_tokens=900,
    )
    candidate = enforce_contact_greeting(remove_emoji_and_emdash(clean_text((result or {}).get("message"), 12000)), contact)
    if meaningful_recovery_message(candidate) and await verify_fact_locked_message(candidate, message_facts):
        return candidate
    return fallback_recovery_draft(case, contact)


async def personalize_recovery_message(case: dict[str, Any], contact: dict[str, Any], reviewed_message: str) -> str:
    facts = case_fact_record(case)
    contact_record = {
        "name": clean_text(contact.get("name")),
        "role": clean_text(contact.get("role")),
        "organization": clean_text(contact.get("organization")),
        "channel": clean_text(contact.get("channel")),
        "address": clean_text(contact.get("address")),
        "notes": clean_text(contact.get("notes")),
    }
    message_facts = {**facts, "contact": contact_record}
    result = await call_ai_json(
        "Personalize the reviewed recovery message for this exact contact using only the supplied record, contact, "
        "and reviewed message. Preserve the owner-approved facts and request. Change the greeting and wording so it "
        "fits the contact's name, role, organization, notes, and channel. Do not add new claims, documents, threats, "
        "or pressure. Use natural short paragraphs, not label blocks. Do not use em dashes or emojis. Return JSON "
        "exactly as {\"message\": \"...\"}.",
        {"recovery_record": facts, "contact": contact_record, "reviewed_message": reviewed_message},
        max_tokens=900,
    )
    candidate = enforce_contact_greeting(remove_emoji_and_emdash(clean_text((result or {}).get("message"), 12000)), contact)
    if meaningful_recovery_message(candidate) and await verify_fact_locked_message(candidate, message_facts):
        return candidate
    return fallback_recovery_draft(case, contact)


def fallback_closing_message(case: dict[str, Any], contact: dict[str, Any], reason: str) -> str:
    name = clean_text(contact.get("name")) or "there"
    owner = clean_text(case.get("owner_name")) or "the account owner"
    reason = clean_text(reason, 1200) or "the recovery case is no longer needed"
    return remove_emoji_and_emdash(
        "\n".join(
            [
                f"Hello {name},",
                "",
                f"Thank you for your help with this recovery request. I am closing the case because {reason}.",
                "",
                "No further action is needed from you at this time.",
                "",
                "Regards,",
                owner,
            ]
        )
    )


async def generate_closing_message(case: dict[str, Any], contact: dict[str, Any], reason: str) -> str:
    facts = case_fact_record(case)
    closing_facts = {**facts, "cancellation_reason": clean_text(reason, 1200)}
    result = await call_ai_json(
        "Draft a short professional closing message for this recovery contact. Use only the supplied case record, "
        "contact, and owner cancellation reason. Do not invent facts, do not apologize excessively, do not use em "
        "dashes or emojis, and do not sound like AI. Say that no further action is needed if that matches the reason. "
        "Return JSON exactly as {\"message\":\"...\"}.",
        {
            "recovery_record": closing_facts,
            "contact": {
                "name": clean_text(contact.get("name")),
                "role": clean_text(contact.get("role")),
                "organization": clean_text(contact.get("organization")),
                "channel": clean_text(contact.get("channel")),
                "notes": clean_text(contact.get("notes")),
            },
            "cancellation_reason": clean_text(reason, 1200),
        },
        max_tokens=500,
    )
    candidate = remove_emoji_and_emdash(clean_text((result or {}).get("message"), 6000))
    if candidate and await verify_fact_locked_message(candidate, closing_facts):
        return candidate
    return fallback_closing_message(case, contact, reason)


def heuristic_abuse_review(payload: dict[str, Any]) -> dict[str, Any]:
    text = json_dumps(payload).casefold()
    clear_abuse_terms = (
        "spam them",
        "mass email",
        "email blast",
        "cold email",
        "troll",
        "prank",
        "harass",
        "annoy them",
        "threaten",
        "blackmail",
        "extort",
        "buy now",
        "limited time offer",
        "crypto giveaway",
        "investment opportunity",
    )
    if any(term in text for term in clear_abuse_terms):
        return {
            "decision": "block",
            "reason": "The recovery request looks like spam, harassment, or non-recovery outreach.",
            "owner_message": "This recovery case looks like it may be used for spam or harassment. Retayn did not create it. Rewrite it as a factual access recovery request with the account, lockout story, and ownership proof.",
        }
    contacts = payload.get("contacts") or []
    proof = clean_text(payload.get("ownership_proof"))
    lockout = clean_text(payload.get("lockout_story"))
    goal = clean_text(payload.get("recovery_goal"))
    if len(contacts) > 12 and len(proof) < 20 and len(lockout) < 40 and len(goal) < 40:
        return {
            "decision": "block",
            "reason": "Too many contacts with too little recovery context.",
            "owner_message": "This has too many contacts for the amount of recovery detail provided. Add the lockout story, account details, and proof before creating the case.",
        }
    return {"decision": "allow", "reason": "No clear abuse pattern found.", "owner_message": ""}


async def review_recovery_case_for_abuse(payload: dict[str, Any]) -> dict[str, Any]:
    heuristic = heuristic_abuse_review(payload)
    if heuristic["decision"] == "block":
        return heuristic
    result = await call_ai_json(
        "You are Retayn's recovery intake abuse reviewer. Review only the typed case fields and contact list, "
        "not document contents. Decide whether this is a legitimate access recovery attempt or likely abuse. "
        "Be permissive: allow real business disputes, incomplete but plausible cases, emotional lockout stories, "
        "and owner-supplied contacts. Block only high-confidence spam, harassment, trolling, threats, extortion, "
        "mass solicitation, unrelated marketing, or impersonation with no access-recovery purpose. Return JSON "
        "exactly as {\"decision\":\"allow|warn|block\",\"reason\":\"...\",\"owner_message\":\"...\"}. "
        "Use warn for weak or messy cases that should still proceed.",
        payload,
        max_tokens=450,
    )
    if not result:
        return heuristic
    decision = clean_text(result.get("decision"), 20).casefold()
    if decision not in {"allow", "warn", "block"}:
        return heuristic
    return {
        "decision": decision,
        "reason": clean_text(result.get("reason"), 500),
        "owner_message": clean_text(result.get("owner_message"), 700),
    }


def heuristic_classification(body: str, has_files: bool = False) -> str:
    text = body.casefold()
    if has_files or any(term in text for term in ("attached the files", "here are the files", "download link", "source files attached")):
        return "files_shared"
    if any(term in text for term in (
        "account name",
        "account username",
        "which account",
        "what account",
        "username to give access",
        "email to give access",
        "where should i give access",
        "who should i invite",
        "what user should i add",
    )):
        return "account_info_request"
    if any(term in text for term in (
        "what repo",
        "which repo",
        "repository name",
        "repo name",
        "what repository",
        "which repository",
        "what platform",
        "which platform",
        "what business",
        "which business",
        "company name",
        "owner email",
        "your email",
        "what email",
        "which email",
        "who is the owner",
        "owner name",
    )):
        return "case_fact_request"
    if any(term in text for term in (
        "need more proof",
        "provide proof",
        "proof of ownership",
        "verify ownership",
        "verify this is you",
        "confirm this is you",
        "confirm that this is actually you",
        "confirm this is actually you",
        "how can i confirm",
        "send evidence",
        "additional documentation",
    )):
        return "proof_request"
    if any(term in text for term in (
        "cannot help",
        "cannot give",
        "can't give",
        "cannot provide",
        "can't provide",
        "cannot restore",
        "can't restore",
        "unable to help",
        "unable to provide",
        "request denied",
        "not eligible",
        "will not transfer",
        "will not provide",
        "will not give",
        "rejected",
    )):
        return "rejection"
    if any(term in text for term in (
        "restored access",
        "restore access",
        "can restore access",
        "giving access",
        "give access",
        "access has been restored",
        "transferred ownership",
        "transfer ownership",
        "invitation sent",
        "admin invitation",
        "credentials are",
        "recovery path",
    )):
        return "access_offer"
    if any(term in text for term in ("thank you", "received", "looking into", "we will review", "case number", "ticket number", "get back to you")):
        return "generic"
    return "other"


async def classify_response(body: str, has_files: bool = False) -> str:
    heuristic = heuristic_classification(body, has_files)
    if heuristic in {"files_shared", "proof_request", "account_info_request", "case_fact_request", "access_offer", "rejection"}:
        return heuristic
    result = await call_ai_json(
        "Classify a recovery-case response. Return JSON exactly as {\"classification\": \"generic\"}. Allowed "
        "values: proof_request, account_info_request, case_fact_request, generic, access_offer, files_shared, rejection, other. files_shared means files or "
        "a file link were provided. access_offer means access, ownership, credentials, or an invitation is being "
        "provided. proof_request means more ownership evidence is requested. account_info_request means the contact "
        "is asking which account, username, email, repo, or identifier to restore or invite. case_fact_request means "
        "the contact asks for a basic fact already in the recovery record, such as owner name, business name, owner "
        "email, platform, repository, account identifier, or recovery goal.",
        {"message": body, "has_files": has_files},
        max_tokens=200,
    )
    classification = clean_text((result or {}).get("classification"), 40)
    return classification if classification in RESPONSE_CLASSIFICATIONS else heuristic


async def generate_generic_followup(case: dict[str, Any], incoming: str) -> str:
    facts = case_fact_record(case)
    result = await call_ai_json(
        "Write one concise professional follow-up to the contact's routine response. Use only facts in the recovery "
        "record and the incoming message. Never claim an action happened unless it is in the record. Do not use em "
        "dashes or emojis. If the contact says they are checking or looking into it, respond naturally with a short "
        "acknowledgement and ask them to let us know what they find. Return JSON exactly as {\"message\": \"...\"}.",
        {"recovery_record": facts, "incoming_message": incoming},
        max_tokens=500,
    )
    candidate = remove_emoji_and_emdash(clean_text((result or {}).get("message"), 5000))
    if candidate and await verify_fact_locked_message(candidate, facts):
        return candidate
    return "Thank you for the update. Please let us know the next required step and whether you need any specific ownership evidence from us."


def routine_acknowledgement(body: str) -> bool:
    text = clean_text(body, 1000).casefold()
    return any(
        term in text
        for term in (
            "let me check",
            "i will check",
            "i'll check",
            "checking now",
            "looking into it",
            "i will look",
            "i'll look",
            "give me a minute",
            "one moment",
        )
    )


async def generate_recovery_followup(case: dict[str, Any], incoming: str, purpose: str) -> str:
    facts = case_fact_record(case)
    result = await call_ai_json(
        "Write a concise professional recovery follow-up using only the supplied record and incoming message. "
        "Do not invent proof, documents, access, actions, or claims. If the contact asks what account to restore or "
        "invite, provide the account identifier from the record directly. If the contact asks for basic known facts "
        "such as owner name, owner email, business name, platform, repository, or recovery goal, answer directly "
        "from the record. If the owner said there is no proof, do not pretend proof exists. Ask for the next "
        "verification step instead. Use natural paragraphs, not labels. "
        "No em dashes or emojis. Return JSON exactly as {\"message\":\"...\"}.",
        {"recovery_record": facts, "incoming_message": incoming, "purpose": purpose},
        max_tokens=650,
    )
    candidate = remove_emoji_and_emdash(clean_text((result or {}).get("message"), 5000))
    if candidate and await verify_fact_locked_message(candidate, facts):
        return candidate
    return fallback_recovery_followup(case, incoming, purpose)


def fallback_recovery_followup(case: dict[str, Any], incoming: str, purpose: str) -> str:
    identifier = clean_text(case.get("account_identifier"))
    owner = clean_text(case.get("owner_name")) or "the account owner"
    proof = clean_text(case.get("ownership_proof"))
    if purpose == "account_info_request" and identifier:
        return remove_emoji_and_emdash(
            f"Please use this account identifier for the access handoff: {identifier}.\n\n"
            "If you need a different username, email address, or invitation target, tell me exactly where it should be added and I will confirm it.\n\n"
            f"Regards,\n{owner}"
        )
    if purpose == "case_fact_request":
        facts = case_fact_record(case)
        available = []
        for label, key in (
            ("Owner", "owner_name"),
            ("Owner email", "owner_email"),
            ("Business", "business_name"),
            ("Platform", "platform_name"),
            ("Account", "account_identifier"),
            ("Recovery goal", "recovery_goal"),
        ):
            value = clean_text(facts.get(key), 1000)
            if value:
                available.append(f"{label}: {value}")
        if available:
            return remove_emoji_and_emdash(
                "Here are the details from the recovery record:\n\n"
                + "\n".join(available)
                + f"\n\nRegards,\n{owner}"
            )
        return remove_emoji_and_emdash(
            "I do not have that detail saved in the recovery record yet. Please tell me exactly what you need and I will confirm it.\n\n"
            f"Regards,\n{owner}"
        )
    if purpose == "proof_request":
        if proof and not re.search(r"\b(no proof|dont have any proof|don't have any proof|do not have proof|none)\b", proof, flags=re.IGNORECASE):
            return remove_emoji_and_emdash(
                f"I can share the ownership context I have: {proof}.\n\n"
                "Please tell me the secure way you want me to send it, and whether there is anything specific you need to verify access.\n\n"
                f"Regards,\n{owner}"
            )
        return remove_emoji_and_emdash(
            "I do not have formal proof ready yet because this is an early startup, but I can answer verification questions about the account, repository, and work history.\n\n"
            "Please tell me exactly what information you need to confirm this safely.\n\n"
            f"Regards,\n{owner}"
        )
    return "Thank you. Please tell me the next step you need from me so we can restore access safely."


async def save_upload(
    upload: UploadFile,
    case_id: int,
    source: str,
    label: str = "",
    contact_id: int | None = None,
    message_id: int | None = None,
) -> dict[str, Any]:
    original_name = Path(upload.filename or "document").name[:240]
    suffix = Path(original_name).suffix[:16]
    stored_name = f"{secrets.token_hex(18)}{suffix}"
    upload_dir = user_upload_dir()
    destination = (upload_dir / stored_name).resolve()
    if destination.parent != upload_dir.resolve():
        raise HTTPException(400, "Invalid evidence file name.")
    size = 0
    try:
        with destination.open("wb") as target:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"{original_name} is larger than 20 MB.")
                target.write(chunk)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    file_id = execute(
        """
        INSERT INTO recovery_files(case_id, contact_id, message_id, source, label, original_name, stored_name, content_type, size_bytes, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            contact_id,
            message_id,
            source,
            clean_text(label, 240),
            original_name,
            stored_name,
            clean_text(upload.content_type, 120) or mimetypes.guess_type(original_name)[0] or "application/octet-stream",
            size,
            utc_now(),
        ),
    )
    return row("SELECT * FROM recovery_files WHERE id=?", (file_id,)) or {}


def attach_existing_bytes(
    case_id: int,
    contact_id: int,
    message_id: int,
    original_name: str,
    content_type: str,
    content: bytes,
) -> dict[str, Any] | None:
    if not content or len(content) > MAX_UPLOAD_BYTES:
        return None
    original_name = Path(original_name or "received-file").name[:240]
    suffix = Path(original_name).suffix[:16]
    stored_name = f"{secrets.token_hex(18)}{suffix}"
    upload_dir = user_upload_dir()
    destination = (upload_dir / stored_name).resolve()
    if destination.parent != upload_dir.resolve():
        return None
    destination.write_bytes(content)
    file_id = execute(
        """
        INSERT INTO recovery_files(case_id, contact_id, message_id, source, label, original_name, stored_name, content_type, size_bytes, created_at)
        VALUES(?, ?, ?, 'contact', '', ?, ?, ?, ?, ?)
        """,
        (case_id, contact_id, message_id, original_name, stored_name, content_type or "application/octet-stream", len(content), utc_now()),
    )
    return row("SELECT * FROM recovery_files WHERE id=?", (file_id,))


def case_owner_files(case_id: int) -> list[dict[str, Any]]:
    return rows("SELECT * FROM recovery_files WHERE case_id=? AND source='owner' ORDER BY created_at", (case_id,))


def telegram_mtproto_configured() -> bool:
    cfg = recovery_config()
    return bool(cfg["telegram_mtproto_api_id"] and cfg["telegram_mtproto_api_hash"])


def telegram_session() -> tuple[Any, int, str] | tuple[None, None, None]:
    cfg = recovery_config()
    if not cfg["telegram_mtproto_api_id"] or not cfg["telegram_mtproto_api_hash"]:
        return None, None, None
    try:
        api_id = int(cfg["telegram_mtproto_api_id"])
    except ValueError:
        return None, None, None
    try:
        from telethon.sessions import StringSession
    except ImportError:
        return None, None, None
    session_string = cfg["telegram_mtproto_session"]
    session_path = cfg["telegram_mtproto_session_path"] or str(BASE_DIR / "recovery_telegram.session")
    if session_path and not Path(session_path).is_absolute():
        session_path = str(BASE_DIR / session_path)
    return (StringSession(session_string) if session_string else session_path, api_id, cfg["telegram_mtproto_api_hash"])


def telegram_target(address: str) -> str:
    value = clean_text(address, 500)
    if not value:
        return value
    if value.startswith("@") or value.lstrip("-").isdigit() or value.startswith("+"):
        return value
    if re.fullmatch(r"[A-Za-z0-9_]{5,32}", value):
        return f"@{value}"
    return value


def parse_utc_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def contact_has_sent_outreach(contact_id: int) -> bool:
    return bool(
        row(
            """
            SELECT id FROM recovery_messages
            WHERE contact_id=? AND direction='outbound' AND status='sent'
            LIMIT 1
            """,
            (contact_id,),
        )
    )


def contact_has_pending_draft(contact_id: int) -> bool:
    return bool(
        row(
            """
            SELECT id FROM recovery_messages
            WHERE contact_id=? AND direction='outbound' AND status='draft'
            LIMIT 1
            """,
            (contact_id,),
        )
    )


def cleanup_premature_telegram_sync(case_id: int | None = None) -> int:
    params: tuple[Any, ...] = (case_id,) if case_id else ()
    case_filter = "AND recovery_contacts.case_id=?" if case_id else ""
    contacts = rows(
        f"""
        SELECT recovery_contacts.* FROM recovery_contacts
        WHERE recovery_contacts.channel='telegram' {case_filter}
        """
        ,
        params,
    )
    removed = 0
    upload_dir = user_upload_dir().resolve()
    affected_cases: set[int] = set()
    for contact in contacts:
        if contact_has_sent_outreach(contact["id"]):
            continue
        stale_messages = rows(
            """
            SELECT * FROM recovery_messages
            WHERE contact_id=? AND direction='inbound' AND external_id LIKE 'telegram-mtproto:%'
            """,
            (contact["id"],),
        )
        if not stale_messages:
            continue
        affected_cases.add(int(contact["case_id"]))
        message_ids = [int(item["id"]) for item in stale_messages]
        for file_item in rows(
            f"SELECT * FROM recovery_files WHERE message_id IN ({','.join('?' for _ in message_ids)})",
            tuple(message_ids),
        ):
            stored_name = clean_text(file_item.get("stored_name"), 500)
            if stored_name:
                path = (upload_dir / stored_name).resolve()
                if path.parent == upload_dir and path.exists():
                    try:
                        path.unlink()
                    except OSError:
                        logging.exception("Could not remove premature Telegram recovery file")
        execute(
            f"DELETE FROM recovery_files WHERE message_id IN ({','.join('?' for _ in message_ids)})",
            tuple(message_ids),
        )
        execute(
            f"DELETE FROM recovery_messages WHERE id IN ({','.join('?' for _ in message_ids)})",
            tuple(message_ids),
        )
        execute(
            "UPDATE recovery_contacts SET status='queued', last_response_at=NULL, updated_at=? WHERE id=?",
            (utc_now(), contact["id"]),
        )
        removed += len(message_ids)
    for affected_case_id in affected_cases:
        outbound = row(
            """
            SELECT id FROM recovery_messages
            WHERE case_id=? AND direction='outbound' AND status IN ('sent','manual_required','waiting_setup')
            LIMIT 1
            """,
            (affected_case_id,),
        )
        if not outbound:
            execute(
                "UPDATE recovery_cases SET status='message_review', approved_message=NULL, updated_at=? WHERE id=?",
                (utc_now(), affected_case_id),
            )
    return removed


def smtp_send(contact: dict[str, Any], subject: str, body: str, files: list[dict[str, Any]]) -> tuple[str, str]:
    cfg = recovery_config()
    if not cfg["smtp_host"] or not cfg["smtp_from"]:
        return "waiting_setup", "Email delivery needs RECOVERY_SMTP_HOST and RECOVERY_SMTP_FROM_EMAIL in guard/.env."
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = cfg["smtp_from"]
    message["To"] = contact["address"]
    message.set_content(body)
    for item in files:
        upload_dir = user_upload_dir()
        path = (upload_dir / item["stored_name"]).resolve()
        if path.parent != upload_dir.resolve() or not path.exists():
            continue
        content_type = str(item.get("content_type") or "application/octet-stream")
        maintype, subtype = (content_type.split("/", 1) + ["octet-stream"])[:2]
        message.add_attachment(path.read_bytes(), maintype=maintype, subtype=subtype, filename=item["original_name"])
    try:
        with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=25) as smtp:
            if cfg["smtp_tls"]:
                smtp.starttls()
            if cfg["smtp_username"]:
                smtp.login(cfg["smtp_username"], cfg["smtp_password"])
            smtp.send_message(message)
        return "sent", message.get("Message-ID") or "smtp"
    except Exception as exc:
        logging.exception("Recovery email delivery failed")
        return "failed", f"Email delivery failed: {exc!s}"[:500]


async def telegram_send(contact: dict[str, Any], body: str, files: list[dict[str, Any]]) -> tuple[str, str]:
    cfg = recovery_config()
    token = cfg["telegram_bot_token"]
    if not token:
        return "waiting_setup", "Telegram delivery needs RECOVERY_TELEGRAM_BOT_TOKEN in guard/.env."
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": contact["address"], "text": body},
            )
            payload = response.json()
            if response.status_code >= 400 or not payload.get("ok"):
                reason = payload.get("description") or response.text
                return "failed", f"Telegram delivery failed: {reason}"[:500]
            external_id = str(payload.get("result", {}).get("message_id") or "telegram")
            for item in files:
                upload_dir = user_upload_dir()
                path = (upload_dir / item["stored_name"]).resolve()
                if path.parent != upload_dir.resolve() or not path.exists():
                    continue
                with path.open("rb") as document:
                    await client.post(
                        f"https://api.telegram.org/bot{token}/sendDocument",
                        data={"chat_id": contact["address"]},
                        files={"document": (item["original_name"], document, item.get("content_type") or "application/octet-stream")},
                    )
        return "sent", external_id
    except Exception as exc:
        logging.exception("Recovery Telegram delivery failed")
        return "failed", f"Telegram delivery failed: {exc!s}"[:500]


async def telegram_mtproto_send(contact: dict[str, Any], body: str, files: list[dict[str, Any]]) -> tuple[str, str]:
    session, api_id, api_hash = telegram_session()
    if not session or not api_id or not api_hash:
        return "waiting_setup", "Telegram account delivery needs RECOVERY_TELEGRAM_MTPROTO_API_ID and RECOVERY_TELEGRAM_MTPROTO_API_HASH in guard/.env."
    try:
        from telethon import TelegramClient
    except ImportError:
        return "waiting_setup", "Install Telethon to send Telegram recovery messages from a Telegram account."
    try:
        async with TelegramClient(session, api_id, api_hash) as client:
            if not await client.is_user_authorized():
                return "waiting_setup", "Telegram account session is not signed in yet. Create RECOVERY_TELEGRAM_MTPROTO_SESSION or sign in the configured session file first."
            destination = telegram_target(contact["address"])
            me = await client.get_me()
            agent_name = getattr(me, "username", None) or getattr(me, "phone", None) or "Telegram account"
            sent = await client.send_message(destination, body)
            for item in files:
                upload_dir = user_upload_dir()
                path = (upload_dir / item["stored_name"]).resolve()
                if path.parent != upload_dir.resolve() or not path.exists():
                    continue
                await client.send_file(destination, str(path), caption=item.get("label") or item["original_name"])
        return "sent", f"telegram-mtproto:{getattr(sent, 'id', 'message')} from {agent_name} to {destination}"
    except Exception as exc:
        logging.exception("Recovery Telegram MTProto delivery failed")
        return "failed", f"Telegram account delivery failed for {telegram_target(contact.get('address', ''))}: {exc!s}"[:500]


async def whatsapp_send(contact: dict[str, Any], body: str, initial: bool) -> tuple[str, str]:
    cfg = recovery_config()
    if not cfg["whatsapp_token"] or not cfg["whatsapp_phone_id"]:
        return "waiting_setup", "WhatsApp delivery needs a Cloud API access token and phone number ID in guard/.env."
    url = f"https://graph.facebook.com/{cfg['whatsapp_api_version']}/{cfg['whatsapp_phone_id']}/messages"
    if initial:
        if not cfg["whatsapp_template"]:
            return "waiting_setup", "WhatsApp first contact needs an approved template configured as RECOVERY_WHATSAPP_TEMPLATE_NAME."
        payload = {
            "messaging_product": "whatsapp",
            "to": contact["address"],
            "type": "template",
            "template": {
                "name": cfg["whatsapp_template"],
                "language": {"code": cfg["whatsapp_template_language"]},
                "components": [{"type": "body", "parameters": [{"type": "text", "text": body[:3500]}]}],
            },
        }
    else:
        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": contact["address"],
            "type": "text",
            "text": {"preview_url": False, "body": body[:4096]},
        }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                url,
                headers={"Authorization": f"Bearer {cfg['whatsapp_token']}", "Content-Type": "application/json"},
                json=payload,
            )
        if response.status_code >= 400:
            return "failed", f"WhatsApp delivery failed: {response.text[:400]}"
        data = response.json()
        return "sent", str((data.get("messages") or [{}])[0].get("id") or "whatsapp")
    except Exception as exc:
        logging.exception("Recovery WhatsApp delivery failed")
        return "failed", f"WhatsApp delivery failed: {exc!s}"[:500]


async def dispatch_message(
    case: dict[str, Any],
    contact: dict[str, Any],
    body: str,
    files: list[dict[str, Any]] | None = None,
    initial: bool = False,
) -> tuple[str, str]:
    channel = contact["channel"]
    files = files or []
    if channel == "email":
        return await asyncio.to_thread(smtp_send, contact, f"Access recovery request: {case['title']}", body, files)
    if channel == "telegram":
        cfg = recovery_config()
        if cfg["telegram_mtproto_api_id"] and cfg["telegram_mtproto_api_hash"]:
            return await telegram_mtproto_send(contact, body, files)
        if cfg["telegram_bot_token"]:
            return await telegram_send(contact, body, files)
        return "waiting_setup", "Telegram delivery needs the Retayn Telegram account connected with MTProto. Set RECOVERY_TELEGRAM_MTPROTO_API_ID and RECOVERY_TELEGRAM_MTPROTO_API_HASH, then run setup_telegram_session.py."
    if channel == "whatsapp":
        return await whatsapp_send(contact, body, initial)
    return "manual_required", f"{channel.replace('_', ' ').title()} does not have an automated delivery adapter yet. Copy the approved message from Retayn and record the response here."


async def sync_telegram_mtproto_responses(limit_per_contact: int = 8) -> dict[str, Any]:
    cleanup_premature_telegram_sync()
    session, api_id, api_hash = telegram_session()
    if not session or not api_id or not api_hash:
        return {"ok": False, "synced": 0, "message": "Telegram account sync needs MTProto API ID, API hash, and a signed-in session."}
    try:
        from telethon import TelegramClient
    except ImportError:
        return {"ok": False, "synced": 0, "message": "Install Telethon before syncing Telegram account replies."}
    contacts = rows(
        """
        SELECT * FROM recovery_contacts
        WHERE channel='telegram' AND status NOT IN ('closed', 'success')
        ORDER BY updated_at DESC
        """
    )
    synced = 0
    errors: list[str] = []
    try:
        async with TelegramClient(session, api_id, api_hash) as client:
            if not await client.is_user_authorized():
                return {"ok": False, "synced": 0, "message": "Telegram account session is not signed in yet."}
            for contact in contacts:
                if not contact_has_sent_outreach(contact["id"]):
                    continue
                sync_after = parse_utc_datetime(contact.get("last_contacted_at")) or parse_utc_datetime(contact.get("created_at"))
                try:
                    entity = await client.get_entity(telegram_target(contact["address"]))
                    messages = [message async for message in client.iter_messages(entity, limit=limit_per_contact)]
                    for message in reversed(messages):
                        if getattr(message, "out", False):
                            continue
                        message_date = parse_utc_datetime(getattr(message, "date", None))
                        if sync_after and message_date and message_date <= sync_after:
                            continue
                        external_id = f"telegram-mtproto:{getattr(message, 'chat_id', contact['address'])}:{message.id}"
                        if row("SELECT id FROM recovery_messages WHERE external_id=?", (external_id,)):
                            continue
                        received_files: list[tuple[str, str, bytes]] = []
                        if getattr(message, "media", None):
                            content = await client.download_media(message, file=bytes)
                            if content:
                                name = f"telegram-file-{message.id}"
                                document = getattr(message, "document", None)
                                mime_type = getattr(document, "mime_type", None) if document else "application/octet-stream"
                                received_files.append((name, mime_type or "application/octet-stream", content))
                        body = clean_text(getattr(message, "message", "") or "", 20000)
                        await process_inbound_message(contact, body or "A Telegram message was received.", received_files, external_id)
                        synced += 1
                except Exception as exc:
                    logging.exception("Could not sync Telegram recovery contact")
                    errors.append(f"{contact['name']}: {exc!s}"[:240])
    except Exception as exc:
        logging.exception("Telegram recovery sync failed")
        return {"ok": False, "synced": synced, "message": f"Telegram sync failed: {exc!s}"[:500], "errors": errors}
    return {"ok": not errors, "synced": synced, "message": f"Synced {synced} Telegram message(s).", "errors": errors}


def insert_message(
    case_id: int,
    contact_id: int,
    direction: str,
    sender_type: str,
    body: str,
    status: str,
    classification: str | None = None,
    external_id: str | None = None,
    delivery_note: str | None = None,
) -> int:
    return execute(
        """
        INSERT INTO recovery_messages(case_id, contact_id, direction, sender_type, body, classification, status, external_id, delivery_note, created_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (case_id, contact_id, direction, sender_type, clean_text(body, 20000), classification, status, external_id, delivery_note, utc_now()),
    )


async def send_and_record(
    case: dict[str, Any],
    contact: dict[str, Any],
    body: str,
    sender_type: str = "agent",
    files: list[dict[str, Any]] | None = None,
    initial: bool = False,
) -> dict[str, Any]:
    await ensure_outbound_message_safe(body, case, contact)
    status, provider_result = await dispatch_message(case, contact, body, files, initial)
    message_id = insert_message(
        case["id"], contact["id"], "outbound", sender_type, body, status,
        external_id=provider_result if status == "sent" else None,
        delivery_note=None if status == "sent" else provider_result,
    )
    for item in files or []:
        if item.get("id"):
            execute("UPDATE recovery_files SET message_id=? WHERE id=?", (message_id, item["id"]))
    contact_status = "contacted" if status == "sent" else status
    execute(
        "UPDATE recovery_contacts SET status=?, last_contacted_at=?, updated_at=? WHERE id=?",
        (contact_status, utc_now() if status == "sent" else contact.get("last_contacted_at"), utc_now(), contact["id"]),
    )
    return row("SELECT * FROM recovery_messages WHERE id=?", (message_id,)) or {}


async def process_inbound_message(
    contact: dict[str, Any],
    body: str,
    received_files: list[tuple[str, str, bytes]] | None = None,
    external_id: str | None = None,
) -> dict[str, Any]:
    case = row("SELECT * FROM recovery_cases WHERE id=?", (contact["case_id"],))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    received_files = received_files or []
    classification = await classify_response(body, bool(received_files))
    message_id = insert_message(
        case["id"], contact["id"], "inbound", "contact", body or "A file was received.", "received",
        classification=classification, external_id=external_id,
    )
    saved_files = []
    for name, content_type, content in received_files:
        saved = attach_existing_bytes(case["id"], contact["id"], message_id, name, content_type, content)
        if saved:
            saved_files.append(saved)
    contact_status = "responded"
    case_status = case["status"]
    if classification == "proof_request":
        contact_status = "needs_info"
        case_status = "needs_owner"
        draft = await generate_recovery_followup(case, body, "proof_request")
        insert_message(case["id"], contact["id"], "outbound", "agent", draft, "draft", classification="proof_response")
        create_recovery_event(
            case["id"], "recovery_proof_requested", "high", "More recovery proof is needed",
            f"{contact['name']} asked for more ownership evidence in {case['title']}.",
            {"contact_id": contact["id"], "message_id": message_id, "contact_name": contact["name"], "incoming_message": body},
        )
    elif classification == "account_info_request":
        contact_status = "responded"
        case_status = "outreach_active"
        followup = await generate_recovery_followup(case, body, "account_info_request")
        await send_and_record(case, contact, followup, sender_type="agent", initial=False)
    elif classification == "case_fact_request":
        contact_status = "responded"
        case_status = "outreach_active"
        followup = await generate_recovery_followup(case, body, "case_fact_request")
        await send_and_record(case, contact, followup, sender_type="agent", initial=False)
    elif classification in {"access_offer", "files_shared"}:
        contact_status = "success"
        case_status = "action_required"
        summary = f"{contact['name']} offered access or recovery materials. Review the conversation now."
        if saved_files:
            summary = f"{contact['name']} sent {len(saved_files)} file(s). They are ready to download in Recover."
        create_recovery_event(
            case["id"], "recovery_handoff_ready", "critical", "Recovery handoff is ready", summary,
            {"contact_id": contact["id"], "message_id": message_id, "contact_name": contact["name"], "incoming_message": body, "file_ids": [item["id"] for item in saved_files]},
        )
    elif classification == "generic" and bool(case.get("auto_reply_generic")) and not contact_has_pending_draft(contact["id"]):
        followup = await generate_generic_followup(case, body)
        await send_and_record(case, contact, followup, sender_type="agent", initial=False)
    elif classification == "rejection":
        case_status = "needs_owner"
        create_recovery_event(
            case["id"], "recovery_rejected", "high", "A recovery contact declined the request",
            f"{contact['name']} declined or could not complete the recovery request.",
            {"contact_id": contact["id"], "message_id": message_id, "contact_name": contact["name"], "incoming_message": body},
        )
    execute(
        "UPDATE recovery_contacts SET status=?, last_response_at=?, updated_at=? WHERE id=?",
        (contact_status, utc_now(), utc_now(), contact["id"]),
    )
    execute("UPDATE recovery_cases SET status=?, updated_at=? WHERE id=?", (case_status, utc_now(), case["id"]))
    return get_recovery_case(case["id"])


@router.get("/api/recovery")
async def recovery_overview_api() -> JSONResponse:
    return JSONResponse({"summary": recovery_summary(), "cases": list_recovery_cases()})


@router.get("/api/recovery/cases/{case_id}")
async def recovery_case_api(case_id: int) -> JSONResponse:
    return JSONResponse(get_recovery_case(case_id))


@router.post("/api/recovery/telegram/sync")
async def sync_telegram_recovery_api() -> JSONResponse:
    return JSONResponse(await sync_telegram_mtproto_responses())


@router.post("/api/recovery/cases")
async def create_recovery_case(request: Request) -> JSONResponse:
    form = await request.form()
    required = {
        "owner_name": clean_text(form.get("owner_name"), 240),
        "asset_type": clean_text(form.get("asset_type"), 240),
        "platform_name": clean_text(form.get("platform_name"), 240),
        "recovery_goal": clean_text(form.get("recovery_goal"), 5000),
        "lockout_story": clean_text(form.get("lockout_story"), 10000),
    }
    missing = [key.replace("_", " ") for key, value in required.items() if not value]
    if missing:
        raise HTTPException(400, f"Complete these required fields: {', '.join(missing)}.")
    contact_names = [clean_text(item, 240) for item in form.getlist("contact_name")]
    contact_roles = [clean_text(item, 240) for item in form.getlist("contact_role")]
    contact_orgs = [clean_text(item, 240) for item in form.getlist("contact_organization")]
    contact_channels = [clean_text(item, 40) for item in form.getlist("contact_channel")]
    contact_addresses = [clean_text(item, 500) for item in form.getlist("contact_address")]
    contact_notes = [clean_text(item, 2000) for item in form.getlist("contact_notes")]
    contacts: list[dict[str, str]] = []
    for index, name in enumerate(contact_names):
        channel = contact_channels[index] if index < len(contact_channels) else "other"
        address = contact_addresses[index] if index < len(contact_addresses) else ""
        if not name and not address:
            continue
        if channel not in CONTACT_CHANNELS:
            raise HTTPException(400, f"Unsupported contact channel: {channel}.")
        if not name or not address:
            raise HTTPException(400, "Each contact needs a name and an address, handle, phone number, or support URL.")
        contacts.append(
            {
                "name": name,
                "role": contact_roles[index] if index < len(contact_roles) else "",
                "organization": contact_orgs[index] if index < len(contact_orgs) else "",
                "channel": channel,
                "address": normalize_address(channel, address),
                "notes": contact_notes[index] if index < len(contact_notes) else "",
            }
        )
    if not contacts:
        raise HTTPException(400, "Add at least one person, support team, developer, agency, or publisher contact.")
    if len(contacts) > 30:
        raise HTTPException(400, "A recovery case can contain up to 30 owner-supplied contacts.")
    abuse_review = await review_recovery_case_for_abuse(
        {
            "owner_name": required["owner_name"],
            "owner_email": clean_text(form.get("owner_email"), 320),
            "business_name": clean_text(form.get("business_name"), 320),
            "title": clean_text(form.get("title"), 240),
            "asset_type": required["asset_type"],
            "platform_name": required["platform_name"],
            "account_identifier": clean_text(form.get("account_identifier"), 1000),
            "recovery_goal": required["recovery_goal"],
            "lockout_story": required["lockout_story"],
            "lockout_date": clean_text(form.get("lockout_date"), 40),
            "ownership_proof": clean_text(form.get("ownership_proof"), 10000),
            "additional_context": clean_text(form.get("additional_context"), 10000),
            "urgency": clean_text(form.get("urgency"), 30) or "normal",
            "contact_count": len(contacts),
            "contacts": contacts,
        }
    )
    if abuse_review["decision"] == "block":
        raise HTTPException(
            400,
            abuse_review["owner_message"] or "Retayn could not create this recovery case because it looks like spam or abusive outreach.",
        )
    now = utc_now()
    title = clean_text(form.get("title"), 240) or f"Recover {required['asset_type']} from {required['platform_name']}"
    case_id = execute(
        """
        INSERT INTO recovery_cases(
          title, owner_name, owner_email, business_name, asset_type, platform_name, account_identifier,
          recovery_goal, lockout_story, lockout_date, ownership_proof, additional_context, urgency, status,
          draft_message, approved_message, auto_reply_generic, share_evidence_initially, created_at, updated_at
        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'draft', NULL, NULL, ?, ?, ?, ?)
        """,
        (
            title,
            required["owner_name"],
            clean_text(form.get("owner_email"), 320),
            clean_text(form.get("business_name"), 320),
            required["asset_type"],
            required["platform_name"],
            clean_text(form.get("account_identifier"), 1000),
            required["recovery_goal"],
            required["lockout_story"],
            clean_text(form.get("lockout_date"), 40),
            clean_text(form.get("ownership_proof"), 10000),
            clean_text(form.get("additional_context"), 10000),
            clean_text(form.get("urgency"), 30) or "normal",
            1 if bool_value(form.get("auto_reply_generic")) else 0,
            1 if bool_value(form.get("share_evidence_initially")) else 0,
            now,
            now,
        ),
    )
    for contact in contacts:
        execute(
            """
            INSERT INTO recovery_contacts(case_id, name, role, organization, channel, address, notes, status, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?, ?, 'queued', ?, ?)
            """,
            (
                case_id, contact["name"], contact["role"], contact["organization"], contact["channel"],
                contact["address"], contact["notes"], now, now,
            ),
        )
    labels = [clean_text(item, 240) for item in form.getlist("evidence_label")]
    uploads = [item for item in form.getlist("evidence_files") if hasattr(item, "filename") and item.filename]
    for index, upload in enumerate(uploads):
        await save_upload(upload, case_id, "owner", labels[index] if index < len(labels) else "")
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,)) or {}
    first_contact = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at LIMIT 1", (case_id,))
    draft = await generate_initial_draft(case, first_contact[0] if first_contact else None)
    execute(
        "UPDATE recovery_cases SET draft_message=?, status='message_review', updated_at=? WHERE id=?",
        (draft, utc_now(), case_id),
    )
    return JSONResponse(get_recovery_case(case_id), status_code=201)


@router.post("/api/recovery/cases/{case_id}/draft")
async def save_recovery_draft(case_id: int, request: Request) -> JSONResponse:
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    payload = await request.json()
    message = remove_emoji_and_emdash(clean_text(payload.get("message"), 12000))
    if len(message) < 40:
        raise HTTPException(400, "The recovery message is too short.")
    first_contact = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at LIMIT 1", (case_id,))
    message = enforce_contact_greeting(message, first_contact[0] if first_contact else None)
    await ensure_outbound_message_safe(message, case, first_contact[0] if first_contact else None)
    execute(
        "UPDATE recovery_cases SET draft_message=?, status='message_review', updated_at=? WHERE id=?",
        (message, utc_now(), case_id),
    )
    return JSONResponse(get_recovery_case(case_id))


@router.post("/api/recovery/cases/{case_id}/regenerate")
async def regenerate_recovery_draft(case_id: int) -> JSONResponse:
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    if case["status"] in {"outreach_active", "action_required", "recovered", "closed"}:
        raise HTTPException(400, "The first message cannot be regenerated after outreach starts.")
    first_contact = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at LIMIT 1", (case_id,))
    draft = await generate_initial_draft(case, first_contact[0] if first_contact else None)
    execute(
        "UPDATE recovery_cases SET draft_message=?, status='message_review', updated_at=? WHERE id=?",
        (draft, utc_now(), case_id),
    )
    return JSONResponse(get_recovery_case(case_id))


@router.post("/api/recovery/cases/{case_id}/approve")
async def approve_recovery_outreach(case_id: int, request: Request) -> JSONResponse:
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    payload = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    submitted_message = remove_emoji_and_emdash(clean_text(payload.get("message"), 12000))
    message = submitted_message or clean_text(case.get("draft_message"), 12000)
    if len(message) < 40:
        raise HTTPException(400, "Review and save a complete first message before starting outreach.")
    contacts = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at", (case_id,))
    if not contacts:
        raise HTTPException(400, "Add at least one recovery contact before starting outreach.")
    await ensure_outbound_message_safe(message, case, contacts[0])
    execute(
        "UPDATE recovery_cases SET approved_message=?, status='outreach_active', updated_at=? WHERE id=?",
        (message, utc_now(), case_id),
    )
    case["approved_message"] = message
    case["status"] = "outreach_active"
    files = case_owner_files(case_id) if bool(case.get("share_evidence_initially")) else []
    first_contact_id = contacts[0]["id"] if contacts else None
    for contact in contacts:
        already_sent = row(
            "SELECT id FROM recovery_messages WHERE contact_id=? AND direction='outbound' AND status IN ('sent','manual_required','waiting_setup') LIMIT 1",
            (contact["id"],),
        )
        if not already_sent:
            contact_message = message if contact["id"] == first_contact_id else await personalize_recovery_message(case, contact, message)
            await send_and_record(case, contact, contact_message, files=files, initial=True)
    return JSONResponse(get_recovery_case(case_id))


@router.post("/api/recovery/cases/{case_id}/evidence")
async def add_recovery_evidence(case_id: int, request: Request) -> JSONResponse:
    if not row("SELECT id FROM recovery_cases WHERE id=?", (case_id,)):
        raise HTTPException(404, "Recovery case not found.")
    form = await request.form()
    uploads = [item for item in form.getlist("evidence_files") if hasattr(item, "filename") and item.filename]
    labels = [clean_text(item, 240) for item in form.getlist("evidence_label")]
    if not uploads:
        raise HTTPException(400, "Choose at least one evidence file.")
    for index, upload in enumerate(uploads):
        await save_upload(upload, case_id, "owner", labels[index] if index < len(labels) else "")
    execute("UPDATE recovery_cases SET updated_at=? WHERE id=?", (utc_now(), case_id))
    return JSONResponse(get_recovery_case(case_id))


@router.get("/api/recovery/files/{file_id}/download")
async def download_recovery_file(file_id: int) -> FileResponse:
    item = row("SELECT * FROM recovery_files WHERE id=?", (file_id,))
    if not item:
        raise HTTPException(404, "Recovery file not found.")
    upload_dir = user_upload_dir()
    path = (upload_dir / item["stored_name"]).resolve()
    if path.parent != upload_dir.resolve() or not path.exists():
        raise HTTPException(404, "The stored recovery file is unavailable.")
    return FileResponse(path, media_type=item.get("content_type") or "application/octet-stream", filename=item["original_name"])


@router.post("/api/recovery/contacts/{contact_id}/responses")
async def record_manual_response(contact_id: int, request: Request) -> JSONResponse:
    contact = row("SELECT * FROM recovery_contacts WHERE id=?", (contact_id,))
    if not contact:
        raise HTTPException(404, "Recovery contact not found.")
    form = await request.form()
    body = clean_text(form.get("body"), 20000)
    uploads = [item for item in form.getlist("response_files") if hasattr(item, "filename") and item.filename]
    if not body and not uploads:
        raise HTTPException(400, "Enter the response or attach a received file.")
    buffered_files: list[tuple[str, str, bytes]] = []
    for upload in uploads:
        content = await upload.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(413, f"{upload.filename} is larger than 20 MB.")
        buffered_files.append((Path(upload.filename or "received-file").name, upload.content_type or "application/octet-stream", content))
    case = await process_inbound_message(contact, body, buffered_files)
    return JSONResponse(case)


@router.post("/api/recovery/messages/{message_id}/send")
async def approve_recovery_message(message_id: int, request: Request) -> JSONResponse:
    message = row("SELECT * FROM recovery_messages WHERE id=?", (message_id,))
    if not message:
        raise HTTPException(404, "Recovery message not found.")
    if message["direction"] != "outbound" or message["status"] not in {"draft", "waiting_setup", "failed", "manual_required"}:
        raise HTTPException(400, "Only a draft or unsent outbound message can be sent.")
    case = row("SELECT * FROM recovery_cases WHERE id=?", (message["case_id"],))
    contact = row("SELECT * FROM recovery_contacts WHERE id=?", (message["contact_id"],))
    if not case or not contact:
        raise HTTPException(404, "Recovery case or contact not found.")
    body = message["body"]
    if request.headers.get("content-type", "").startswith("application/json"):
        payload = await request.json()
        submitted = remove_emoji_and_emdash(clean_text(payload.get("message"), 12000))
        if submitted:
            body = submitted
    await ensure_outbound_message_safe(body, case, contact)
    status, provider_result = await dispatch_message(case, contact, body, case_owner_files(case["id"]), False)
    execute(
        "UPDATE recovery_messages SET body=?, status=?, external_id=?, delivery_note=? WHERE id=?",
        (body, status, provider_result if status == "sent" else None, None if status == "sent" else provider_result, message_id),
    )
    execute(
        "UPDATE recovery_contacts SET status=?, last_contacted_at=?, updated_at=? WHERE id=?",
        ("contacted" if status == "sent" else status, utc_now() if status == "sent" else contact.get("last_contacted_at"), utc_now(), contact["id"]),
    )
    if case["status"] == "needs_owner":
        execute("UPDATE recovery_cases SET status='outreach_active', updated_at=? WHERE id=?", (utc_now(), case["id"]))
    return JSONResponse(get_recovery_case(case["id"]))


@router.post("/api/recovery/contacts/{contact_id}/reply")
async def send_owner_recovery_reply(contact_id: int, request: Request) -> JSONResponse:
    contact = row("SELECT * FROM recovery_contacts WHERE id=?", (contact_id,))
    if not contact:
        raise HTTPException(404, "Recovery contact not found.")
    case = row("SELECT * FROM recovery_cases WHERE id=?", (contact["case_id"],))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    files: list[dict[str, Any]] = []
    if request.headers.get("content-type", "").startswith("multipart/form-data"):
        form = await request.form()
        body = remove_emoji_and_emdash(clean_text(form.get("message"), 12000))
        uploads = [item for item in form.getlist("evidence_files") if hasattr(item, "filename") and item.filename]
        labels = [clean_text(item, 240) for item in form.getlist("evidence_label")]
        for index, upload in enumerate(uploads):
            files.append(await save_upload(upload, case["id"], "owner", labels[index] if index < len(labels) else "", contact_id=contact["id"]))
    else:
        payload = await request.json()
        body = remove_emoji_and_emdash(clean_text(payload.get("message"), 12000))
    if len(body) < 2:
        raise HTTPException(400, "Enter a reply before sending.")
    await ensure_outbound_message_safe(body, case, contact)
    await send_and_record(case, contact, body, sender_type="owner", files=files, initial=False)
    return JSONResponse(get_recovery_case(case["id"]))


@router.post("/api/recovery/cases/{case_id}/cancel")
async def cancel_recovery_case(case_id: int, request: Request) -> JSONResponse:
    case = row("SELECT * FROM recovery_cases WHERE id=?", (case_id,))
    if not case:
        raise HTTPException(404, "Recovery case not found.")
    if case["status"] in {"recovered", "closed"}:
        raise HTTPException(400, "This recovery case is already closed.")
    payload = await request.json()
    reason = clean_text(payload.get("reason"), 1200)
    if len(reason) < 3:
        raise HTTPException(400, "Add a short reason for closing this recovery case.")
    contacts = rows("SELECT * FROM recovery_contacts WHERE case_id=? ORDER BY created_at", (case_id,))
    for contact in contacts:
        had_conversation = row(
            "SELECT id FROM recovery_messages WHERE contact_id=? AND direction='outbound' LIMIT 1",
            (contact["id"],),
        )
        if not had_conversation:
            continue
        already_drafted = row(
            "SELECT id FROM recovery_messages WHERE contact_id=? AND direction='outbound' AND classification='case_closure' AND status='draft' LIMIT 1",
            (contact["id"],),
        )
        if already_drafted:
            continue
        closing_message = await generate_closing_message(case, contact, reason)
        insert_message(case_id, contact["id"], "outbound", "agent", closing_message, "draft", classification="case_closure")
    execute(
        "UPDATE recovery_contacts SET status='closed', updated_at=? WHERE case_id=? AND status NOT IN ('success')",
        (utc_now(), case_id),
    )
    execute(
        "UPDATE recovery_cases SET status='closed', cancellation_reason=?, updated_at=? WHERE id=?",
        (reason, utc_now(), case_id),
    )
    notify_owner("Recovery case closed", "Retayn drafted closing messages for any contacts already involved.")
    return JSONResponse(get_recovery_case(case_id))


@router.post("/api/recovery/cases/{case_id}/complete")
async def complete_recovery_case(case_id: int) -> JSONResponse:
    if not row("SELECT id FROM recovery_cases WHERE id=?", (case_id,)):
        raise HTTPException(404, "Recovery case not found.")
    execute("UPDATE recovery_cases SET status='recovered', updated_at=? WHERE id=?", (utc_now(), case_id))
    notify_owner("Recovery case completed", "The recovered access and files are recorded in Retayn.")
    return JSONResponse(get_recovery_case(case_id))


async def telegram_download_file(file_id: str, suggested_name: str) -> tuple[str, str, bytes] | None:
    token = recovery_config()["telegram_bot_token"]
    if not token:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            info = await client.get(f"https://api.telegram.org/bot{token}/getFile", params={"file_id": file_id})
            info.raise_for_status()
            file_path = info.json().get("result", {}).get("file_path")
            if not file_path:
                return None
            response = await client.get(f"https://api.telegram.org/file/bot{token}/{file_path}")
            response.raise_for_status()
        name = Path(suggested_name or file_path).name
        return name, mimetypes.guess_type(name)[0] or "application/octet-stream", response.content
    except Exception:
        logging.exception("Could not download Telegram recovery file")
        return None


@router.post("/webhooks/recovery/{tenant_token}/telegram")
async def telegram_recovery_webhook(tenant_token: str, request: Request) -> JSONResponse:
    cfg = recovery_config()
    supplied_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if cfg["telegram_webhook_secret"] and not hmac.compare_digest(supplied_secret, cfg["telegram_webhook_secret"]):
        raise HTTPException(403, "Invalid Telegram webhook secret.")
    payload = await request.json()
    message = payload.get("message") or payload.get("edited_message") or {}
    chat_id = str((message.get("chat") or {}).get("id") or "")
    if not chat_id:
        return JSONResponse({"ok": True, "ignored": True})
    contact = row(
        "SELECT * FROM recovery_contacts WHERE channel='telegram' AND (address=? OR external_thread_id=?) ORDER BY updated_at DESC LIMIT 1",
        (chat_id, chat_id),
    )
    if not contact:
        return JSONResponse({"ok": True, "ignored": True})
    body = clean_text(message.get("text") or message.get("caption"), 20000)
    received: list[tuple[str, str, bytes]] = []
    document = message.get("document") or {}
    if document.get("file_id"):
        downloaded = await telegram_download_file(str(document["file_id"]), str(document.get("file_name") or "telegram-file"))
        if downloaded:
            received.append(downloaded)
    await process_inbound_message(contact, body, received, external_id=str(message.get("message_id") or ""))
    return JSONResponse({"ok": True})


@router.get("/webhooks/recovery/{tenant_token}/whatsapp")
async def verify_whatsapp_recovery_webhook(tenant_token: str, request: Request) -> PlainTextResponse:
    cfg = recovery_config()
    mode = request.query_params.get("hub.mode", "")
    token = request.query_params.get("hub.verify_token", "")
    challenge = request.query_params.get("hub.challenge", "")
    if mode == "subscribe" and cfg["whatsapp_verify_token"] and hmac.compare_digest(token, cfg["whatsapp_verify_token"]):
        return PlainTextResponse(challenge)
    raise HTTPException(403, "WhatsApp webhook verification failed.")


def verify_whatsapp_signature(raw_body: bytes, signature: str, secret: str) -> bool:
    if not secret:
        return True
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature[7:], expected)


async def whatsapp_download_media(media: dict[str, Any]) -> tuple[str, str, bytes] | None:
    cfg = recovery_config()
    media_id = str(media.get("id") or "")
    if not media_id or not cfg["whatsapp_token"]:
        return None
    try:
        headers = {"Authorization": f"Bearer {cfg['whatsapp_token']}"}
        async with httpx.AsyncClient(timeout=30) as client:
            info = await client.get(
                f"https://graph.facebook.com/{cfg['whatsapp_api_version']}/{media_id}",
                headers=headers,
            )
            info.raise_for_status()
            url = info.json().get("url")
            if not url:
                return None
            response = await client.get(url, headers=headers)
            response.raise_for_status()
        content_type = str(media.get("mime_type") or response.headers.get("content-type") or "application/octet-stream")
        suffix = mimetypes.guess_extension(content_type.split(";", 1)[0]) or ""
        name = clean_text(media.get("filename"), 240) or f"whatsapp-file{suffix}"
        return Path(name).name, content_type, response.content
    except Exception:
        logging.exception("Could not download WhatsApp recovery file")
        return None


@router.post("/webhooks/recovery/{tenant_token}/whatsapp")
async def whatsapp_recovery_webhook(tenant_token: str, request: Request) -> JSONResponse:
    raw_body = await request.body()
    cfg = recovery_config()
    if not verify_whatsapp_signature(raw_body, request.headers.get("X-Hub-Signature-256", ""), cfg["whatsapp_app_secret"]):
        raise HTTPException(403, "Invalid WhatsApp webhook signature.")
    payload = json.loads(raw_body or b"{}")
    incoming: list[dict[str, Any]] = []
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            incoming.extend((change.get("value") or {}).get("messages") or [])
    for message in incoming:
        sender = normalize_address("whatsapp", str(message.get("from") or ""))
        contact = row(
            "SELECT * FROM recovery_contacts WHERE channel='whatsapp' AND address=? ORDER BY updated_at DESC LIMIT 1",
            (sender,),
        )
        if not contact:
            continue
        message_type = str(message.get("type") or "")
        body = clean_text((message.get("text") or {}).get("body"), 20000)
        received: list[tuple[str, str, bytes]] = []
        if message_type in {"document", "image", "audio", "video"}:
            media = message.get(message_type) or {}
            body = body or clean_text(media.get("caption"), 20000)
            downloaded = await whatsapp_download_media(media)
            if downloaded:
                received.append(downloaded)
        await process_inbound_message(contact, body, received, external_id=str(message.get("id") or ""))
    return JSONResponse({"ok": True})
