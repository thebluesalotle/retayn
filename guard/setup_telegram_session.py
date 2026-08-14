import asyncio
import os
from pathlib import Path

from telethon import TelegramClient


BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def env_value(name: str) -> str:
    if ENV_PATH.exists():
        for raw_line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            if key.strip() == name:
                return value.strip().strip('"').strip("'")
    return os.getenv(name, "").strip()


async def main() -> None:
    api_id = env_value("RECOVERY_TELEGRAM_MTPROTO_API_ID")
    api_hash = env_value("RECOVERY_TELEGRAM_MTPROTO_API_HASH")
    session_path = env_value("RECOVERY_TELEGRAM_MTPROTO_SESSION_PATH") or "recovery_telegram.session"
    if not api_id or not api_hash:
        raise SystemExit("Set RECOVERY_TELEGRAM_MTPROTO_API_ID and RECOVERY_TELEGRAM_MTPROTO_API_HASH in guard/.env first.")
    session_file = Path(session_path)
    if not session_file.is_absolute():
        session_file = BASE_DIR / session_file
    client = TelegramClient(str(session_file), int(api_id), api_hash)
    await client.start()
    me = await client.get_me()
    await client.disconnect()
    print(f"Telegram recovery agent signed in as {getattr(me, 'username', None) or getattr(me, 'phone', 'account')}.")
    print(f"Session saved at {session_file}")


if __name__ == "__main__":
    asyncio.run(main())
