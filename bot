"""
================================================================================
 GROUP SECURITY BOT — single-file Pyrogram + MongoDB Telegram bot
================================================================================

Features:
  - Join-request pipeline: ban check -> imposter check -> CAPTCHA -> approve
  - Ban / unban / banned-list (with pagination)
  - Mute / unmute (real ChatPermissions restrictions)
  - Decline join requests / declined-list (with pagination)
  - Custom bot-admin system (owner + admins) stored in MongoDB
  - CAPTCHA verification via private message + inline button challenge
  - Imposter / impersonation detection for changed username/name
  - Inline keyboards, /start, /help
  - Robust error handling (RPCError, FloodWait, etc.)

Run:
    python bot.py

Env vars (see bottom of README section / CONFIG below):
    API_ID, API_HASH, BOT_TOKEN, MONGO_URI, OWNER_ID
================================================================================
"""

import os
import html
import random
import logging
import asyncio
import datetime
from typing import Optional, List, Dict, Any, Tuple

from pyrogram import Client, filters
from pyrogram.types import (
    Message,
    CallbackQuery,
    ChatJoinRequest,
    User,
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    ChatPermissions,
)
from pyrogram.enums import ChatMemberStatus, ParseMode
from pyrogram.errors import (
    RPCError,
    FloodWait,
    UserNotParticipant,
    ChatAdminRequired,
    PeerIdInvalid,
    UsernameNotOccupied,
    UserIsBlocked,
    InputUserDeactivated,
    ChatWriteForbidden,
    UserAlreadyParticipant,
    UserIdInvalid,
)

import motor.motor_asyncio
from pymongo import ReturnDocument

# ==============================================================================
# CONFIGURATION
# ==============================================================================

API_ID = int(os.getenv("API_ID", "8045459"))
API_HASH = os.getenv("API_HASH", "e6d1f09120e17a4372fe022dde88511b")
BOT_TOKEN = os.getenv("BOT_TOKEN", "8244250546:AAEuPSONBf-pnA-pdB3ceNvIqWjRB30eH1w")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://zewdatabase:ijoXgdmQ0NCyg9DO@zewgame.urb3i.mongodb.net/ontap?retryWrites=true&w=majority")
OWNER_ID = int(os.getenv("OWNER_ID", "8671058334"))

# Optional tuning knobs (all overridable via env vars)
CAPTCHA_TIMEOUT_SECONDS = int(os.getenv("CAPTCHA_TIMEOUT_SECONDS", "300"))       # 5 minutes
CAPTCHA_MAX_ATTEMPTS = int(os.getenv("CAPTCHA_MAX_ATTEMPTS", "3"))
CAPTCHA_SWEEP_INTERVAL = int(os.getenv("CAPTCHA_SWEEP_INTERVAL", "60"))         # background cleanup cadence
PAGE_SIZE = int(os.getenv("PAGE_SIZE", "8"))                                     # items per page in lists

if not all([API_ID, API_HASH, BOT_TOKEN, MONGO_URI, OWNER_ID]):
    raise RuntimeError(
        "Missing required configuration. Please set API_ID, API_HASH, BOT_TOKEN, "
        "MONGO_URI and OWNER_ID as environment variables."
    )

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logging.getLogger("pyrogram").setLevel(logging.WARNING)
logger = logging.getLogger("security_bot")

# ==============================================================================
# PYROGRAM CLIENT
# ==============================================================================

app = Client(
    "group_security_bot",
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN,
    parse_mode=ParseMode.HTML,
)

# ==============================================================================
# MONGODB
# ==============================================================================

mongo_client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_URI)
db = mongo_client.get_database("group_security_bot_db")

admins_coll = db.get_collection("admins")
banned_coll = db.get_collection("banned_users")
muted_coll = db.get_collection("muted_users")
declined_coll = db.get_collection("declined_users")
join_requests_coll = db.get_collection("join_requests")
captcha_coll = db.get_collection("captcha_sessions")
protected_coll = db.get_collection("protected_users")
settings_coll = db.get_collection("settings")
userdata_coll = db.get_collection("user_identity_cache")  # for imposter detection


async def ensure_indexes() -> None:
    """Create indexes used by the bot. Safe to call every startup."""
    await admins_coll.create_index("user_id", unique=True)
    await banned_coll.create_index([("chat_id", 1), ("user_id", 1)], unique=True)
    await muted_coll.create_index([("chat_id", 1), ("user_id", 1)], unique=True)
    await declined_coll.create_index([("chat_id", 1), ("user_id", 1)])
    await join_requests_coll.create_index([("chat_id", 1), ("user_id", 1)], unique=True)
    await captcha_coll.create_index([("chat_id", 1), ("user_id", 1)], unique=True)
    await captcha_coll.create_index("expires_at")
    await protected_coll.create_index([("chat_id", 1), ("user_id", 1)], unique=True)
    await settings_coll.create_index("chat_id", unique=True)
    await userdata_coll.create_index("user_id", unique=True)


# ==============================================================================
# SMALL HELPERS
# ==============================================================================

def now_utc() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def fmt_dt(dt: Optional[datetime.datetime]) -> str:
    if not dt:
        return "Unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def mention_html(user_id: int, name: str) -> str:
    safe_name = html.escape(name or "User")
    return f"<a href='tg://user?id={user_id}'>{safe_name}</a>"


def full_name(user: User) -> str:
    return f"{user.first_name or ''} {user.last_name or ''}".strip() or "User"


async def safe_call(coro, *, default=None, action: str = "operation"):
    """Run a Pyrogram coroutine with unified error handling. Returns default on failure."""
    try:
        return await coro
    except FloodWait as e:
        logger.warning("FloodWait during %s: sleeping %ss", action, e.value)
        await asyncio.sleep(e.value)
        try:
            return await coro
        except RPCError as e2:
            logger.error("RPCError after FloodWait retry during %s: %s", action, e2)
            return default
    except ChatAdminRequired:
        logger.error("Missing admin rights for: %s", action)
        return default
    except (PeerIdInvalid, UserIdInvalid, UsernameNotOccupied):
        logger.warning("Invalid peer/user during %s", action)
        return default
    except (UserIsBlocked, InputUserDeactivated, ChatWriteForbidden):
        logger.info("Cannot message user during %s (blocked/deactivated/forbidden)", action)
        return default
    except UserAlreadyParticipant:
        return default
    except RPCError as e:
        logger.error("RPCError during %s: %s", action, e)
        return default
    except Exception as e:  # noqa: BLE001 - top level safety net
        logger.exception("Unexpected error during %s: %s", action, e)
        return default


def parse_target_user_id(message: Message) -> Optional[int]:
    """Extract a target user id from a reply or a command argument."""
    if message.reply_to_message and message.reply_to_message.from_user:
        return message.reply_to_message.from_user.id
    if len(message.command) > 1:
        arg = message.command[1]
        if arg.isdigit() or (arg.startswith("-") and arg[1:].isdigit()):
            return int(arg)
    return None


def get_reason(message: Message, start_index: int = 1) -> Optional[str]:
    """Extract a free-text reason following a command, ignoring a leading user-id arg."""
    parts = message.command[start_index:]
    if parts and (parts[0].isdigit() or (parts[0].startswith("-") and parts[0][1:].isdigit())):
        parts = parts[1:]
    return " ".join(parts).strip() or None


# ==============================================================================
# PERMISSION SYSTEM
# ==============================================================================

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_ID


async def is_bot_admin(user_id: int) -> bool:
    if is_owner(user_id):
        return True
    doc = await admins_coll.find_one({"user_id": user_id})
    return doc is not None


async def is_group_admin(client: Client, chat_id: int, user_id: int) -> bool:
    member = await safe_call(
        client.get_chat_member(chat_id, user_id), action="get_chat_member"
    )
    if not member:
        return False
    return member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)


async def is_group_owner(client: Client, chat_id: int, user_id: int) -> bool:
    member = await safe_call(
        client.get_chat_member(chat_id, user_id), action="get_chat_member"
    )
    if not member:
        return False
    return member.status == ChatMemberStatus.OWNER


async def is_authorized(client: Client, message: Message) -> bool:
    """A user may run moderation commands if they are a bot-admin/owner OR a
    Telegram admin of the group the command is used in."""
    user_id = message.from_user.id if message.from_user else None
    if user_id is None:
        return False
    if await is_bot_admin(user_id):
        return True
    if message.chat and message.chat.type.name in ("GROUP", "SUPERGROUP"):
        return await is_group_admin(client, message.chat.id, user_id)
    return False


async def has_required_permissions(client: Client, chat_id: int, *, need: str = "restrict") -> bool:
    """Check that the bot itself has the admin permission it needs."""
    me = await safe_call(client.get_me(), action="get_me")
    if not me:
        return False
    member = await safe_call(
        client.get_chat_member(chat_id, me.id), action="get_bot_member"
    )
    if not member or member.status != ChatMemberStatus.ADMINISTRATOR:
        return False
    privileges = member.privileges
    if not privileges:
        return False
    if need == "restrict":
        return bool(privileges.can_restrict_members)
    if need == "invite":
        return bool(privileges.can_invite_users)
    return True


async def can_manage_user(client: Client, chat_id: int, actor_id: int, target_id: int) -> Tuple[bool, str]:
    """Guard against an admin acting on the owner / a group owner / themselves."""
    if target_id == OWNER_ID:
        return False, "You cannot take action against the bot owner."
    if target_id == actor_id:
        return False, "You cannot take this action against yourself."
    me = await safe_call(client.get_me(), action="get_me")
    if me and target_id == me.id:
        return False, "I cannot take action against myself."
    if await is_group_owner(client, chat_id, target_id):
        if not is_owner(actor_id):
            return False, "You cannot take action against the group owner."
    return True, ""


# ==============================================================================
# SETTINGS
# ==============================================================================

DEFAULT_SETTINGS = {
    "captcha_enabled": True,
    "imposter_notify_admins": True,
    "auto_decline_high_risk": False,
}


async def get_settings(chat_id: int) -> dict:
    doc = await settings_coll.find_one({"chat_id": chat_id})
    if not doc:
        doc = {"chat_id": chat_id, **DEFAULT_SETTINGS}
        await settings_coll.insert_one(doc)
    return doc


# ==============================================================================
# BAN SYSTEM
# ==============================================================================

async def ban_user_db(chat_id: int, user_id: int, name: str, username: Optional[str],
                       banned_by: int, reason: Optional[str]) -> bool:
    existing = await banned_coll.find_one({"chat_id": chat_id, "user_id": user_id})
    if existing:
        return False
    await banned_coll.insert_one({
        "chat_id": chat_id,
        "user_id": user_id,
        "name": name,
        "username": username,
        "banned_by": banned_by,
        "reason": reason,
        "banned_at": now_utc(),
    })
    return True


async def unban_user_db(chat_id: int, user_id: int) -> bool:
    result = await banned_coll.delete_one({"chat_id": chat_id, "user_id": user_id})
    return result.deleted_count > 0


async def is_banned(chat_id: int, user_id: int) -> bool:
    doc = await banned_coll.find_one({"chat_id": chat_id, "user_id": user_id})
    return doc is not None


async def list_banned(chat_id: int, page: int) -> Tuple[List[dict], int]:
    total = await banned_coll.count_documents({"chat_id": chat_id})
    cursor = (
        banned_coll.find({"chat_id": chat_id})
        .sort("banned_at", -1)
        .skip(page * PAGE_SIZE)
        .limit(PAGE_SIZE)
    )
    items = await cursor.to_list(length=PAGE_SIZE)
    return items, total


@app.on_message(filters.command("ban") & filters.group)
async def cmd_ban(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply(
            "<b>Usage:</b> reply to a user with /ban [reason], or /ban &lt;user_id&gt; [reason]"
        )

    ok, err = await can_manage_user(client, message.chat.id, message.from_user.id, target_id)
    if not ok:
        return await message.reply(f"<b>{err}</b>")

    if not await has_required_permissions(client, message.chat.id, need="restrict"):
        return await message.reply(
            "<b>I need 'Ban/Restrict users' admin permission to do this.</b>"
        )

    reason = get_reason(message, start_index=1)

    target_user = await safe_call(client.get_users(target_id), action="get_users")
    name = full_name(target_user) if target_user else str(target_id)
    username = target_user.username if target_user else None

    inserted = await ban_user_db(message.chat.id, target_id, name, username, message.from_user.id, reason)
    if not inserted:
        return await message.reply("<b>This user is already banned.</b>")

    banned = await safe_call(
        client.ban_chat_member(message.chat.id, target_id), action="ban_chat_member"
    )
    if banned is None:
        await banned_coll.delete_one({"chat_id": message.chat.id, "user_id": target_id})
        return await message.reply(
            "<b>Failed to ban the user on Telegram. Check my admin permissions.</b>"
        )

    text = (
        f"<b>🔨 User Banned</b>\n"
        f"👤 <b>User:</b> {mention_html(target_id, name)}\n"
        f"🆔 <b>ID:</b> <code>{target_id}</code>\n"
        f"👮 <b>By:</b> {mention_html(message.from_user.id, full_name(message.from_user))}\n"
    )
    if reason:
        text += f"📝 <b>Reason:</b> {html.escape(reason)}\n"
    await message.reply(text)
    logger.info("User %s banned in chat %s by %s", target_id, message.chat.id, message.from_user.id)


@app.on_message(filters.command("unban") & filters.group)
async def cmd_unban(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply("<b>Usage:</b> reply to a user with /unban, or /unban &lt;user_id&gt;")

    removed = await unban_user_db(message.chat.id, target_id)
    if not removed:
        return await message.reply("<b>This user is not banned.</b>")

    await safe_call(client.unban_chat_member(message.chat.id, target_id), action="unban_chat_member")
    await message.reply(
        f"<b>✅ User Unbanned</b>\n🆔 <code>{target_id}</code>"
    )
    logger.info("User %s unbanned in chat %s by %s", target_id, message.chat.id, message.from_user.id)


@app.on_message(filters.command("banned") & filters.group)
async def cmd_banned(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")
    text, markup = await render_banned_page(message.chat.id, 0)
    await message.reply(text, reply_markup=markup)


async def render_banned_page(chat_id: int, page: int):
    items, total = await list_banned(chat_id, page)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if not items:
        return "<b>No banned users found.</b>", None
    lines = [f"<b>🚫 Banned Users ({total} total)</b>\n"]
    for doc in items:
        uname = f"@{doc['username']}" if doc.get("username") else "no username"
        lines.append(
            f"• {mention_html(doc['user_id'], doc.get('name', 'User'))} "
            f"(<code>{doc['user_id']}</code>, {uname})"
        )
    text = "\n".join(lines)
    buttons = []
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅ Prev", callback_data=f"banp:{chat_id}:{page-1}"))
    nav.append(InlineKeyboardButton(f"Page {page+1}/{total_pages}", callback_data="noop"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton("Next ➡", callback_data=f"banp:{chat_id}:{page+1}"))
    buttons.append(nav)
    buttons.append([InlineKeyboardButton("✖ Close", callback_data="close")])
    return text, InlineKeyboardMarkup(buttons)


@app.on_callback_query(filters.regex(r"^banp:(-?\d+):(\d+)$"))
async def cb_banned_page(client: Client, cq: CallbackQuery):
    chat_id, page = int(cq.matches[0].group(1)), int(cq.matches[0].group(2))
    if not await is_authorized(client, cq.message):
        return await cq.answer("Not authorized.", show_alert=True)
    text, markup = await render_banned_page(chat_id, page)
    await safe_call(cq.message.edit_text(text, reply_markup=markup), action="edit_banned_page")
    await cq.answer()


# ==============================================================================
# MUTE SYSTEM
# ==============================================================================

MUTED_PERMISSIONS = ChatPermissions(
    can_send_messages=False,
    can_send_audios=False,
    can_send_documents=False,
    can_send_photos=False,
    can_send_videos=False,
    can_send_video_notes=False,
    can_send_voice_notes=False,
    can_send_polls=False,
    can_send_other_messages=False,
    can_add_web_page_previews=False,
    can_change_info=False,
    can_invite_users=False,
    can_pin_messages=False,
)

UNMUTED_PERMISSIONS = ChatPermissions(
    can_send_messages=True,
    can_send_audios=True,
    can_send_documents=True,
    can_send_photos=True,
    can_send_videos=True,
    can_send_video_notes=True,
    can_send_voice_notes=True,
    can_send_polls=True,
    can_send_other_messages=True,
    can_add_web_page_previews=True,
    can_invite_users=True,
)


@app.on_message(filters.command("mute") & filters.group)
async def cmd_mute(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply("<b>Usage:</b> reply to a user with /mute, or /mute &lt;user_id&gt;")

    ok, err = await can_manage_user(client, message.chat.id, message.from_user.id, target_id)
    if not ok:
        return await message.reply(f"<b>{err}</b>")

    if await is_group_admin(client, message.chat.id, target_id):
        return await message.reply("<b>I cannot mute a group administrator.</b>")

    if not await has_required_permissions(client, message.chat.id, need="restrict"):
        return await message.reply("<b>I need 'Restrict members' admin permission to do this.</b>")

    existing = await muted_coll.find_one({"chat_id": message.chat.id, "user_id": target_id})
    if existing:
        return await message.reply("<b>This user is already muted.</b>")

    result = await safe_call(
        client.restrict_chat_member(message.chat.id, target_id, MUTED_PERMISSIONS),
        action="restrict_chat_member",
    )
    if result is None:
        return await message.reply("<b>Failed to mute the user. Check my admin permissions.</b>")

    target_user = await safe_call(client.get_users(target_id), action="get_users")
    name = full_name(target_user) if target_user else str(target_id)

    await muted_coll.insert_one({
        "chat_id": message.chat.id,
        "user_id": target_id,
        "name": name,
        "muted_by": message.from_user.id,
        "muted_at": now_utc(),
    })
    await message.reply(
        f"<b>🔇 User Muted</b>\n👤 {mention_html(target_id, name)}\n🆔 <code>{target_id}</code>"
    )
    logger.info("User %s muted in chat %s", target_id, message.chat.id)


@app.on_message(filters.command("unmute") & filters.group)
async def cmd_unmute(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply("<b>Usage:</b> reply to a user with /unmute, or /unmute &lt;user_id&gt;")

    existing = await muted_coll.find_one({"chat_id": message.chat.id, "user_id": target_id})
    if not existing:
        return await message.reply("<b>This user is not muted.</b>")

    result = await safe_call(
        client.restrict_chat_member(message.chat.id, target_id, UNMUTED_PERMISSIONS),
        action="unrestrict_chat_member",
    )
    await muted_coll.delete_one({"chat_id": message.chat.id, "user_id": target_id})
    if result is None:
        return await message.reply(
            "<b>Removed mute record, but I could not update Telegram permissions. Check my admin rights.</b>"
        )
    await message.reply(f"<b>🔊 User Unmuted</b>\n🆔 <code>{target_id}</code>")
    logger.info("User %s unmuted in chat %s", target_id, message.chat.id)


# ==============================================================================
# DECLINE JOIN REQUEST SYSTEM
# ==============================================================================

async def decline_request(client: Client, chat_id: int, user_id: int, name: str,
                           declined_by: int, reason: Optional[str] = None) -> bool:
    result = await safe_call(
        client.decline_chat_join_request(chat_id, user_id), action="decline_chat_join_request"
    )
    await join_requests_coll.update_one(
        {"chat_id": chat_id, "user_id": user_id},
        {"$set": {"status": "declined", "decided_at": now_utc(), "decided_by": declined_by}},
        upsert=True,
    )
    await declined_coll.insert_one({
        "chat_id": chat_id,
        "user_id": user_id,
        "name": name,
        "declined_by": declined_by,
        "reason": reason,
        "declined_at": now_utc(),
    })
    await captcha_coll.delete_one({"chat_id": chat_id, "user_id": user_id})
    return result is not None


@app.on_message(filters.command("decline") & filters.group)
async def cmd_decline(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply(
            "<b>Usage:</b> reply to the join-request notice with /decline, or /decline &lt;user_id&gt;"
        )

    pending = await join_requests_coll.find_one(
        {"chat_id": message.chat.id, "user_id": target_id, "status": "pending"}
    )
    if not pending:
        return await message.reply("<b>No pending join request found for this user.</b>")

    reason = get_reason(message, start_index=1)
    name = pending.get("name", str(target_id))
    await decline_request(client, message.chat.id, target_id, name, message.from_user.id, reason)
    await message.reply(f"<b>❌ Join request declined for</b> {mention_html(target_id, name)}")


@app.on_message(filters.command("declined") & filters.group)
async def cmd_declined(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")
    text, markup = await render_declined_page(message.chat.id, 0)
    await message.reply(text, reply_markup=markup)


async def render_declined_page(chat_id: int, page: int):
    total = await declined_coll.count_documents({"chat_id": chat_id})
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    cursor = (
        declined_coll.find({"chat_id": chat_id})
        .sort("declined_at", -1)
        .skip(page * PAGE_SIZE)
        .limit(PAGE_SIZE)
    )
    items = await cursor.to_list(length=PAGE_SIZE)
    if not items:
        return "<b>No declined join requests found.</b>", None
    lines = [f"<b>🚷 Declined Requests ({total} total)</b>\n"]
    for doc in items:
        lines.append(
            f"• {mention_html(doc['user_id'], doc.get('name', 'User'))} "
            f"(<code>{doc['user_id']}</code>) — {fmt_dt(doc.get('declined_at'))}"
        )
    text = "\n".join(lines)
    nav = []
    if page > 0:
        nav.append(InlineKeyboardButton("⬅ Prev", callback_data=f"decp:{chat_id}:{page-1}"))
    nav.append(InlineKeyboardButton(f"Page {page+1}/{total_pages}", callback_data="noop"))
    if page + 1 < total_pages:
        nav.append(InlineKeyboardButton("Next ➡", callback_data=f"decp:{chat_id}:{page+1}"))
    buttons = [nav, [InlineKeyboardButton("✖ Close", callback_data="close")]]
    return text, InlineKeyboardMarkup(buttons)


@app.on_callback_query(filters.regex(r"^decp:(-?\d+):(\d+)$"))
async def cb_declined_page(client: Client, cq: CallbackQuery):
    chat_id, page = int(cq.matches[0].group(1)), int(cq.matches[0].group(2))
    if not await is_authorized(client, cq.message):
        return await cq.answer("Not authorized.", show_alert=True)
    text, markup = await render_declined_page(chat_id, page)
    await safe_call(cq.message.edit_text(text, reply_markup=markup), action="edit_declined_page")
    await cq.answer()


# ==============================================================================
# ADMIN MANAGEMENT
# ==============================================================================

@app.on_message(filters.command("addadmin"))
async def cmd_addadmin(client: Client, message: Message):
    if not is_owner(message.from_user.id):
        return await message.reply("<b>Only the bot owner can add bot admins.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply("<b>Usage:</b> reply to a user with /addadmin, or /addadmin &lt;user_id&gt;")

    if target_id == OWNER_ID:
        return await message.reply("<b>The owner is already the highest authority.</b>")

    existing = await admins_coll.find_one({"user_id": target_id})
    if existing:
        return await message.reply("<b>This user is already a bot admin.</b>")

    target_user = await safe_call(client.get_users(target_id), action="get_users")
    if not target_user:
        return await message.reply("<b>Could not find this user. Provide a valid user ID or reply to them.</b>")

    await admins_coll.insert_one({
        "user_id": target_id,
        "username": target_user.username,
        "name": full_name(target_user),
        "added_by": message.from_user.id,
        "added_at": now_utc(),
    })
    await message.reply(f"<b>✅ Added bot admin:</b> {mention_html(target_id, full_name(target_user))}")


@app.on_message(filters.command("removeadmin"))
async def cmd_removeadmin(client: Client, message: Message):
    if not is_owner(message.from_user.id):
        return await message.reply("<b>Only the bot owner can remove bot admins.</b>")

    target_id = parse_target_user_id(message)
    if not target_id:
        return await message.reply("<b>Usage:</b> reply to a user with /removeadmin, or /removeadmin &lt;user_id&gt;")

    if target_id == OWNER_ID:
        return await message.reply("<b>The owner cannot be removed.</b>")

    result = await admins_coll.delete_one({"user_id": target_id})
    if result.deleted_count == 0:
        return await message.reply("<b>This user is not a bot admin.</b>")
    await message.reply(f"<b>✅ Removed bot admin:</b> <code>{target_id}</code>")


@app.on_message(filters.command("admins"))
async def cmd_admins(client: Client, message: Message):
    lines = [f"<b>👑 Owner:</b> <code>{OWNER_ID}</code>\n\n<b>🛡 Bot Admins:</b>"]
    cursor = admins_coll.find({}).sort("added_at", 1)
    admins = await cursor.to_list(length=200)
    if not admins:
        lines.append("<i>No additional bot admins.</i>")
    else:
        for doc in admins:
            uname = f"@{doc['username']}" if doc.get("username") else "no username"
            lines.append(f"• {mention_html(doc['user_id'], doc.get('name', 'Admin'))} ({uname})")
    await message.reply("\n".join(lines))


# ==============================================================================
# CAPTCHA VERIFICATION
# ==============================================================================

def generate_challenge() -> Tuple[str, str, List[str]]:
    """Return (question_text, correct_answer, [choice1..choice4]) for a simple
    randomized math challenge with 4 shuffled numeric choices."""
    a, b = random.randint(1, 9), random.randint(1, 9)
    op = random.choice(["+", "-"])
    if op == "-" and b > a:
        a, b = b, a
    answer = a + b if op == "+" else a - b
    question = f"What is {a} {op} {b} ?"
    choices = {str(answer)}
    while len(choices) < 4:
        delta = random.choice([-3, -2, -1, 1, 2, 3])
        candidate = answer + delta
        if candidate >= 0:
            choices.add(str(candidate))
    choice_list = list(choices)
    random.shuffle(choice_list)
    return question, str(answer), choice_list


async def create_captcha_session(chat_id: int, user: User) -> dict:
    question, answer, choices = generate_challenge()
    expires_at = now_utc() + datetime.timedelta(seconds=CAPTCHA_TIMEOUT_SECONDS)
    doc = {
        "chat_id": chat_id,
        "user_id": user.id,
        "name": full_name(user),
        "username": user.username,
        "question": question,
        "answer": answer,
        "choices": choices,
        "attempts": 0,
        "verified": False,
        "created_at": now_utc(),
        "expires_at": expires_at,
    }
    await captcha_coll.find_one_and_update(
        {"chat_id": chat_id, "user_id": user.id},
        {"$set": doc},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return doc


def captcha_keyboard(chat_id: int, user_id: int, choices: List[str]) -> InlineKeyboardMarkup:
    rows = []
    row = []
    for i, choice in enumerate(choices, 1):
        row.append(InlineKeyboardButton(choice, callback_data=f"cap:{chat_id}:{user_id}:{choice}"))
        if i % 2 == 0:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    return InlineKeyboardMarkup(rows)


async def send_captcha(client: Client, chat_id: int, chat_title: str, user: User) -> bool:
    doc = await create_captcha_session(chat_id, user)
    text = (
        f"<b>🔐 Verification Required</b>\n\n"
        f"To join <b>{html.escape(chat_title)}</b>, please solve this quick check "
        f"within {CAPTCHA_TIMEOUT_SECONDS // 60} minutes:\n\n"
        f"<b>{doc['question']}</b>"
    )
    sent = await safe_call(
        client.send_message(
            user.id, text, reply_markup=captcha_keyboard(chat_id, user.id, doc["choices"])
        ),
        action="send_captcha_pm",
    )
    return sent is not None


@app.on_callback_query(filters.regex(r"^cap:(-?\d+):(\d+):(.+)$"))
async def cb_captcha_answer(client: Client, cq: CallbackQuery):
    chat_id = int(cq.matches[0].group(1))
    user_id = int(cq.matches[0].group(2))
    chosen = cq.matches[0].group(3)

    if cq.from_user.id != user_id:
        return await cq.answer("This verification isn't for you.", show_alert=True)

    session = await captcha_coll.find_one({"chat_id": chat_id, "user_id": user_id})
    if not session:
        return await cq.answer("This verification session has expired or was already used.", show_alert=True)

    if session.get("verified"):
        return await cq.answer("You are already verified.", show_alert=True)

    if now_utc() > session["expires_at"].replace(tzinfo=datetime.timezone.utc):
        await captcha_coll.delete_one({"_id": session["_id"]})
        await safe_call(cq.message.edit_text("<b>⌛ This verification has expired.</b>"), action="edit_expired")
        return await cq.answer("Expired. Please request to join again.", show_alert=True)

    if chosen != session["answer"]:
        attempts = session.get("attempts", 0) + 1
        if attempts >= CAPTCHA_MAX_ATTEMPTS:
            await captcha_coll.delete_one({"_id": session["_id"]})
            name = session.get("name", str(user_id))
            await decline_request(client, chat_id, user_id, name, OWNER_ID, reason="Failed CAPTCHA")
            await safe_call(
                cq.message.edit_text(
                    "<b>❌ Verification failed too many times. Your join request was declined.</b>"
                ),
                action="edit_failed",
            )
            return await cq.answer("Verification failed. Request declined.", show_alert=True)
        await captcha_coll.update_one({"_id": session["_id"]}, {"$set": {"attempts": attempts}})
        remaining = CAPTCHA_MAX_ATTEMPTS - attempts
        return await cq.answer(f"Incorrect. {remaining} attempt(s) left.", show_alert=True)

    # Correct answer -> mark verified and approve the join request.
    await captcha_coll.update_one({"_id": session["_id"]}, {"$set": {"verified": True}})
    approved = await safe_call(
        client.approve_chat_join_request(chat_id, user_id), action="approve_chat_join_request"
    )
    await join_requests_coll.update_one(
        {"chat_id": chat_id, "user_id": user_id},
        {"$set": {"status": "approved" if approved is not None else "verify_failed_approve",
                   "decided_at": now_utc()}},
        upsert=True,
    )
    await captcha_coll.delete_one({"_id": session["_id"]})

    if approved is not None:
        await safe_call(
            cq.message.edit_text("<b>✅ Verified! Your join request has been approved. Welcome!</b>"),
            action="edit_verified",
        )
        await cq.answer("Verified! You're in.")
    else:
        await safe_call(
            cq.message.edit_text(
                "<b>✅ Verified, but I could not auto-approve your request. "
                "An admin will let you in shortly.</b>"
            ),
            action="edit_verified_no_approve",
        )
        await cq.answer("Verified, awaiting admin approval.")


async def captcha_sweeper() -> None:
    """Background loop: periodically decline join requests whose CAPTCHA
    session has expired without verification."""
    while True:
        try:
            cursor = captcha_coll.find({"verified": False, "expires_at": {"$lt": now_utc()}})
            expired = await cursor.to_list(length=500)
            for doc in expired:
                await decline_request(
                    app, doc["chat_id"], doc["user_id"], doc.get("name", str(doc["user_id"])),
                    OWNER_ID, reason="CAPTCHA expired",
                )
                logger.info(
                    "Auto-declined expired CAPTCHA for user %s in chat %s",
                    doc["user_id"], doc["chat_id"],
                )
        except Exception:  # noqa: BLE001
            logger.exception("Error in captcha sweeper loop")
        await asyncio.sleep(CAPTCHA_SWEEP_INTERVAL)


# ==============================================================================
# IMPOSTER / IMPERSONATION DETECTION
# (adapted from the reference imposter.py: detects when a known user's
#  username/first name/last name changes, and flags admins whose identity
#  is being mimicked by a newcomer.)
# ==============================================================================

async def get_cached_identity(user_id: int) -> Optional[dict]:
    return await userdata_coll.find_one({"user_id": user_id})


async def upsert_identity(user_id: int, username: Optional[str], first_name: Optional[str],
                           last_name: Optional[str]) -> None:
    await userdata_coll.update_one(
        {"user_id": user_id},
        {"$set": {
            "user_id": user_id,
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "updated_at": now_utc(),
        }},
        upsert=True,
    )


async def add_protected_user(chat_id: int, user: User) -> None:
    await protected_coll.update_one(
        {"chat_id": chat_id, "user_id": user.id},
        {"$set": {
            "chat_id": chat_id,
            "user_id": user.id,
            "username": user.username,
            "name": full_name(user),
        }},
        upsert=True,
    )


async def is_impersonating_protected(chat_id: int, candidate_username: Optional[str],
                                      candidate_name: str, candidate_id: int) -> Optional[dict]:
    """Return the protected-user doc being impersonated, if any."""
    cursor = protected_coll.find({"chat_id": chat_id})
    protected_list = await cursor.to_list(length=500)
    cand_uname = (candidate_username or "").lower().strip()
    cand_name = candidate_name.lower().strip()
    for p in protected_list:
        if p["user_id"] == candidate_id:
            continue
        p_uname = (p.get("username") or "").lower().strip()
        p_name = (p.get("name") or "").lower().strip()
        if cand_uname and p_uname and cand_uname == p_uname:
            return p
        if cand_name and p_name and cand_name == p_name:
            return p
    return None


@app.on_message(filters.group & ~filters.bot & ~filters.via_bot, group=69)
async def imposter_watch(client: Client, message: Message):
    if message.sender_chat or not message.from_user:
        return
    user = message.from_user
    settings = await get_settings(message.chat.id)

    cached = await get_cached_identity(user.id)
    if not cached:
        await upsert_identity(user.id, user.username, user.first_name, user.last_name)
        return

    changed_msg = ""
    if cached.get("username") != user.username:
        before = f"@{cached['username']}" if cached.get("username") else "NO USERNAME"
        after = f"@{user.username}" if user.username else "NO USERNAME"
        changed_msg += f"\n🐻 <b>Username changed:</b> {html.escape(before)} → {html.escape(after)}"
    if cached.get("first_name") != user.first_name:
        changed_msg += (
            f"\n🪧 <b>First name changed:</b> "
            f"{html.escape(cached.get('first_name') or 'NONE')} → {html.escape(user.first_name or 'NONE')}"
        )
    if cached.get("last_name") != user.last_name:
        changed_msg += (
            f"\n🪧 <b>Last name changed:</b> "
            f"{html.escape(cached.get('last_name') or 'NONE')} → {html.escape(user.last_name or 'NONE')}"
        )

    if changed_msg:
        text = (
            f"<b>🔓 Identity Change Detected</b>\n"
            f"👤 {mention_html(user.id, full_name(user))}\n"
            f"🆔 <code>{user.id}</code>{changed_msg}"
        )
        await safe_call(message.reply(text), action="reply_imposter_notice")
        await upsert_identity(user.id, user.username, user.first_name, user.last_name)

    # Check whether this user is impersonating a protected admin's name/username.
    impersonated = await is_impersonating_protected(message.chat.id, user.username, full_name(user), user.id)
    if impersonated and settings.get("imposter_notify_admins", True):
        alert = (
            f"<b>⚠️ Possible Impersonation</b>\n"
            f"{mention_html(user.id, full_name(user))} (<code>{user.id}</code>) appears to be "
            f"mimicking protected user <b>{html.escape(impersonated.get('name', ''))}</b>."
        )
        await safe_call(message.reply(alert), action="reply_impersonation_alert")


@app.on_message(filters.command("imposter") & filters.group)
async def cmd_imposter(client: Client, message: Message):
    if not await is_authorized(client, message):
        return await message.reply("<b>You are not authorized to use this command.</b>")
    if len(message.command) == 1:
        return await message.reply(
            "<b>Usage:</b> /imposter protect (reply to a user) — marks them as protected\n"
            "/imposter unprotect &lt;user_id&gt; — removes protection"
        )
    sub = message.command[1].lower()
    if sub == "protect":
        target_id = parse_target_user_id(message)
        if not target_id:
            return await message.reply("<b>Reply to the user you want to protect.</b>")
        target_user = await safe_call(client.get_users(target_id), action="get_users")
        if not target_user:
            return await message.reply("<b>Could not resolve that user.</b>")
        await add_protected_user(message.chat.id, target_user)
        await message.reply(f"<b>🛡 Now protecting</b> {mention_html(target_id, full_name(target_user))}")
    elif sub == "unprotect":
        target_id = parse_target_user_id(message)
        if not target_id:
            return await message.reply("<b>Usage:</b> /imposter unprotect &lt;user_id&gt;")
        await protected_coll.delete_one({"chat_id": message.chat.id, "user_id": target_id})
        await message.reply("<b>Protection removed.</b>")
    else:
        await message.reply("<b>Unknown sub-command. Use protect/unprotect.</b>")


# ==============================================================================
# JOIN REQUEST PIPELINE
# ==============================================================================

@app.on_chat_join_request()
async def handle_join_request(client: Client, request: ChatJoinRequest):
    chat = request.chat
    user = request.from_user
    if not user:
        return

    logger.info("Join request: user=%s chat=%s", user.id, chat.id)

    await join_requests_coll.update_one(
        {"chat_id": chat.id, "user_id": user.id},
        {"$set": {
            "chat_id": chat.id,
            "user_id": user.id,
            "name": full_name(user),
            "username": user.username,
            "status": "pending",
            "requested_at": now_utc(),
        }},
        upsert=True,
    )

    # 1) Banned users are declined immediately.
    if await is_banned(chat.id, user.id):
        await decline_request(client, chat.id, user.id, full_name(user), OWNER_ID, reason="User is banned")
        logger.info("Declined banned user %s for chat %s", user.id, chat.id)
        return

    # 2) Imposter / impersonation check against protected users of this chat.
    impersonated = await is_impersonating_protected(chat.id, user.username, full_name(user), user.id)
    settings = await get_settings(chat.id)
    if impersonated:
        alert = (
            f"<b>⚠️ High-risk join request</b>\n"
            f"{mention_html(user.id, full_name(user))} (<code>{user.id}</code>) may be impersonating "
            f"<b>{html.escape(impersonated.get('name', ''))}</b>."
        )
        await safe_call(client.send_message(chat.id, alert), action="notify_group_imposter")
        if settings.get("auto_decline_high_risk"):
            await decline_request(
                client, chat.id, user.id, full_name(user), OWNER_ID, reason="High-risk impersonation"
            )
            return

    # 3) CAPTCHA verification (unless disabled for this chat).
    if settings.get("captcha_enabled", True):
        delivered = await send_captcha(client, chat.id, chat.title or str(chat.id), user)
        if not delivered:
            # Could not DM the user (they haven't started the bot). Leave request
            # pending and notify the group admins so they can review manually.
            await safe_call(
                client.send_message(
                    chat.id,
                    f"<b>ℹ️ Could not send CAPTCHA to</b> {mention_html(user.id, full_name(user))} "
                    f"<b>(they haven't started me in PM). Their request stays pending for manual review.</b>",
                ),
                action="notify_captcha_undeliverable",
            )
        return

    # 4) CAPTCHA disabled -> approve directly.
    approved = await safe_call(
        client.approve_chat_join_request(chat.id, user.id), action="approve_chat_join_request_direct"
    )
    await join_requests_coll.update_one(
        {"chat_id": chat.id, "user_id": user.id},
        {"$set": {"status": "approved" if approved is not None else "approve_failed", "decided_at": now_utc()}},
    )


# ==============================================================================
# GENERAL COMMANDS: /start /help
# ==============================================================================

START_TEXT = (
    "<b>👋 Welcome to Group Security Bot!</b>\n\n"
    "I help admins manage join requests and keep groups safe. I can handle:\n"
    "• Join-request approval with CAPTCHA verification\n"
    "• Ban / unban / mute / unmute\n"
    "• Declined join-request tracking\n"
    "• Custom bot-admin management\n"
    "• Imposter / impersonation detection\n\n"
    "Add me to your group as an admin with permission to manage join requests, "
    "invite users, and restrict members to get started."
)

FEATURES_TEXT = (
    "<b>🌟 Features</b>\n\n"
    "<b>Join Requests</b>\n"
    "Automatic ban checks, impersonation checks, and CAPTCHA verification before "
    "any user is approved into your group.\n\n"
    "<b>Moderation</b>\n"
    "/ban /unban /banned /mute /unmute — full moderation toolkit with MongoDB persistence.\n\n"
    "<b>Admin Management</b>\n"
    "/addadmin /removeadmin /admins — owner-controlled bot admin system, separate "
    "from Telegram's own admin list.\n\n"
    "<b>Imposter Detection</b>\n"
    "Flags identity changes and possible impersonation of protected accounts."
)


def start_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup([
        [InlineKeyboardButton("❓ Help", callback_data="show_help"),
         InlineKeyboardButton("🌟 Features", callback_data="show_features")],
        [InlineKeyboardButton("✖ Close", callback_data="close")],
    ])


@app.on_message(filters.command("start") & filters.private)
async def cmd_start(client: Client, message: Message):
    await message.reply(START_TEXT, reply_markup=start_keyboard())


HELP_TEXT = (
    "<b>📖 Command Reference</b>\n\n"
    "<b>Join Requests</b>\n"
    "/decline — decline a pending join request (reply to their request notice)\n"
    "/declined — view previously declined users\n\n"
    "<b>Moderation</b>\n"
    "/ban [reason] — ban a user (reply or pass user id)\n"
    "/unban — unban a user\n"
    "/banned — list banned users\n"
    "/mute — restrict a user from sending messages\n"
    "/unmute — restore a user's permissions\n\n"
    "<b>Imposter Detection</b>\n"
    "/imposter protect — mark a replied-to user as protected\n"
    "/imposter unprotect &lt;user_id&gt; — remove protection\n\n"
    "<b>Admin Management</b>\n"
    "/addadmin — add a bot admin (owner only)\n"
    "/removeadmin — remove a bot admin (owner only)\n"
    "/admins — list bot admins\n\n"
    "<b>General</b>\n"
    "/start — welcome message\n"
    "/help — this menu"
)


@app.on_message(filters.command("help"))
async def cmd_help(client: Client, message: Message):
    await message.reply(HELP_TEXT, reply_markup=InlineKeyboardMarkup(
        [[InlineKeyboardButton("✖ Close", callback_data="close")]]
    ))


@app.on_callback_query(filters.regex(r"^show_help$"))
async def cb_show_help(client: Client, cq: CallbackQuery):
    await safe_call(
        cq.message.edit_text(HELP_TEXT, reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅ Back", callback_data="show_start")],
             [InlineKeyboardButton("✖ Close", callback_data="close")]]
        )),
        action="edit_help",
    )
    await cq.answer()


@app.on_callback_query(filters.regex(r"^show_features$"))
async def cb_show_features(client: Client, cq: CallbackQuery):
    await safe_call(
        cq.message.edit_text(FEATURES_TEXT, reply_markup=InlineKeyboardMarkup(
            [[InlineKeyboardButton("⬅ Back", callback_data="show_start")],
             [InlineKeyboardButton("✖ Close", callback_data="close")]]
        )),
        action="edit_features",
    )
    await cq.answer()


@app.on_callback_query(filters.regex(r"^show_start$"))
async def cb_show_start(client: Client, cq: CallbackQuery):
    await safe_call(cq.message.edit_text(START_TEXT, reply_markup=start_keyboard()), action="edit_start")
    await cq.answer()


@app.on_callback_query(filters.regex(r"^close$"))
async def cb_close(client: Client, cq: CallbackQuery):
    await safe_call(cq.message.delete(), action="close_message")
    await cq.answer()


@app.on_callback_query(filters.regex(r"^noop$"))
async def cb_noop(client: Client, cq: CallbackQuery):
    await cq.answer()


# ==============================================================================
# GLOBAL CALLBACK / ERROR SAFETY NET
# ==============================================================================

@app.on_callback_query(group=99)
async def cb_catch_all_errors(client: Client, cq: CallbackQuery):
    # This handler runs after all specific handlers (higher group number = later).
    # Pyrogram stops propagation once a handler completes without raising
    # ContinuePropagation, so in practice this only fires for truly unmatched
    # callback data — respond politely instead of leaving the client hanging.
    await safe_call(cq.answer("This action is no longer available."), action="fallback_callback_answer")


# ==============================================================================
# STARTUP / SHUTDOWN
# ==============================================================================

async def register_bot_commands() -> None:
    from pyrogram.types import BotCommand
    commands = [
        BotCommand("start", "Welcome message"),
        BotCommand("help", "Show all commands"),
        BotCommand("ban", "Ban a user"),
        BotCommand("unban", "Unban a user"),
        BotCommand("banned", "List banned users"),
        BotCommand("mute", "Mute a user"),
        BotCommand("unmute", "Unmute a user"),
        BotCommand("decline", "Decline a join request"),
        BotCommand("declined", "List declined join requests"),
        BotCommand("addadmin", "Add a bot admin"),
        BotCommand("removeadmin", "Remove a bot admin"),
        BotCommand("admins", "List bot admins"),
    ]
    await safe_call(app.set_bot_commands(commands), action="set_bot_commands")


async def main() -> None:
    logger.info("Connecting to MongoDB...")
    try:
        await mongo_client.admin.command("ping")
    except Exception as e:  # noqa: BLE001
        logger.critical("Could not connect to MongoDB: %s", e)
        raise SystemExit(1)
    logger.info("MongoDB connected.")

    await ensure_indexes()
    logger.info("Indexes ensured.")

    await app.start()
    await register_bot_commands()
    me = await app.get_me()
    logger.info("Bot started as @%s (id=%s)", me.username, me.id)

    sweeper_task = asyncio.create_task(captcha_sweeper())

    try:
        await asyncio.Event().wait()  # run forever
    finally:
        sweeper_task.cancel()
        await app.stop()
        mongo_client.close()
        logger.info("Bot stopped cleanly.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutdown requested.")
