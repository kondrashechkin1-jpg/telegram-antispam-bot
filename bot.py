"""Telegram group anti-spam bot with PostgreSQL member tracking and moderation."""
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import asyncpg
from telegram import ChatPermissions, Update
from telegram.constants import ChatMemberStatus
from telegram.ext import (
    ApplicationBuilder, ChatMemberHandler, ContextTypes, MessageHandler, filters,
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ['BOT_TOKEN']
DATABASE_URL = os.environ['DATABASE_URL']
ALLOWED_CHAT_ID = int(os.environ['ALLOWED_CHAT_ID'])
DRY_RUN = os.getenv('DRY_RUN', 'true').strip().lower() != 'false'
TEST_ADMINS = os.getenv('TEST_ADMINS', 'false').strip().lower() == 'true'
MUTE_HOURS = int(os.getenv('MUTE_HOURS', '24'))

OLD_PATTERNS = [re.compile(p, re.I) for p in [
    r'заработок\s+от\s+[\d\s]+', r'доход\s+от\s+[\d\s]+',
    r'пассивный\s+доход', r'быстрые\s+деньги',
    r'гарантированн\w*\s+заработок',
]]
URL_RE = re.compile(r'(?:https?://|www\.|t\.me/|telegram\.me/|telegram\.dog/)[^\s<>]+', re.I)
TG_RE = re.compile(r'(?:https?://)?(?:t\.me|telegram\.me|telegram\.dog)/', re.I)
CTA_RE = re.compile(r'\b(?:скачивай(?:те)?|подписывай(?:тесь|ся)|переходи(?:те)?|заходи(?:те)?|вступай(?:те)?|жми(?:те)?|регистрируй(?:тесь|ся)|присоединяй(?:тесь|ся))\b', re.I)
SALES_RE = re.compile(r'\b(?:скидк[аиу]|промокод|акци[яи]|бонус|доход|заработок|выплат[аы]|без\s+вложений)\b', re.I)
DM_RE = re.compile(r'(?:пиши(?:те)?|обращай(?:тесь|ся))\s+(?:мне\s+)?(?:в\s+)?(?:лс|личк[уи]|директ)', re.I)
MENTION_RE = re.compile(r'(?<!\w)@[A-Za-z0-9_]{5,32}\b')


async def init_db(app):
    app.bot_data['db'] = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
    async with app.bot_data['db'].acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                chat_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                joined_at TIMESTAMPTZ,
                first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_message_at TIMESTAMPTZ,
                message_count BIGINT NOT NULL DEFAULT 0,
                violations INTEGER NOT NULL DEFAULT 0,
                last_violation_at TIMESTAMPTZ,
                PRIMARY KEY (chat_id, user_id)
            )
        ''')
    logger.info('PostgreSQL connected; table ready | DRY_RUN=%s | TEST_ADMINS=%s', DRY_RUN, TEST_ADMINS)


async def close_db(app):
    pool = app.bot_data.get('db')
    if pool:
        await pool.close()


async def joined(update: Update, context: ContextTypes.DEFAULT_TYPE):
    change = update.chat_member
    if not change or change.chat.id != ALLOWED_CHAT_ID:
        return
    before, after = change.old_chat_member.status, change.new_chat_member.status
    active = {ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER}
    if after not in active or before in active:
        return
    user_id = change.new_chat_member.user.id
    async with context.application.bot_data['db'].acquire() as conn:
        await conn.execute('''
            INSERT INTO group_members (chat_id, user_id, joined_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (chat_id, user_id) DO UPDATE SET joined_at=EXCLUDED.joined_at
        ''', change.chat.id, user_id, change.date)
    logger.info('Member joined | user=%s', user_id)


def extract_links(message, body):
    links = URL_RE.findall(body)
    for entity in list(message.entities or ()) + list(message.caption_entities or ()):
        if entity.type == 'text_link' and entity.url:
            links.append(entity.url)
    return links


def assess(message, body, member_record):
    links = extract_links(message, body)
    tg_link = any(TG_RE.search(link) for link in links)
    has_link = bool(links)
    cta = bool(CTA_RE.search(body))
    sales = bool(SALES_RE.search(body))
    dm = bool(DM_RE.search(body))
    old = any(p.search(body) for p in OLD_PATTERNS)
    mentions = bool(MENTION_RE.search(body))
    score = (4 if old else 0) + (2 if has_link else 0) + (2 if tg_link else 0)
    score += (3 if cta else 0) + (2 if sales else 0) + (2 if dm else 0)
    # New-member status is only a weak signal, never sufficient on its own.
    joined_at = member_record['joined_at']
    if joined_at and datetime.now(timezone.utc) - joined_at < timedelta(hours=24):
        score += 1
    if member_record['message_count'] == 1 and has_link:
        score += 1
    # Strong advertising evidence: promotion AND a link/handle. No automatic ban for plain links.
    obvious_ad = (cta and (has_link or mentions) and (sales or tg_link or has_link)) or (dm and sales and has_link)
    reasons = f'old={old}, link={has_link}, telegram={tg_link}, cta={cta}, sales={sales}, dm={dm}, mention={mentions}'
    return score, obvious_ad, old, reasons


async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message, chat, user = update.effective_message, update.effective_chat, update.effective_user
    if not message or not chat or not user or user.is_bot or chat.id != ALLOWED_CHAT_ID:
        return
    try:
        member = await context.bot.get_chat_member(chat.id, user.id)
        is_admin = member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
        if is_admin and not TEST_ADMINS:
            return
        body = message.text or message.caption or ''
        if not body:
            return
        pool = context.application.bot_data['db']
        async with pool.acquire() as conn:
            record = await conn.fetchrow('''
                INSERT INTO group_members (chat_id, user_id, last_message_at, message_count)
                VALUES ($1, $2, NOW(), 1)
                ON CONFLICT (chat_id, user_id) DO UPDATE SET
                    last_message_at=NOW(), message_count=group_members.message_count+1
                RETURNING joined_at, message_count, violations
            ''', chat.id, user.id)
        score, obvious_ad, old, reasons = assess(message, body, record)
        suspicious = old or score >= 5 or obvious_ad
        if not suspicious:
            return
        logger.warning('Spam candidate | user=%s | msg=%s | score=%s | obvious_ad=%s | %s',
                       user.id, message.message_id, score, obvious_ad, reasons)
        if DRY_RUN:
            logger.info('DRY_RUN: no deletion, mute, ban, or violation recorded')
            return
        try:
            await message.delete()
        except Exception:
            logger.exception('Could not delete message %s', message.message_id)
            return
        async with pool.acquire() as conn:
            violations = await conn.fetchval('''
                UPDATE group_members SET violations=violations+1, last_violation_at=NOW()
                WHERE chat_id=$1 AND user_id=$2 RETURNING violations
            ''', chat.id, user.id)
        logger.info('Deleted | user=%s | violations=%s', user.id, violations)
        # Never try to ban/mute admins, even with TEST_ADMINS enabled.
        if is_admin:
            logger.info('Admin test: deletion only, no restrictions')
            return
        try:
            if obvious_ad:
                await context.bot.ban_chat_member(chat.id, user.id, revoke_messages=False)
                logger.warning('BANNED obvious advertising | user=%s', user.id)
            elif violations >= 2:
                until = datetime.now(timezone.utc) + timedelta(hours=MUTE_HOURS)
                await context.bot.restrict_chat_member(
                    chat.id, user.id,
                    permissions=ChatPermissions(can_send_messages=False),
                    until_date=until,
                    use_independent_chat_permissions=True,
                )
                logger.warning('MUTED %sh | user=%s', MUTE_HOURS, user.id)
        except Exception:
            logger.exception('Moderation action failed | user=%s', user.id)
    except Exception:
        logger.exception('Message processing failed | chat=%s | user=%s', chat.id, user.id)


def main():
    app = (ApplicationBuilder().token(BOT_TOKEN)
           .post_init(init_db).post_shutdown(close_db).build())
    app.add_handler(ChatMemberHandler(joined, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND, check_message))
    logger.info('Starting | chat=%s | DRY_RUN=%s | MUTE_HOURS=%s', ALLOWED_CHAT_ID, DRY_RUN, MUTE_HOURS)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
