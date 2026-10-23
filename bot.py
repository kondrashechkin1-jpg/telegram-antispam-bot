"""Telegram anti-spam moderation with PostgreSQL and age-based penalties."""
import asyncio
import html
import logging
import os
import re
from datetime import datetime, timedelta, timezone

import asyncpg
from telegram import ChatPermissions, Update
from telegram.constants import ChatMemberStatus, ParseMode
from telegram.ext import ApplicationBuilder, ChatMemberHandler, ContextTypes, MessageHandler, filters

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logging.getLogger('httpx').setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ['BOT_TOKEN']
DATABASE_URL = os.environ['DATABASE_URL']
ALLOWED_CHAT_ID = int(os.environ['ALLOWED_CHAT_ID'])
DRY_RUN = os.getenv('DRY_RUN', 'true').strip().lower() != 'false'
TEST_ADMINS = os.getenv('TEST_ADMINS', 'false').strip().lower() == 'true'
NOTICE_TTL_SECONDS = 60
NEWCOMER_HOURS = 24
MUTE_HOURS = 48

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
    pool = await asyncpg.create_pool(DATABASE_URL, min_size=1, max_size=3)
    app.bot_data['db'] = pool
    async with pool.acquire() as conn:
        await conn.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                chat_id BIGINT NOT NULL, user_id BIGINT NOT NULL,
                joined_at TIMESTAMPTZ,
                first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_message_at TIMESTAMPTZ,
                message_count BIGINT NOT NULL DEFAULT 0,
                violations INTEGER NOT NULL DEFAULT 0,
                last_violation_at TIMESTAMPTZ,
                PRIMARY KEY (chat_id, user_id)
            )
        ''')
        # Lock in whether the FIRST confirmed violation occurred in the first 24h.
        # Existing records from the earlier version are migrated without data loss.
        await conn.execute('''
            ALTER TABLE group_members
            ADD COLUMN IF NOT EXISTS first_violation_newcomer BOOLEAN
        ''')
    logger.info('PostgreSQL connected | DRY_RUN=%s | TEST_ADMINS=%s', DRY_RUN, TEST_ADMINS)


async def close_db(app):
    pool = app.bot_data.get('db')
    if pool:
        await pool.close()


async def save_join(chat_id, user_id, joined_at, pool):
    async with pool.acquire() as conn:
        await conn.execute('''
            INSERT INTO group_members (chat_id, user_id, joined_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (chat_id, user_id) DO UPDATE SET
                joined_at=EXCLUDED.joined_at,
                violations=0,
                first_violation_newcomer=NULL,
                last_violation_at=NULL
        ''', chat_id, user_id, joined_at)
    logger.info('Member joined | user=%s', user_id)


async def joined(update: Update, context: ContextTypes.DEFAULT_TYPE):
    change = update.chat_member
    if not change or change.chat.id != ALLOWED_CHAT_ID:
        return
    active = {ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER,
              ChatMemberStatus.RESTRICTED}
    before, after = change.old_chat_member.status, change.new_chat_member.status
    if after not in active or before in active:
        return
    try:
        await save_join(change.chat.id, change.new_chat_member.user.id, change.date,
                        context.application.bot_data['db'])
    except Exception:
        logger.exception('Failed to record joining member')


async def service_join(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    if not message or message.chat_id != ALLOWED_CHAT_ID:
        return
    for user in message.new_chat_members:
        if user.is_bot:
            continue
        try:
            await save_join(message.chat_id, user.id, message.date,
                            context.application.bot_data['db'])
        except Exception:
            logger.exception('Failed to record service join')


def extract_links(message, body):
    links = URL_RE.findall(body)
    for entity in list(message.entities or ()) + list(message.caption_entities or ()):
        if entity.type == 'text_link' and entity.url:
            links.append(entity.url)
    return links


def assess(message, body, record):
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
    joined_at = record['joined_at']
    if joined_at and timedelta(0) <= datetime.now(timezone.utc) - joined_at < timedelta(hours=24):
        score += 1
    if record['message_count'] == 1 and has_link:
        score += 1
    # This is a heuristic, NOT a definitive determination of advertising.
    obvious_ad = (cta and (has_link or mentions) and (sales or tg_link or has_link)) or (dm and sales and has_link)
    reasons = f'old={old}, link={has_link}, telegram={tg_link}, cta={cta}, sales={sales}, dm={dm}, mention={mentions}'
    return score, obvious_ad, old, reasons


def newcomer_on_first_violation(record):
    joined_at = record['joined_at']
    if joined_at is None:
        return False  # Unknown join date: safer long-term-member rules.
    age = datetime.now(timezone.utc) - joined_at
    return timedelta(0) <= age < timedelta(hours=NEWCOMER_HOURS)


def action_for(violations, newcomer):
    if newcomer:
        return 'delete_and_ban' if violations >= 2 else 'delete_and_warn_new'
    if violations == 1:
        return 'delete_only'
    if violations == 2:
        return 'delete_and_warn_regular'
    return 'delete_and_mute'


def user_mention(user):
    safe_name = html.escape(user.full_name or 'Участник')
    return f'<a href="tg://user?id={user.id}">{safe_name}</a>'


def notice_for(action, mention):
    if action == 'delete_and_warn_new':
        return f'Поймал за рекламой {mention}. Пока почистил за ним следы, но в следующий раз накажу 😎'
    if action == 'delete_and_ban':
        return f'Доигрался, дружок. {mention} наказан удалением за рекламу. Так обидно, я думал, он норм 🥹'
    if action == 'delete_and_warn_regular':
        return (f'Поймал за рекламой {mention}. Пока почистил за ним следы, '
                'но в следующий раз засуну кляп в рот на 48 часов. Тебе такое нравится? 🥰')
    if action == 'delete_and_mute':
        return (f'Я медленно вставляю кляп в твой рот на 48 часов, {mention}. '
                'Не рекламируй тут, пожалуйста :(')
    return None


async def delete_notice_later(bot, chat_id, message_id):
    await asyncio.sleep(NOTICE_TTL_SECONDS)
    try:
        await bot.delete_message(chat_id, message_id)
    except Exception:
        logger.exception('Could not remove temporary notice %s', message_id)


async def send_notice(context, chat_id, user, action):
    notice = notice_for(action, user_mention(user))
    if not notice:
        return
    try:
        sent = await context.bot.send_message(chat_id, notice, parse_mode=ParseMode.HTML)
        # Mute notice stays in chat; all other notices disappear after 60 seconds.
        if action != 'delete_and_mute':
            context.application.create_task(delete_notice_later(context.bot, chat_id, sent.message_id))
    except Exception:
        logger.exception('Failed to send moderation notice | action=%s', action)


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
                RETURNING joined_at, message_count, violations, first_violation_newcomer
            ''', chat.id, user.id)
        score, obvious_ad, old, reasons = assess(message, body, record)
        suspicious = old or score >= 5 or obvious_ad
        if not suspicious:
            return
        newcomer = (record['first_violation_newcomer'] if record['first_violation_newcomer'] is not None
                    else newcomer_on_first_violation(record))
        next_violations = record['violations'] + 1
        proposed_action = action_for(next_violations, newcomer)
        logger.warning('Spam candidate | user=%s | msg=%s | score=%s | obvious_ad=%s | %s | '
                       'next_violation=%s | newcomer=%s | proposed_action=%s | DRY_RUN=%s',
                       user.id, message.message_id, score, obvious_ad, reasons,
                       next_violations, newcomer, proposed_action, DRY_RUN)
        if DRY_RUN:
            return
        try:
            await message.delete()
        except Exception:
            logger.exception('Could not delete message %s; no penalty recorded', message.message_id)
            return
        # Keep a single member's counters consistent when messages arrive quickly.
        async with pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow('''
                    SELECT violations, joined_at, first_violation_newcomer
                    FROM group_members WHERE chat_id=$1 AND user_id=$2 FOR UPDATE
                ''', chat.id, user.id)
                locked_newcomer = (row['first_violation_newcomer'] if row['first_violation_newcomer'] is not None
                                   else newcomer_on_first_violation(row))
                violations = row['violations'] + 1
                await conn.execute('''
                    UPDATE group_members SET violations=$3, last_violation_at=NOW(),
                        first_violation_newcomer=COALESCE(first_violation_newcomer, $4)
                    WHERE chat_id=$1 AND user_id=$2
                ''', chat.id, user.id, violations, locked_newcomer)
        action = action_for(violations, locked_newcomer)
        logger.info('Deleted | user=%s | violations=%s | newcomer=%s | action=%s',
                    user.id, violations, locked_newcomer, action)
        if is_admin:
            logger.info('Admin test: deletion only, no penalties or notices')
            return
        try:
            if action == 'delete_and_ban':
                await context.bot.ban_chat_member(chat.id, user.id, revoke_messages=False)
            elif action == 'delete_and_mute':
                await context.bot.restrict_chat_member(
                    chat.id, user.id,
                    permissions=ChatPermissions(can_send_messages=False),
                    until_date=datetime.now(timezone.utc) + timedelta(hours=MUTE_HOURS),
                    use_independent_chat_permissions=True,
                )
        except Exception:
            logger.exception('Failed to enforce %s | user=%s', action, user.id)
            return  # Do not announce a punishment that failed.
        await send_notice(context, chat.id, user, action)
    except Exception:
        logger.exception('Message processing failed | chat=%s | user=%s', chat.id, user.id)


def main():
    app = (ApplicationBuilder().token(BOT_TOKEN)
           .post_init(init_db).post_shutdown(close_db).build())
    app.add_handler(ChatMemberHandler(joined, ChatMemberHandler.CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & filters.StatusUpdate.NEW_CHAT_MEMBERS, service_join))
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND,
                                   check_message))
    logger.info('Starting | chat=%s | DRY_RUN=%s | newcomer=%sh | mute=%sh',
                ALLOWED_CHAT_ID, DRY_RUN, NEWCOMER_HOURS, MUTE_HOURS)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == '__main__':
    main()
