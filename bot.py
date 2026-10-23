import logging
import os
import re
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

BOT_TOKEN = os.environ['BOT_TOKEN']
DRY_RUN = os.getenv('DRY_RUN', 'true').strip().lower() != 'false'
ALLOWED_CHAT_ID = int(os.getenv('ALLOWED_CHAT_ID', '0'))

PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'заработок\s+от\s+[\d\s]+',
        r'доход\s+от\s+[\d\s]+',
        r'пассивный\s+доход',
        r'быстрые\s+деньги',
        r'гарантированн\w*\s+заработок',
    ]
]

async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.effective_message
    chat = update.effective_chat
    user = update.effective_user
    if not message or not chat or not user:
        return
    logger.info('Incoming chat ID: %s', chat.id)
    if ALLOWED_CHAT_ID == 0 or chat.id != ALLOWED_CHAT_ID:
        return
    member = await context.bot.get_chat_member(chat.id, user.id)
    if member.status in ('administrator', 'creator'):
        return
    body = message.text or message.caption or ''
    if not body:
        return
    for pattern in PATTERNS:
        if pattern.search(body):
            logger.warning('Suspected spam | chat=%s | user=%s | message=%s | pattern=%s', chat.id, user.id, message.message_id, pattern.pattern)
            if not DRY_RUN:
                try:
                    await message.delete()
                    logger.info('Deleted message %s', message.message_id)
                except Exception:
                    logger.exception('Failed to delete message %s', message.message_id)
            return


def main() -> None:
    app = ApplicationBuilder().token(BOT_TOKEN).build()
    app.add_handler(MessageHandler(filters.ChatType.GROUPS & (filters.TEXT | filters.CAPTION) & ~filters.COMMAND, check_message))
    logger.info('Bot started | DRY_RUN=%s | ALLOWED_CHAT_ID=%s', DRY_RUN, ALLOWED_CHAT_ID)
    app.run_polling()

if __name__ == '__main__':
    main()
