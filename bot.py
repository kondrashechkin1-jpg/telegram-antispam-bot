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


def force_regular_for(chat_id, user_id):
    return (TEST_FORCE_REGULAR and TEST_FORCE_REGULAR_USER_ID > 0
            and TEST_FORCE_REGULAR_CHAT_ID < 0
            and chat_id == TEST_FORCE_REGULAR_CHAT_ID == ALLOWED_CHAT_ID
            and user_id == TEST_FORCE_REGULAR_USER_ID)


def effective_newcomer(record, chat_id, user_id):
    if force_regular_for(chat_id, user_id):
        return False
    return (record['first_violation_newcomer'] if record['first_violation_newcomer'] is not None
            else newcomer_on_first_violation(record))


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
        reason = ('missing_message_chat_user' if not message or not chat or not user
                  else 'bot_sender' if user.is_bot else 'wrong_chat')
        logger.info('DIAG_SKIP | instance=%s | update=%s | reason=%s',
                    DIAG_INSTANCE, update.update_id, reason)
        return
    try:
        logger.info('DIAG_STAGE | instance=%s | update=%s | stage=get_chat_member',
                    DIAG_INSTANCE, update.update_id)
        member = await context.bot.get_chat_member(chat.id, user.id)
        is_admin = member.status in (ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.OWNER)
        if is_admin and not TEST_ADMINS:
            logger.info('DIAG_SKIP | instance=%s | update=%s | reason=admin_exempt',
                        DIAG_INSTANCE, update.update_id)
            return
        body = message.text or message.caption or ''
        if not body:
            logger.info('DIAG_SKIP | instance=%s | update=%s | reason=no_text_or_caption',
                        DIAG_INSTANCE, update.update_id)
            return
        pool = context.application.bot_data['db']
        logger.info('DIAG_STAGE | instance=%s | update=%s | stage=db_record',
                    DIAG_INSTANCE, update.update_id)
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
        # Shadow analysis runs for every non-admin text message, regardless of old score.
        # Do not block existing moderation on an external API request.
        if AI_SHADOW_ENABLED and OPENAI_API_KEY:
            context.application.create_task(
                ai_shadow_check(message, body, update.update_id, context.application),
                update=update)
        logger.info('DIAG_DECISION | instance=%s | update=%s | score=%s | suspicious=%s | %s',
                    DIAG_INSTANCE, update.update_id, score, suspicious, reasons)
        if not suspicious:
            logger.info('DIAG_SKIP | instance=%s | update=%s | reason=not_spam',
                        DIAG_INSTANCE, update.update_id)
            return
        newcomer = effective_newcomer(record, chat.id, user.id)
        next_violations = record['violations'] + 1
        proposed_action = action_for(next_violations, newcomer)
        logger.warning('Spam candidate | user=%s | msg=%s | score=%s | obvious_ad=%s | %s | '
                       'next_violation=%s | newcomer=%s | proposed_action=%s | DRY_RUN=%s',
