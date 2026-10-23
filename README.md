# Telegram Antispam Bot

A minimal Telegram group antispam bot with safe dry-run mode.

## Railway configuration

Deploy this GitHub repository as a Railway service. Set:

- `BOT_TOKEN`: Telegram token from BotFather (keep secret).
- `DRY_RUN`: `true` initially. Set to `false` only after verifying logs.
- `ALLOWED_CHAT_ID`: ID of the test group. Initially set `0` to discover the ID in logs; with `0` the bot never moderates anything.

Start command: `python bot.py`

Send a message to the test group and check Railway logs for `Incoming chat ID`. Set `ALLOWED_CHAT_ID` to that number and redeploy. The bot skips administrators; test with a non-admin account. Give the bot permission to delete messages before disabling dry-run.

The starter filter matches a few obvious Russian spam phrases. It does not identify every spam message and may occasionally flag legitimate text. Inspect logs before enabling deletion.
