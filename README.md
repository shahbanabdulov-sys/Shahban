# SHARIFA

CRM for Sharifa.

## Netlify

- Build command: `npm run build`
- Publish directory: `dist`

## Supabase

Create a Supabase project and add these variables in Netlify:

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_PUBLISHABLE_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

`SUPABASE_SERVICE_ROLE_KEY` is server-only. Add it only in Netlify environment variables, never in frontend code.

## Telegram hourly backups

The project includes a Netlify scheduled function:

- Function: `hourly-crm-export`
- Schedule: `0 * * * *`
- Result: every hour a new CRM JSON backup is sent to Telegram with a filename like `backup-2026-06-17-14-00.json`
- Storage: backups are not saved in Supabase Storage, Google Drive, Yandex Disk, or the database as files

Add these server-side variables in Netlify:

- `SUPABASE_SERVICE_ROLE_KEY`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_CHAT_ID`

How to create Telegram bot:

1. Open Telegram.
2. Find `@BotFather`.
3. Send `/newbot`.
4. Create the bot and copy `TELEGRAM_BOT_TOKEN`.
5. Open your new bot and press `Start`.
6. Find your `TELEGRAM_CHAT_ID` using a Telegram ID bot or by calling `getUpdates` after sending a message to your bot.
7. In Netlify open `Site configuration` -> `Environment variables`.
8. Add `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, and `SUPABASE_SERVICE_ROLE_KEY`.

Manual test:

Open CRM -> `Настройки` -> `Telegram`. The button calls `/.netlify/functions/hourly-crm-export` and sends a test backup immediately.
