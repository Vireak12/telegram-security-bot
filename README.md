# Telegram Security Bot (Next.js)

Scans links and files posted in Telegram chats with VirusTotal and deletes anything malicious or suspicious.

## Setup

1. `npm install`
2. `cp .env.example .env.local` and fill in the values
3. Deploy (e.g. Vercel: import the repo, add the same env vars)
4. Register the webhook once:
   `npm run set-webhook -- https://your-app.vercel.app`
5. In groups: add the bot as **admin with "Delete messages"**. Otherwise disable
   privacy mode in @BotFather (`/setprivacy` -> Disable) so it can see all messages.

## Local development

On **Windows**, if file scans fail with `UNABLE_TO_VERIFY_LEAF_SIGNATURE`, the
`npm run dev` script already passes Node’s `--use-system-ca` flag (uses your OS
trust store for VirusTotal HTTPS).

`npm run dev`, expose port 3000 with a tunnel (ngrok / cloudflared),
then run `npm run set-webhook -- https://<tunnel-url>`.

## Notes

- Cache: set the Upstash Redis vars for a persistent 24h cache. Without them an in-memory cache is used.
- VirusTotal free tier is 4 requests/min, so at most 3 links per message are scanned.
- Telegram bots can only download files up to 20 MB.
