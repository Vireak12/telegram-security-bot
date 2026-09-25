// Usage: npm run set-webhook -- https://your-app.vercel.app
const token = process.env.TELEGRAM_BOT_TOKEN;
const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
const base = (process.argv[2] ?? process.env.WEBHOOK_BASE_URL ?? "").replace(/\/$/, "");

if (!token || !secret || !base) {
  console.error("Need TELEGRAM_BOT_TOKEN, TELEGRAM_WEBHOOK_SECRET and a base URL argument.");
  process.exit(1);
}

const url = `${base}/api/telegram`;
const res = await fetch(`https://api.telegram.org/bot${token}/setWebhook`, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({
    url,
    secret_token: secret,
    allowed_updates: ["message", "edited_message"],
    drop_pending_updates: true,
  }),
});

console.log(await res.json());
console.log(`Webhook -> ${url}`);
