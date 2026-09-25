import { after } from "next/server";
import { getBot } from "@/lib/bot";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60; // scans can take a while (polling VirusTotal)

export async function POST(req: Request) {
  // Telegram echoes the secret we registered in setWebhook. Fail closed if unset.
  const secret = process.env.TELEGRAM_WEBHOOK_SECRET;
  if (!secret || req.headers.get("x-telegram-bot-api-secret-token") !== secret) {
    return new Response("Unauthorized", { status: 401 });
  }

  const update = await req.json();
  const bot = getBot();

  const handle = async () => {
    try {
      await bot.init();
      await bot.handleUpdate(update);
    } catch (err) {
      console.error("Update handling failed:", err);
    }
  };

  // Acknowledge Telegram immediately; scans can take several seconds or longer.
  if (process.env.NODE_ENV === "development") void handle();
  else after(handle);
  return new Response("OK");
}
