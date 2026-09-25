import type { Api } from "grammy";

function parseAdminUserIds(): number[] {
  const raw = process.env.TELEGRAM_ADMIN_USER_IDS?.trim();
  if (!raw) return [];
  return raw
    .split(/[,;\s]+/)
    .map((s) => Number.parseInt(s, 10))
    .filter((n) => Number.isFinite(n));
}

function parseAdminLogChatId(): number | null {
  const raw = process.env.TELEGRAM_ADMIN_LOG_CHAT_ID?.trim();
  if (!raw) return null;
  const id = Number.parseInt(raw, 10);
  return Number.isFinite(id) ? id : null;
}

/**
 * Sends a security incident summary to configured admin DM(s) and/or log channel.
 */
export async function notifyAdmins(api: Api, html: string): Promise<void> {
  const userIds = parseAdminUserIds();
  const logChatId = parseAdminLogChatId();
  if (userIds.length === 0 && logChatId === null) return;

  const targets: number[] = [...userIds];
  if (logChatId !== null) targets.push(logChatId);

  for (const chatId of targets) {
    try {
      await api.sendMessage(chatId, html, { parse_mode: "HTML" });
    } catch (err) {
      console.error(`Admin notify failed for chat ${chatId}:`, err);
    }
  }
}
