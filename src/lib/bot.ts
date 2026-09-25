import { Bot, type Context } from "grammy";
import type { MessageEntity } from "grammy/types";
import {
  ALERT_AUTO_DELETE_SECONDS,
  MALICIOUS_THRESHOLD,
  MAX_FILE_SIZE,
  MAX_URLS_PER_MESSAGE,
  MUTE_DURATION_SECONDS,
  SUSPICIOUS_THRESHOLD,
  requireEnv,
} from "./config";
import { scanFile, scanUrl, type ScanResult } from "./virustotal";
import { notifyAdmins } from "./admin-notify";
import { getScanStats, recordThreatBlocked } from "./stats";
import {
  addWhitelistDomain,
  getAllWhitelistedDomains,
  removeWhitelistDomain,
} from "./whitelist";

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

function extractUrls(msg: {
  text?: string;
  caption?: string;
  entities?: MessageEntity[];
  caption_entities?: MessageEntity[];
}): string[] {
  const text = msg.text ?? msg.caption ?? "";
  const entities = msg.entities ?? msg.caption_entities ?? [];
  const urls = new Set<string>();

  for (const e of entities) {
    // Telegram offsets are UTF-16 code units, which is exactly what JS slice() uses.
    if (e.type === "url") urls.add(text.slice(e.offset, e.offset + e.length));
    else if (e.type === "text_link") urls.add(e.url);
  }

  // Fallback regex to catch plain URLs even without Telegram entities
  const matches = text.match(/\bhttps?:\/\/[^\s]+/gi);
  if (matches) {
    for (const m of matches) urls.add(m);
  }

  return [...urls].slice(0, MAX_URLS_PER_MESSAGE);
}

async function isUserAdmin(ctx: Context): Promise<boolean> {
  if (!ctx.chat || ctx.chat.type === "private") return true;
  if (!ctx.from) return false;
  try {
    const member = await ctx.api.getChatMember(ctx.chat.id, ctx.from.id);
    return member.status === "creator" || member.status === "administrator";
  } catch {
    return false;
  }
}

async function handleThreat(
  ctx: Context,
  kind: "Link" | "File",
  detailLine: string,
  result: ScanResult,
) {
  const msg = ctx.msg;
  if (!msg) return;

  // 1) Delete the malicious message
  let deleted = false;
  try {
    await ctx.api.deleteMessage(msg.chat.id, msg.message_id);
    deleted = true;
  } catch (err) {
    console.error("deleteMessage failed:", err);
  }

  // 2) Auto-Mute / Restrict the sender (if in a group and not an admin)
  let muted = false;
  const isGroup = ctx.chat?.type === "group" || ctx.chat?.type === "supergroup";
  if (isGroup && ctx.from && ctx.chat) {
    try {
      const senderMember = await ctx.api.getChatMember(ctx.chat.id, ctx.from.id);
      if (senderMember.status !== "creator" && senderMember.status !== "administrator") {
        await ctx.api.restrictChatMember(
          ctx.chat.id,
          ctx.from.id,
          {
            can_send_messages: false,
            can_send_audios: false,
            can_send_documents: false,
            can_send_photos: false,
            can_send_videos: false,
            can_send_video_notes: false,
            can_send_voice_notes: false,
            can_send_polls: false,
            can_send_other_messages: false,
            can_add_web_page_previews: false,
          },
          {
            until_date: Math.floor(Date.now() / 1000) + MUTE_DURATION_SECONDS,
          },
        );
        muted = true;
      }
    } catch (err) {
      console.error("restrictChatMember failed:", err);
    }
  }

  const sender = esc(ctx.from?.first_name ?? "Unknown");
  const kindKhmer = kind === "File" ? "ឯកសារ (File)" : "តំណភ្ជាប់ (Link)";
  
  let actionSummary = "";
  if (deleted) actionSummary += `❌ ${kind === "File" ? "ឯកសារ" : "សារ"}នេះត្រូវបានលុបចេញភ្លាមៗ។\n`;
  else actionSummary += "⚠️ មិនអាចលុបសារនេះបានទេ។ សូមកំណត់ខ្ញុំជា Admin និងបើកសិទ្ធិ “Delete messages”។\n";

  if (muted) {
    actionSummary += "🔇 <b>ចំណាត់ការ៖</b> ជនបង្កត្រូវបាន Mute (ផ្អាកមិនឱ្យនិយាយ) រយៈពេល ២៤ ម៉ោងដើម្បីសុវត្ថិភាព!\n";
  }

  const autoDeleteNotice = isGroup
    ? `\n⏱️ <i>សារ Alert នេះនឹងត្រូវលុបស្វ័យប្រវត្តិក្នងរយៈពេល ${ALERT_AUTO_DELETE_SECONDS} វិនាទី។</i>`
    : "";

  await recordThreatBlocked();

  const chatTitle =
    ctx.chat && "title" in ctx.chat && ctx.chat.title ? esc(ctx.chat.title) : `Chat ${msg.chat.id}`;
  const chatLabel = ctx.chat?.type === "private" ? "Private Chat" : chatTitle;

  void notifyAdmins(
    ctx.api,
    `📥 <b>Admin Log — មេរោគត្រូវបានទប់ស្កាត់</b>\n\n` +
      `💬 <b>កន្លែង៖</b> ${chatLabel} (<code>${msg.chat.id}</code>)\n` +
      `📌 <b>ប្រភេទ៖</b> ${kindKhmer}\n` +
      `👤 <b>អ្នកផ្ញើ៖</b> ${sender}` +
      (ctx.from?.id ? ` (<code>${ctx.from.id}</code>)` : "") +
      `\n${detailLine}\n` +
      `📋 ${result.text}\n\n` +
      `${deleted ? "✅ សារត្រូវបានលុប" : "⚠️ លុបសារបរាជ័យ"} · ${muted ? "🔇 Mute ២៤ម៉ោង" : "—"}`,
  );

  // 3) Send Security Alert
  try {
    const alertMsg = await ctx.api.sendMessage(
      msg.chat.id,
      `🚨 <b>ការជូនដំណឹងសុវត្ថិភាព</b> 🚨\n\n` +
        `📌 <b>ប្រភេទ៖</b> ${kindKhmer}\n` +
        `👤 <b>អ្នកផ្ញើ៖</b> ${sender}\n` +
        `${detailLine}\n` +
        `📋 <b>ព័ត៌មានលម្អិត៖</b>\n${result.text}\n\n` +
        `${actionSummary}${autoDeleteNotice}`,
      { parse_mode: "HTML" },
    );

    // 4) Auto-Delete the alert message after configured seconds
    if (isGroup && alertMsg) {
      setTimeout(async () => {
        try {
          await ctx.api.deleteMessage(msg.chat.id, alertMsg.message_id);
        } catch {}
      }, ALERT_AUTO_DELETE_SECONDS * 1000);
    }
  } catch (err) {
    console.error("sendMessage failed:", err);
  }
}

function createBot(): Bot {
  const token = requireEnv("TELEGRAM_BOT_TOKEN");
  const bot = new Bot(token);

  // /start command
  bot.command("start", (ctx) =>
    ctx.reply(
      "🔒 <b>Bot ការពារសុវត្ថិភាពកម្រិតខ្ពស់កំពុងដំណើរការ!</b>\n\n" +
        "លោកអ្នកពុំចាំបាច់វាយពាក្យបញ្ជាអ្វីទាំងអស់ក្នុងពេលប្រើប្រាស់ធម្មតា។\n" +
        "👉 គ្រាន់តែ<b>ផ្ញើ Link (URL)</b> ឬ <b>ឯកសារ (File)</b> ចូលក្នុង Chat ឬ Group នោះ Bot នឹងពិនិត្យមេរោគដោយស្វ័យប្រវត្តិ៖\n" +
        "• បើមានមេរោគ ➡️ លុបសារចោលភ្លាម + Mute អ្នកផ្ញើ ២៤ ម៉ោង\n" +
        "• បើគ្មានមេរោគ ➡️ អនុញ្ញាតឱ្យសារនៅធម្មតា\n\n" +
        "<b>ពាក្យបញ្ជាសម្រាប់ Admin៖</b>\n" +
        "• <code>/whitelist</code> - មើលបញ្ជី Domain ទុកចិត្ត\n" +
        "• <code>/whitelist &lt;domain&gt;</code> - បន្ថែម Domain ទុកចិត្ត\n" +
        "• <code>/unwhitelist &lt;domain&gt;</code> - ដក Domain ចេញពីបញ្ជី\n" +
        "• <code>/botstatus</code> - ពិនិត្យស្ថានភាព Bot និងសុវត្ថិភាព\n" +
        "• <code>/scan &lt;url&gt;</code> - ស្កេន Link ដោយផ្ទាល់",
      { parse_mode: "HTML" },
    ),
  );

  // /botstatus command
  bot.command("botstatus", async (ctx) => {
    const domains = await getAllWhitelistedDomains();
    const stats = await getScanStats();
    const isGroup = ctx.chat.type === "group" || ctx.chat.type === "supergroup";
    const adminLogOn =
      Boolean(process.env.TELEGRAM_ADMIN_USER_IDS?.trim()) ||
      Boolean(process.env.TELEGRAM_ADMIN_LOG_CHAT_ID?.trim());
    ctx.reply(
      `🛡️ <b>ស្ថានភាពប្រព័ន្ធសុវត្ថិភាព (Bot Status)</b>\n\n` +
        `🟢 <b>ស្ថានភាព៖</b> កំពុងដំណើរការ (Online)\n` +
        `⚙️ <b>ទីតាំង៖</b> ${isGroup ? "Group Chat" : "Private Chat"}\n` +
        `📊 <b>ស្ថិតិ Scan៖</b> ${stats.scans} សរុប · ${stats.threatsBlocked} ទប់ស្កាត់\n` +
        `🎯 <b>កម្រិតចាប់មេរោគ (Threshold)៖</b>\n` +
        `  • Malicious: ≥ ${MALICIOUS_THRESHOLD}\n` +
        `  • Suspicious: ≥ ${SUSPICIOUS_THRESHOLD}\n` +
        `🔇 <b>ទណ្ឌកម្ម Auto-Mute៖</b> ${MUTE_DURATION_SECONDS / 3600} ម៉ោង\n` +
        `⏱️ <b>លុប Alert ស្វ័យប្រវត្តិ៖</b> ${ALERT_AUTO_DELETE_SECONDS} វិនាទី\n` +
        `📁 <b>ទំហំ File អតិបរមា៖</b> ${MAX_FILE_SIZE / (1024 * 1024)} MB\n` +
        `🌐 <b>Domain ក្នុងបញ្ជី Whitelist៖</b> ${domains.length} domains\n` +
        `📬 <b>Admin Log (DM/Channel)៖</b> ${adminLogOn ? "បើក ✓" : "បិទ — កំណត់ TELEGRAM_ADMIN_USER_IDS ឬ TELEGRAM_ADMIN_LOG_CHAT_ID"}`,
      { parse_mode: "HTML" },
    );
  });

  // /whitelist command (List or Add)
  bot.command("whitelist", async (ctx) => {
    const admin = await isUserAdmin(ctx);
    if (!admin) {
      return ctx.reply("⚠️ ពាក្យបញ្ជានេះសម្រាប់តែ Admin នៃ Group ប៉ុណ្ណោះ។");
    }

    const input = ctx.match.trim().split(/\s+/)[0];
    if (!input) {
      const list = await getAllWhitelistedDomains();
      return ctx.reply(
        `📋 <b>បញ្ជី Domain ទុកចិត្ត (Whitelisted Domains)៖</b>\n\n` +
          list.map((d) => `• <code>${esc(d)}</code>`).join("\n") +
          `\n\n<i>បន្ថែម Domain ថ្មី៖ /whitelist example.com</i>`,
        { parse_mode: "HTML" },
      );
    }

    const added = await addWhitelistDomain(input);
    if (!added) {
      return ctx.reply("❌ ទម្រង់ Domain មិនត្រឹមត្រូវ។ ឧទាហរណ៍៖ <code>/whitelist mysite.com</code>", {
        parse_mode: "HTML",
      });
    }

    return ctx.reply(`✅ បានបន្ថែម Domain <code>${esc(added)}</code> ទៅក្នុងបញ្ជី Whitelist ជោគជ័យ!`, {
      parse_mode: "HTML",
    });
  });

  // /unwhitelist command
  bot.command("unwhitelist", async (ctx) => {
    const admin = await isUserAdmin(ctx);
    if (!admin) {
      return ctx.reply("⚠️ ពាក្យបញ្ជានេះសម្រាប់តែ Admin នៃ Group ប៉ុណ្ណោះ។");
    }

    const input = ctx.match.trim().split(/\s+/)[0];
    if (!input) {
      return ctx.reply("⚠️ របៀបប្រើ៖ <code>/unwhitelist example.com</code>", { parse_mode: "HTML" });
    }

    const removed = await removeWhitelistDomain(input);
    if (removed) {
      return ctx.reply(`🗑️ បានដក Domain <code>${esc(input)}</code> ចេញពីបញ្ជី Whitelist រួចរាល់។`, {
        parse_mode: "HTML",
      });
    } else {
      return ctx.reply(`ℹ️ រកមិនឃើញ Domain <code>${esc(input)}</code> ក្នុងបញ្ជី Dynamic Whitelist ទេ។`, {
        parse_mode: "HTML",
      });
    }
  });

  // /scan command (Manual scan)
  bot.command("scan", async (ctx) => {
    const url = ctx.match.trim().split(/\s+/)[0];
    if (!url) return ctx.reply("⚠️ របៀបប្រើ៖ គ្រាន់តែផ្ញើ Link មកផ្ទាល់ ឬ /scan https://example.com");

    const status = await ctx.reply(`⏳ កំពុងស្កេន ${esc(url)}...`, { parse_mode: "HTML" });
    const result = await scanUrl(url);
    await ctx.api.editMessageText(
      ctx.chat.id,
      status.message_id,
      `🔍 <b>លទ្ធផលស្កេន</b>\n\n🔗 <code>${esc(url)}</code>\n\n📋 <b>ស្ថានភាព៖</b>\n${result.text}`,
      { parse_mode: "HTML" },
    );
  });

  // Auto-scan documents / files
  bot.on("message:document", async (ctx) => {
    const doc = ctx.msg.document;
    if (doc.file_size && doc.file_size > MAX_FILE_SIZE) return;

    const name = doc.file_name ?? "file";

    try {
      const file = await ctx.api.getFile(doc.file_id);
      if (!file.file_path) return;

      const res = await fetch(`https://api.telegram.org/file/bot${token}/${file.file_path}`);
      if (!res.ok) throw new Error(`Telegram file download failed: ${res.status}`);

      const result = await scanFile(await res.arrayBuffer(), name);

      if (result.dangerous) {
        await handleThreat(ctx, "File", `📄 <b>ឈ្មោះឯកសារ៖</b> <code>${esc(name)}</code>`, result);
        return;
      }
      if (result.text.startsWith("❌")) {
        console.error("File scan error:", name, result.text);
      }
    } catch (err) {
      console.error("Error scanning document:", err);
    }
  });

  // Auto-scan links in all messages (and edited messages)
  bot.on(["message", "edited_message"], async (ctx, next) => {
    const msg = ctx.msg;
    const urls = extractUrls(msg);
    if (urls.length === 0) return next();

    for (const url of urls) {
      const result = await scanUrl(url);
      if (result.dangerous) {
        await handleThreat(ctx, "Link", `🔗 <b>តំណភ្ជាប់៖</b> <code>${esc(url)}</code>`, result);
        return; // message deleted
      }
      // If safe: silent, don't reply
    }
    return next();
  });

  bot.catch((err) => console.error("Bot error:", err.error));
  return bot;
}

let instance: Bot | undefined;
export function getBot(): Bot {
  return (instance ??= createBot());
}
