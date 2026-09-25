import { createHash } from "node:crypto";
import { getCached, setCached } from "./cache";
import { MALICIOUS_THRESHOLD, SUSPICIOUS_THRESHOLD, requireEnv } from "./config";
import { recordScan } from "./stats";
import { withVtRateLimit } from "./vt-rate-limit";
import { isWhitelisted } from "./whitelist";

const VT_API = "https://www.virustotal.com/api/v3";
const POLL_INTERVAL_MS = 1000;
const MAX_POLLS = 12;

/** `cacheable` is false for errors/timeouts so they never get cached for 24h. */
export type ScanResult = { dangerous: boolean; text: string; cacheable: boolean };

type Stats = { malicious?: number; suspicious?: number; undetected?: number };

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const vtHeaders = () => ({
  accept: "application/json",
  "x-apikey": requireEnv("VIRUSTOTAL_API_KEY"),
});

const failure = (text: string): ScanResult => ({ dangerous: false, text, cacheable: false });

function verdict(stats: Stats, label = ""): ScanResult {
  const malicious = stats.malicious ?? 0;
  const suspicious = stats.suspicious ?? 0;
  const undetected = stats.undetected ?? 0;

  if (malicious >= MALICIOUS_THRESHOLD) {
    return {
      dangerous: true,
      cacheable: true,
      text: `🔴 <b>មានគ្រោះថ្នាក់${label}!</b>\n🦠 មេរោគ (Malicious)៖ ${malicious}\n⚠️ សង្ស័យ (Suspicious)៖ ${suspicious}`,
    };
  }
  if (suspicious >= SUSPICIOUS_THRESHOLD) {
    return {
      dangerous: true,
      cacheable: true,
      text: `🟡 <b>គួរឱ្យសង្ស័យកម្រិតខ្ពស់${label}!</b>\n⚠️ សង្ស័យ (Suspicious)៖ ${suspicious}\n🛡️ សុវត្ថិភាព៖ ${undetected}`,
    };
  }
  if (suspicious > 0) {
    // Under threshold (e.g. 1 vendor out of 90) -> Treated as safe to prevent false positive deletion
    return {
      dangerous: false,
      cacheable: true,
      text: `🟡 <b>សង្ស័យកម្រិតស្រាល${label}</b> (អាចជា False Positive)\n⚠️ សង្ស័យ៖ ${suspicious}\n🛡️ សុវត្ថិភាព៖ ${undetected}`,
    };
  }
  return {
    dangerous: false,
    cacheable: true,
    text: `✅ <b>មានសុវត្ថិភាព${label}!</b> ✓ Antivirus ចំនួន ${undetected} បញ្ជាក់ថាសុវត្ថិភាព`,
  };
}

/** Throttled: VT free tier quota (POST scan, file lookup). */
async function vtFetchQuota(input: string, init?: RequestInit): Promise<Response> {
  return withVtRateLimit(() => fetch(input, init));
}

function vtUrlId(url: string): string {
  return Buffer.from(url).toString("base64url");
}

/** Instant report for URLs VirusTotal already knows (e.g. eicar.org). */
async function fetchKnownUrlReport(url: string): Promise<ScanResult | null> {
  const res = await vtFetchQuota(`${VT_API}/urls/${vtUrlId(url)}`, { headers: vtHeaders() });
  if (res.status === 429) return failure("❌ លើសកម្រិតកំណត់ API (Rate limit)");
  if (!res.ok) return null;
  const json = await res.json();
  const stats = json.data?.attributes?.last_analysis_stats as Stats | undefined;
  if (!stats) return null;
  return verdict(stats);
}

async function getAnalysisReport(analysisId: string): Promise<ScanResult> {
  for (let i = 0; i < MAX_POLLS; i++) {
    const res = await fetch(`${VT_API}/analyses/${analysisId}`, { headers: vtHeaders() });

    if (res.status === 429) return failure("❌ លើសកម្រិតកំណត់ API របស់ VirusTotal (Rate limit)");
    if (!res.ok) {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }

    const json = await res.json();
    const attrs = json.data.attributes;
    if (attrs.status === "queued" || attrs.status === "in-progress") {
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    return verdict(attrs.stats ?? {});
  }
  return failure("⏱️ អស់ពេលកំណត់ក្នុងការស្កេន (Timed out)");
}

async function withCache(key: string, run: () => Promise<ScanResult>): Promise<ScanResult> {
  const hit = await getCached(key);
  if (hit) return { ...hit, text: `${hit.text} (⚡ ពី Cache)`, cacheable: false };

  const result = await run();
  if (result.cacheable) await setCached(key, { dangerous: result.dangerous, text: result.text });
  return result;
}

export async function scanUrl(url: string): Promise<ScanResult> {
  if (await isWhitelisted(url)) {
    return { dangerous: false, cacheable: false, text: "✅ <b>មានសុវត្ថិភាព!</b> (Domain ស្ថិតក្នុងបញ្ជីទុកចិត្ត)" };
  }

  return withCache(`url:${url}`, async () => {
    await recordScan();
    try {
      const known = await fetchKnownUrlReport(url);
      if (known && known.cacheable) return known;

      const res = await vtFetchQuota(`${VT_API}/urls`, {
        method: "POST",
        headers: vtHeaders(),
        body: new URLSearchParams({ url }),
      });
      if (res.status === 429) return failure("❌ លើសកម្រិតកំណត់ API (Rate limit)");
      if (!res.ok) return failure(`❌ កំហុសពី VirusTotal៖ ${res.status}`);

      const json = await res.json();
      return await getAnalysisReport(json.data.id);
    } catch (err) {
      console.error("scanUrl failed:", err);
      return failure("❌ ការស្កេនបរាជ័យ");
    }
  });
}

export async function scanFile(data: ArrayBuffer, fileName: string): Promise<ScanResult> {
  const hash = createHash("sha256").update(new Uint8Array(data)).digest("hex");

  return withCache(`file:${hash}`, async () => {
    await recordScan();
    try {
      // 1) Already known to VirusTotal? Use the existing report.
      const lookup = await vtFetchQuota(`${VT_API}/files/${hash}`, { headers: vtHeaders() });
      if (lookup.ok) {
        const json = await lookup.json();
        return verdict(json.data.attributes.last_analysis_stats ?? {}, " (រកឃើញតាម Hash)");
      }
      if (lookup.status === 429) return failure("❌ លើសកម្រិតកំណត់ API (Rate limit)");

      // 2) Unknown file -> upload and poll.
      const form = new FormData();
      form.append("file", new Blob([data]), fileName);

      const upload = await vtFetchQuota(`${VT_API}/files`, {
        method: "POST",
        headers: vtHeaders(),
        body: form,
      });
      if (upload.status === 429) return failure("❌ លើសកម្រិតកំណត់ API (Rate limit)");
      if (!upload.ok) return failure(`❌ បរាជ័យក្នុងការ Upload៖ ${upload.status}`);

      const json = await upload.json();
      return await getAnalysisReport(json.data.id);
    } catch (err) {
      console.error("scanFile failed:", err);
      return failure("❌ ការស្កេនបរាជ័យ");
    }
  });
}
