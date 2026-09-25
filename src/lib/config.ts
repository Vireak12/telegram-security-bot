export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing environment variable: ${name}`);
  return value;
}

// Telegram's cloud Bot API only lets bots download files up to 20 MB.
export const MAX_FILE_SIZE = 20 * 1024 * 1024;

// Protects your VirusTotal quota (free tier: 4 requests/min).
export const MAX_URLS_PER_MESSAGE = 3;

export const CACHE_TTL_SECONDS = 24 * 60 * 60;

// Security Sensitivity Thresholds:
// Malicious: 1 or more malicious detections -> danger
// Suspicious: 2 or more suspicious detections (if 0 malicious) -> danger
export const MALICIOUS_THRESHOLD = 1;
export const SUSPICIOUS_THRESHOLD = 2;

// Auto-delete alert message in group after this duration (seconds) to keep chat clean:
export const ALERT_AUTO_DELETE_SECONDS = 60;

// Auto-mute duration for malicious senders (24 hours in seconds):
export const MUTE_DURATION_SECONDS = 24 * 60 * 60;

export const WHITELIST_DOMAINS = [
  "google.com",
  "youtube.com",
  "facebook.com",
  "instagram.com",
  "github.com",
  "telegram.org",
  "t.me",
  "wikipedia.org",
  "microsoft.com",
];

