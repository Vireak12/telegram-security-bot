import { getRedis } from "./cache";

const REDIS_SCANS_KEY = "vt:stats:scans";
const REDIS_THREATS_KEY = "vt:stats:threats";

let memoryScans = 0;
let memoryThreats = 0;

async function incrRedis(key: string): Promise<number | null> {
  const r = getRedis();
  if (!r) return null;
  try {
    return await r.incr(key);
  } catch (err) {
    console.error(`Redis incr ${key} failed:`, err);
    return null;
  }
}

export async function recordScan(): Promise<void> {
  memoryScans += 1;
  await incrRedis(REDIS_SCANS_KEY);
}

export async function recordThreatBlocked(): Promise<void> {
  memoryThreats += 1;
  await incrRedis(REDIS_THREATS_KEY);
}

export async function getScanStats(): Promise<{ scans: number; threatsBlocked: number }> {
  const r = getRedis();
  if (r) {
    try {
      const [scans, threatsBlocked] = await Promise.all([
        r.get<number>(REDIS_SCANS_KEY),
        r.get<number>(REDIS_THREATS_KEY),
      ]);
      return {
        scans: scans ?? memoryScans,
        threatsBlocked: threatsBlocked ?? memoryThreats,
      };
    } catch (err) {
      console.error("Redis get scan stats failed:", err);
    }
  }
  return { scans: memoryScans, threatsBlocked: memoryThreats };
}
