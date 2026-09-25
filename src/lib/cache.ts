import { Redis } from "@upstash/redis";
import { CACHE_TTL_SECONDS } from "./config";

export type CachedVerdict = { dangerous: boolean; text: string };

const memory = new Map<string, { value: CachedVerdict; expires: number }>();
let redis: Redis | null | undefined;

export function getRedis(): Redis | null {
  if (redis !== undefined) return redis;
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
  redis = url && token ? new Redis({ url, token }) : null;
  return redis;
}

export async function getCached(key: string): Promise<CachedVerdict | null> {
  const r = getRedis();
  if (r) {
    try {
      return (await r.get<CachedVerdict>(`vt:${key}`)) ?? null;
    } catch (err) {
      console.error("Redis get failed:", err);
    }
  }
  const hit = memory.get(key);
  if (!hit) return null;
  if (hit.expires < Date.now()) {
    memory.delete(key);
    return null;
  }
  return hit.value;
}

export async function setCached(key: string, value: CachedVerdict): Promise<void> {
  const r = getRedis();
  if (r) {
    try {
      await r.set(`vt:${key}`, value, { ex: CACHE_TTL_SECONDS });
      return;
    } catch (err) {
      console.error("Redis set failed:", err);
    }
  }
  memory.set(key, { value, expires: Date.now() + CACHE_TTL_SECONDS * 1000 });
}
