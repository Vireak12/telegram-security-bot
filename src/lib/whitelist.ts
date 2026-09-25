import { getRedis } from "./cache";
import { WHITELIST_DOMAINS } from "./config";

const dynamicMemoryWhitelist = new Set<string>();
const REDIS_WHITELIST_KEY = "vt:dynamic_whitelist";

/**
 * Normalizes input string to a clean domain name (lowercase, stripped protocol and path).
 */
export function normalizeDomain(input: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(input) ? input : `http://${input}`;
    const host = new URL(withScheme).hostname.toLowerCase();
    return host || null;
  } catch {
    return null;
  }
}

/**
 * Gets all whitelisted domains (hardcoded + dynamically added).
 */
export async function getAllWhitelistedDomains(): Promise<string[]> {
  const all = new Set<string>(WHITELIST_DOMAINS);
  for (const d of dynamicMemoryWhitelist) all.add(d);

  const r = getRedis();
  if (r) {
    try {
      const list = await r.smembers<string[]>(REDIS_WHITELIST_KEY);
      if (list && Array.isArray(list)) {
        for (const d of list) {
          dynamicMemoryWhitelist.add(d);
          all.add(d);
        }
      }
    } catch (err) {
      console.error("Failed to read dynamic whitelist from Redis:", err);
    }
  }

  return [...all];
}

/**
 * Checks whether a given URL or domain is whitelisted.
 */
export async function isWhitelisted(input: string): Promise<boolean> {
  const host = normalizeDomain(input);
  if (!host) return false;

  const domains = await getAllWhitelistedDomains();
  return domains.some((d) => host === d || host.endsWith(`.${d}`));
}

/**
 * Adds a domain dynamically to the whitelist.
 */
export async function addWhitelistDomain(input: string): Promise<string | null> {
  const domain = normalizeDomain(input);
  if (!domain) return null;

  dynamicMemoryWhitelist.add(domain);
  const r = getRedis();
  if (r) {
    try {
      await r.sadd(REDIS_WHITELIST_KEY, domain);
    } catch (err) {
      console.error("Failed to add domain to Redis whitelist:", err);
    }
  }
  return domain;
}

/**
 * Removes a domain from the dynamic whitelist.
 */
export async function removeWhitelistDomain(input: string): Promise<boolean> {
  const domain = normalizeDomain(input);
  if (!domain) return false;

  const deletedFromMem = dynamicMemoryWhitelist.delete(domain);
  let deletedFromRedis = false;
  const r = getRedis();
  if (r) {
    try {
      const res = await r.srem(REDIS_WHITELIST_KEY, domain);
      deletedFromRedis = res > 0;
    } catch (err) {
      console.error("Failed to remove domain from Redis whitelist:", err);
    }
  }

  return deletedFromMem || deletedFromRedis;
}
