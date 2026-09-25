let chain: Promise<void> = Promise.resolve();

/**
 * Serializes VirusTotal HTTP calls without sleeping between requests. Telegram webhook
 * work must never wait on the free-tier quota; VirusTotal 429 responses are handled by
 * the caller and reported as a scan failure.
 */
export function withVtRateLimit<T>(run: () => Promise<T>): Promise<T> {
  const job = chain.then(run);
  chain = job.then(
    () => undefined,
    () => undefined,
  );
  return job;
}
