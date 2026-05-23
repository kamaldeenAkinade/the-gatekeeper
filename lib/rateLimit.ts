type Window = { count: number; resetAt: number };
const store = new Map<string, Window>();

export function allow(
  key: string,
  maxAttempts = 5,
  windowMs = 15 * 60 * 1000
): boolean {
  const now = Date.now();
  const existing = store.get(key);

  if (!existing || now > existing.resetAt) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (existing.count >= maxAttempts) {
    return false;
  }

  existing.count += 1;
  return true;
}
