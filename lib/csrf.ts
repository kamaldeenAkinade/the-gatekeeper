import { randomBytes, createHmac, timingSafeEqual } from "crypto";

export function generateCsrfToken(sessionId: string): string {
  const nonce = randomBytes(16).toString("hex");
  const secret = process.env.SESSION_SECRET as string;
  const sig = createHmac("sha256", secret)
    .update(`${sessionId}:${nonce}`)
    .digest("hex");
  return `${nonce}.${sig}`;
}

export function verifyCsrfToken(token: string, sessionId: string): boolean {
  try {
    const [nonce] = token.split(".");
    const expected = generateCsrfToken(sessionId);
    const a = Buffer.from(token);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
