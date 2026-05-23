import { randomBytes, createHmac, timingSafeEqual } from "crypto";

const SECRET = process.env.SESSION_SECRET as string;

export function createVerificationToken(email: string): string {
  const nonce = randomBytes(24).toString("hex");
  const sig = createHmac("sha256", SECRET)
    .update(`verify:${email}:${nonce}`)
    .digest("hex");
  return `${nonce}.${sig}`;
}

export function verifyEmailToken(token: string, email: string): boolean {
  try {
    const [nonce] = token.split(".");
    const expected = createVerificationToken(email);
    const a = Buffer.from(token);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
