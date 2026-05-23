# The Gatekeeper — Security Audit

> Six vulnerabilities examined honestly. Each one gets the actual broken code,
> a clear explanation of why it matters, and a concrete fix you can apply today.
> Written so you understand the *thinking*, not just the patch.

---

## How to Read This Audit

Every finding follows the same structure:

- **The vulnerability** — what exactly is wrong
- **The vulnerable code** — the exact file and line that contains it
- **Why an attacker cares** — the real-world consequence, not theory
- **The fix** — working code that closes the gap
- **Why the fix works** — the reasoning behind the change, not just the result

A patch you don't understand is just a magic spell. The goal here is understanding.

---

## Issue 1 — Timing Attack on Email Lookup

### The vulnerability

When a user tries to log in with an email that does not exist in the database, the server responds almost instantly. When they try with a real email but a wrong password, the server pauses for roughly 260 milliseconds — the time bcrypt takes to re-hash the attempt.

An attacker does not need to crack any password to exploit this. They just measure how long the server takes to respond. A fast response means "that email is not registered here." A slow response means "that email exists, the password was just wrong." They now have a list of real accounts without guessing a single password correctly.

This is called a **timing side-channel**: information leaked through *how long* something takes rather than through error messages or response bodies.

### The vulnerable code

```
app/actions/auth.ts : 66–68
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return { errors: { email: ["Invalid email or password"] } };
  }
```

When `!user` is true, the function returns immediately on line 68. `bcrypt.compare` — which lives on line 71 — is never called. That's the asymmetry. Email not found → instant return. Email found → bcrypt delay → return.

### Why an attacker cares

With a list of, say, one million email addresses from any data breach, an attacker can fire each one at the login endpoint and sort the responses by latency: fast ones (non-accounts) go in the bin; slow ones (real accounts) go on a target list. They now know exactly which addresses have accounts on your service. They can sell that list, send targeted phishing, or focus brute-force attempts where they know an account exists. They learned all of this without breaking a single password.

### The fix

Always run `bcrypt.compare`, even when the user doesn't exist. Use a dummy hash so the timing of the "user not found" path matches the timing of the "user found, wrong password" path.

```typescript
// app/actions/auth.ts

// Place this constant at the top of the file, outside any function.
// It is a valid bcrypt hash of a throwaway string, generated once.
// Its only purpose is to consume ~260ms when compare() is called against it.
const DUMMY_HASH =
  "$2a$12$ZeU7mxBVhNsXTZaGM3NuJ.LJv3mq9YPlOd5WtmGYjmKrv6rkuGOaS";

export async function loginAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  // ... Zod validation unchanged ...

  const user = await prisma.user.findUnique({ where: { email } });

  // Always compare. If the user doesn't exist, compare against the dummy hash.
  // The dummy compare takes the same ~260ms as a real one, so timing is equal.
  const hashToCompare = user?.password ?? DUMMY_HASH;
  const valid = await bcrypt.compare(password, hashToCompare);

  // Combine both failure modes into one check — same message, same timing.
  if (!user || !valid) {
    return { errors: { email: ["Invalid email or password"] } };
  }

  // ... session creation unchanged ...
}
```

### Why the fix works

`bcrypt.compare(password, DUMMY_HASH)` does the full bcrypt work — 4,096 rounds of hashing — even though the result will always be `false`. The server now takes roughly 260ms for *both* the "email not found" case and the "wrong password" case. An attacker measuring response times sees the same number for every attempt. The timing side-channel closes because there is no longer a timing difference to measure.

The key insight: you are not trying to hide *that* the email doesn't exist (you already say "Invalid email or password" in both cases). You are hiding the *timing signature* that revealed it anyway.

---

## Issue 2 — Weak Cookie Configuration

### The vulnerability

The session cookie has three flags set: `secure`, `httpOnly`, and `sameSite`. Two of them are fine. One is understated, and one important flag is missing entirely.

```
lib/session.ts : 13–17
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
  },
```

**Problem A — `sameSite: "lax"` is not the strongest option.**
`"lax"` prevents the cookie from being sent on *embedded* cross-site requests (images, iframes, fetch calls from other sites). But it *does* allow the cookie to be sent when a user clicks a link on another site that navigates to your app. For most auth cookies, `"strict"` is more appropriate because it blocks the cookie on all cross-site navigations, not just embedded ones.

**Problem B — No `maxAge` means the cookie never expires.**
Without a `maxAge`, the cookie is a "session cookie" — the browser is supposed to delete it when the tab closes. In practice, most modern browsers restore sessions after a restart, keeping "session cookies" alive for days or weeks. An account stays logged in indefinitely until the user manually logs out. This is the same as not having a logout timeout at all.

### The vulnerable code (both files)

```
lib/session.ts : 10–18     ← where sessionOptions is defined
proxy.ts : 5–13            ← a duplicate of the same options
```

Note: the options are duplicated. Fixing one and forgetting the other would create an inconsistency where the page-level session and the proxy-level session behave differently. Both must be fixed.

### Why an attacker cares

Without `maxAge`, a session stolen today is valid next month. If a user logs into your app on a shared computer and forgets to click "Log Out," their session persists indefinitely. `sameSite: "lax"` leaves a small window where crafted links (say, in a phishing email that navigates to your site) can carry the cookie along, enabling cross-site request forgery on GET-based state changes if any ever exist.

### The fix

Update both `lib/session.ts` and `proxy.ts`. Since the options are duplicated, extract them to a shared location to guarantee they stay in sync.

```typescript
// lib/session.ts — full revised file

import { getIronSession, type SessionOptions } from "iron-session";
import { cookies } from "next/headers";

export interface SessionData {
  userId: string;
  name: string;
  email: string;
}

export const sessionOptions: SessionOptions = {
  cookieName: "gatekeeper_session",
  password: process.env.SESSION_SECRET as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict",   // upgraded: blocks all cross-site navigation, not just embeds
    maxAge: 60 * 60 * 8,  // 8 hours in seconds — session expires even if user never logs out
  },
};

export async function getSession() {
  const session = await getIronSession<SessionData>(
    await cookies(),
    sessionOptions
  );
  return session;
}
```

```typescript
// proxy.ts — import the shared options instead of redefining them

import { NextRequest, NextResponse } from "next/server";
import { getIronSession } from "iron-session";
import { type SessionData, sessionOptions } from "@/lib/session"; // ← shared, not duplicated

export async function proxy(req: NextRequest) {
  const res = NextResponse.next();
  const session = await getIronSession<SessionData>(req, res, sessionOptions);

  if (!session.userId) {
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("from", req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return res;
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
```

### Why the fix works

`sameSite: "strict"` makes the browser never send the cookie on any cross-site request — navigation, fetch, form post, image load. An attacker on another site cannot trigger a request to your app that carries the session.

`maxAge: 60 * 60 * 8` tells the browser to hard-delete the cookie after 8 hours, regardless of what the user does. Even if they leave the tab open for a week, the session expires. This limits the damage window for a stolen or abandoned session.

Exporting `sessionOptions` from `lib/session.ts` and importing it in `proxy.ts` means you have one source of truth. The proxy and the page can never fall out of sync because they literally share the same object.

---

## Issue 3 — CSRF Protection: What Exists and What Does Not

### The vulnerability

CSRF (Cross-Site Request Forgery) is when a malicious website tricks your browser into making a request to a different website using your existing session. Because browsers automatically attach cookies to requests, the victim's session cookie goes along for the ride, and the target site sees an authenticated request that the user never intended.

The app has *partial* CSRF protection from two sources:
1. `sameSite: "lax"` (upgraded to `"strict"` in Issue 2) prevents the cookie from riding cross-site requests
2. Next.js Server Actions check the `Origin` header by default in Next.js 14+

However, these protections have gaps worth understanding:

**Gap A — The `Origin` check only applies when JavaScript is running.**
Server Actions are called as POST requests with a specific `Next-Action` header. When the form falls back to a native HTML submission (no JavaScript), the browser sends a standard POST without the `Next-Action` header, bypassing the Server Action CSRF check and going to the same URL as a regular form.

**Gap B — There are no explicit CSRF tokens in the HTML.**
The traditional defence is a hidden `<input>` containing a secret token generated per-session or per-form. If that token is not present in the request, the server rejects it. Our forms have no such tokens.

### The vulnerable code

```
app/signup/SignupForm.tsx : 15
  <form action={action} className="space-y-5">

app/login/LoginForm.tsx : 13
  <form action={action} className="space-y-5">
```

Neither form contains a hidden CSRF token field.

### Why an attacker cares

With `sameSite: "lax"` (before the fix in Issue 2), a crafted page on `evil.com` could contain:

```html
<form method="POST" action="https://yourapp.com/api/sensitive-endpoint">
  <input name="target" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
```

When the victim visits `evil.com` while logged into your app, this form silently submits with their session cookie attached. With `sameSite: "strict"` the cookie is withheld and the attack fails. The `"strict"` fix from Issue 2 is the primary defence here — but a belt-and-suspenders approach also adds explicit tokens.

### The fix

For state-changing actions in the app, add a CSRF token that is tied to the session and verified on the server before the action runs.

```typescript
// lib/csrf.ts — new file

import { randomBytes, createHmac } from "crypto";

export function generateCsrfToken(sessionId: string): string {
  const nonce = randomBytes(16).toString("hex");
  const secret = process.env.SESSION_SECRET as string;
  // HMAC ties the token to the specific session — it cannot be reused for another user
  const sig = createHmac("sha256", secret)
    .update(`${sessionId}:${nonce}`)
    .digest("hex");
  return `${nonce}.${sig}`;
}

export function verifyCsrfToken(token: string, sessionId: string): boolean {
  try {
    const [nonce] = token.split(".");
    const expected = generateCsrfToken(sessionId); // regenerate and compare
    // Avoid timing attacks on token comparison
    const a = Buffer.from(token);
    const b = Buffer.from(expected);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}
```

On pages with forms, generate the token server-side and embed it as a hidden field. In the Server Action, verify it before processing. The exact implementation depends on your session shape — the important concept is: **the token must be unguessable, tied to the session, and verified on the server before any state change.**

Because this app already uses `sameSite: "strict"` (from Issue 2) and Next.js Server Actions' built-in `Origin` check, CSRF protection is already strong. Explicit tokens are an additional layer for defence in depth.

---

## Issue 4 — SESSION_SECRET: Placeholder Value and No Validation

### The vulnerability

The `SESSION_SECRET` is the master key that iron-session uses to encrypt and decrypt every session cookie. If an attacker knows this key, they can:
- Decrypt any session cookie and read its contents
- Forge a completely fake session cookie that your app will accept as valid
- Log in as any user without a password by minting a cookie with their `userId`

The current `.env` file ships with a placeholder value:

```
.env : 9
  SESSION_SECRET="change-me-to-a-32-char-or-longer-secret-string"
```

The string literally contains the words "change me." If a developer deploys without changing this — easy to do, especially under deadline pressure — the secret is known to anyone who has ever seen this codebase, including everyone who reads this repository on GitHub.

Additionally, the code reads it without checking whether it was actually changed:

```
lib/session.ts : 12
  password: process.env.SESSION_SECRET as string,
```

The `as string` cast tells TypeScript "trust me, this is a string" — but it does nothing at runtime. If `SESSION_SECRET` is the placeholder, or is missing entirely, the code continues silently.

### Why an attacker cares

With the known placeholder secret, an attacker can craft a valid iron-session cookie manually:

```bash
# Pseudocode — real tools exist for this
node -e "
  const { sealData } = require('iron-session');
  sealData({ userId: 'admin_id_here', name: 'Admin', email: 'admin@example.com' },
    { password: 'change-me-to-a-32-char-or-longer-secret-string' })
  .then(console.log);
"
```

They paste that output into their browser's `gatekeeper_session` cookie. The server decrypts it successfully, finds a `userId`, and shows them the dashboard — bypassing every other layer of auth. The entire bcrypt hashing, the Zod validation, the database check — all made irrelevant by one known string.

This is not hypothetical. Public codebases with default secrets are actively scanned for this by automated tools.

### The fix

Two parts: guard at startup, and a stronger `.env` default.

**Part 1 — Add a startup guard in `lib/session.ts`:**

```typescript
// lib/session.ts

// Run this check once when the module loads, before any session is created.
// In production, a bad secret fails loudly at boot rather than silently at runtime.
function assertSessionSecret() {
  const secret = process.env.SESSION_SECRET;

  if (!secret) {
    throw new Error(
      "[session] SESSION_SECRET is not set. Add it to your .env file."
    );
  }

  if (secret.length < 32) {
    throw new Error(
      `[session] SESSION_SECRET is too short (${secret.length} chars). ` +
      "It must be at least 32 characters."
    );
  }

  const knownPlaceholders = [
    "change-me-to-a-32-char-or-longer-secret-string",
    "secret",
    "changeme",
    "your-secret-here",
  ];
  if (knownPlaceholders.includes(secret)) {
    throw new Error(
      "[session] SESSION_SECRET is set to a known placeholder. " +
      "Generate a real secret: openssl rand -base64 32"
    );
  }
}

assertSessionSecret();

// ... rest of session.ts unchanged ...
```

**Part 2 — Improve `.env` to guide developers:**

```bash
# .env

DATABASE_URL="file:./dev.db"

# Generate with: openssl rand -base64 32
# Must be at least 32 characters. Never commit the real value to git.
SESSION_SECRET=""
```

An empty string will trigger the guard immediately on first run. The developer sees a clear error with the exact command to generate a proper secret.

### Why the fix works

`assertSessionSecret()` runs at module-load time — the moment `lib/session.ts` is first imported. That happens at server startup, before the first request is ever processed. A misconfigured secret fails loudly and immediately with a clear message, rather than failing silently in production days later when someone exploits it.

The error messages include the fix command (`openssl rand -base64 32`) so a developer hitting this for the first time knows exactly what to do. Failing with good instructions is more useful than failing with a generic crash.

---

## Issue 5 — Password Policy Weaknesses

### The vulnerability

The current Zod schema enforces:
- Minimum 8 characters
- At least one uppercase letter
- At least one number

```
lib/validations.ts : 6–10
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
```

**Weakness A — No maximum length. bcrypt silently truncates at 72 bytes.**

bcrypt is designed to accept passwords of any length but internally operates on only the first 72 bytes. A user who sets a 90-character password is unknowingly protected by only the first 72 characters. The remaining 18 are silently dropped. Another user who later changes their password to "the first 72 characters of the old one" would log in successfully, which is not what anyone expects.

This is also a denial-of-service vector: bcrypt is intentionally slow. A malicious user can submit a 10,000-character password and force the server to attempt to hash a massive input (though bcrypt itself only processes 72 bytes, some implementations still copy the full input first).

**Weakness B — The policy incentivises predictable patterns.**

Every rule you add is a hint about what you *don't* require. The classic user response to "min 8 chars, 1 uppercase, 1 number" is `Password1`. It satisfies every rule. It is also one of the most common passwords on every breach list in existence. The policy creates a false sense of security.

**Weakness C — No check against commonly breached passwords.**

A password like `Welcome1` passes every rule but appears in every major credential stuffing list. The policy gives it a green light while bcrypt dutifully hashes it, and now you have a "securely hashed" version of a completely guessable password sitting in your database.

### The fix

**For Weakness A — add `max(72)`:**

```typescript
// lib/validations.ts

export const signupSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(72, "Password must be at most 72 characters") // ← bcrypt's hard limit
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
});
```

**For Weakness C — add a check against a deny list of common passwords:**

```typescript
// lib/validations.ts

// A small illustrative list. In production, use the Have I Been Pwned API
// or ship a local copy of the top 10,000 breached passwords.
const COMMON_PASSWORDS = new Set([
  "password1", "Password1", "Password1!", "Welcome1",
  "Qwerty123", "Summer2024", "Winter2024", "January1",
  "Admin1234", "Letmein1",
]);

export const signupSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(72, "Password must be at most 72 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one number")
    .refine(
      (pw) => !COMMON_PASSWORDS.has(pw),
      "This password is too common. Please choose something less predictable."
    ),
});
```

For production, integrate with the Have I Been Pwned Passwords API (which uses k-anonymity — you send the first 5 characters of the SHA-1 hash, never the full password) to check against over 800 million real-world breached passwords.

### Why the fix works

`max(72)` makes the bcrypt truncation limit explicit and visible. Users who write passphrases longer than 72 characters are told now, clearly, rather than silently discovering it later when half their password still works. It also prevents the large-input denial-of-service scenario.

The `refine` check runs as a custom validation step inside Zod, after all the regex rules pass. It only activates when everything else is already satisfied — so the error message is specific ("too common") rather than competing with other errors. It runs on the server (inside the `"use server"` action) so it cannot be bypassed by disabling JavaScript.

---

## Issue 6 — No Rate Limiting

### The vulnerability

The login and signup endpoints will accept and process as many requests per second as the server can handle. There are no limits.

```
app/actions/auth.ts : 50–83   ← loginAction, no rate limiting
app/actions/auth.ts : 14–48   ← signupAction, no rate limiting
```

This creates three concrete problems:

**Problem A — Brute force on login.**
Even with bcrypt at cost 12 (each attempt takes ~260ms server-side), an attacker with a distributed botnet can test thousands of email-and-password combinations per day across many source IPs. bcrypt slows down each individual attempt but does nothing to limit the *number* of attempts.

**Problem B — Account enumeration via signup.**
`signupAction` on line 31–34 returns "An account with this email already exists" when a registered email is submitted. Without rate limiting, an attacker can send millions of email addresses and collect which ones are registered — similar to Issue 1 but through the signup path where the different error message is intentional UX.

**Problem C — Resource exhaustion.**
Every login request runs `prisma.user.findUnique` (a database query) and `bcrypt.compare` (an expensive CPU operation). Unlimited login requests can overwhelm the database connection pool and saturate a CPU core, degrading the service for legitimate users. This is a denial-of-service vector that does not require any credentials.

### The fix

A full solution uses a distributed store (Redis) because Next.js can run across many serverless instances that do not share memory. But the core concept can be demonstrated with an in-memory approach that works correctly on a single-process server.

```typescript
// lib/rateLimit.ts — new file

type Window = { count: number; resetAt: number };
const store = new Map<string, Window>();

/**
 * Returns true if the request is allowed, false if it should be blocked.
 *
 * key        — a string identifying the subject (e.g., IP address or email)
 * maxAttempts — number of requests allowed in the window
 * windowMs   — the window size in milliseconds
 */
export function allow(
  key: string,
  maxAttempts = 5,
  windowMs = 15 * 60 * 1000   // 15 minutes
): boolean {
  const now = Date.now();
  const existing = store.get(key);

  if (!existing || now > existing.resetAt) {
    store.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  if (existing.count >= maxAttempts) {
    return false;  // blocked
  }

  existing.count += 1;
  return true;  // allowed
}
```

```typescript
// app/actions/auth.ts — updated loginAction (top of function)

import { headers } from "next/headers";
import { allow } from "@/lib/rateLimit";

export async function loginAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  // Get the requester's IP address from the forwarded header.
  // In production behind a reverse proxy (Vercel, Nginx), this is the real IP.
  const ip = (await headers()).get("x-forwarded-for") ?? "127.0.0.1";
  const email = String(formData.get("email") ?? "").toLowerCase();

  // Rate limit by IP (catches botnets) AND by email (catches distributed IP attacks).
  if (!allow(`login:ip:${ip}`) || !allow(`login:email:${email}`, 10)) {
    return {
      message:
        "Too many login attempts. Please wait 15 minutes before trying again.",
    };
  }

  // ... rest of loginAction unchanged ...
}
```

Apply the same pattern to `signupAction` to prevent signup spam:

```typescript
export async function signupAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  const ip = (await headers()).get("x-forwarded-for") ?? "127.0.0.1";

  if (!allow(`signup:ip:${ip}`, 3, 60 * 60 * 1000)) {  // 3 signups per hour per IP
    return {
      message: "Too many signup attempts from this location. Please try again later.",
    };
  }

  // ... rest of signupAction unchanged ...
}
```

### Why the fix works

**Dual keying** (by IP *and* by email) addresses two distinct attack shapes:

- An attacker using one IP with many email-password guesses is caught by the IP key.
- An attacker using a botnet with thousands of IPs all targeting one account is caught by the email key — even if each IP only attempts once, the email-level counter sees all of them.

**Different limits per endpoint** reflect different risk profiles: 5 login attempts per 15 minutes per IP is enough for a legitimate user who fat-fingers their password a few times but stops a rapid-fire guesser. 3 signups per hour per IP stops account-factory scripts.

**The production caveat to understand clearly:** `Map` lives in the memory of one process. In a serverless deployment (Vercel, AWS Lambda), each function instance is isolated — a botnet that hits 50 different server instances would bypass a Map-based limiter entirely, because each instance sees only its own fraction of the traffic. For real production, replace the `Map` with a Redis atomic counter, or use a service like Upstash Rate Limit that wraps this pattern with a distributed store. The logic here is identical; only the storage backend changes.

---

## Consolidated Findings

| # | Issue | Vulnerable File(s) | Severity | Status After Fix |
|---|---|---|---|---|
| 1 | Timing attack on email lookup | `auth.ts:66–68` | High | Constant-time dummy hash equalises both paths |
| 2 | Weak / missing cookie flags | `session.ts:13–17`, `proxy.ts:8–12` | Medium | `sameSite: "strict"` + `maxAge: 8h` + shared options |
| 3 | CSRF protection gaps | `SignupForm.tsx:15`, `LoginForm.tsx:13` | Medium | Covered by `sameSite: "strict"` + Next.js origin check; explicit tokens optional |
| 4 | SESSION_SECRET placeholder | `.env:9`, `session.ts:12` | Critical | Startup guard with clear error + generation instructions |
| 5 | Password policy weaknesses | `validations.ts:6–10` | Medium | `max(72)` + common-password deny list |
| 6 | No rate limiting | `auth.ts:50–83` | High | Dual-keyed limiter (IP + email) on login and signup |

---

## A Note on the Order of Fixes

If you can only do one thing today, do **Issue 4**. A compromised `SESSION_SECRET` renders every other protection meaningless. An attacker who knows the secret can mint any session they want and every check in the app — bcrypt, Zod, the proxy, the dashboard guard — becomes irrelevant.

After that, **Issue 1** and **Issue 6** are closely related: rate limiting makes a timing attack much slower, and closing the timing side-channel makes a brute force with unlimited attempts less informative. They compound each other. Fix them together.

**Issues 2 and 3** address the session cookie itself. `sameSite: "strict"` and `maxAge` are two lines of configuration change. They are the cheapest fixes relative to their impact.

**Issue 5** is ongoing hygiene. The `max(72)` fix is a one-liner. The common-password list is a starting point — its value grows with the size of the list. For a production app, integrating with Have I Been Pwned Passwords is an afternoon of work and dramatically improves the quality of passwords your users actually set.

Every fix here is surgical. None of them requires rearchitecting the application. That is intentional. Good security is not a rewrite — it is a series of precise, well-understood additions on top of a foundation that is already sound.
