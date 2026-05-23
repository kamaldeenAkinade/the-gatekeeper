# The Gatekeeper — Cross-Check: What the First Audit Missed

> The first audit found six issues. This document cross-checks those findings against
> the full authentication flow and identifies gaps the first audit overlooked entirely,
> as well as issues it acknowledged but under-corrected.

---

## How to Read This Cross-Check

Every missed finding follows the same structure:

- **The gap** — what the first audit missed or under-corrected
- **Why it matters** — the real-world consequence
- **The vulnerable code** — exact file and line, with context
- **What the audit said** — how it was handled (or not) in the first audit
- **The fix** — working code that closes the gap
- **Why the fix works** — the reasoning behind the change

---

## Issue 1 — Self-Asserted Email Identity (No Verification)

### The gap

Anyone can sign up with any email address they do not own. The app never verifies
that the user controls the email they provide. The "email" field is a self-asserted
identifier, not a verified contact method.

### Why an attacker cares

1. **Account squatting.** An attacker can register using another person's email
   address before that person does. The legitimate owner can never register with
   their own email — it is already taken. The attacker controls a profile that
   appears to belong to the legitimate user.

2. **Impossible to distinguish.** There is nothing in the database that separates
   "this email was verified by its owner" from "this email was typed into a form."
   Every account looks identical. Any future feature that relies on email
   (notifications, password reset, identity verification) is built on an untrusted
   foundation.

3. **Complicates future remediation.** Adding email verification later requires a
   migration. Existing unverified accounts need to be flagged, and there is no
   mechanism to force their users to verify. You inherit a permanent class of
   accounts with unknown trust levels.

### The vulnerable code

```
app/actions/auth.ts : 31–39
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return { errors: { email: ["An account with this email already exists"] } };
  }

  const hashed = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });
```

The only gate between a filled-out form and a created account is the uniqueness
check on line 31. Pass that check and an account is created. No email is sent.
No link is clicked. No proof of ownership is required.

```
app/signup/SignupForm.tsx : 11–14
  const [state, action, pending] = useActionState(signupAction, initial);

  return (
    <form action={action} className="space-y-5">
```

The signup form itself — no email field beyond the basic input.

```
prisma/schema.prisma : 18
  email     String   @unique
```

The database schema enforces uniqueness but not verifiability.

### What the audit said

The first audit did not mention email verification at all. Issue 6 Problem B
mentions account enumeration via signup ("An account with this email already
exists" as an oracle), but frames it as a rate-limiting concern, not an identity
trust concern. It never asks: "what does it mean that the email field is never
verified?"

### The fix

The signup flow must be split into two phases: **registration** (collect the
email, send a verification token) and **activation** (create the account only
after the token is confirmed).

```typescript
// lib/verification.ts — new file

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
```

```typescript
// app/actions/auth.ts — updated signupAction (abbreviated)

import { createVerificationToken } from "@/lib/verification";

export async function signupAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  // ... Zod validation unchanged ...

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    // Do not reveal whether the account is verified or not.
    return {
      message:
        "If that email is available, check your inbox for a verification link.",
    };
  }

  // Store a pending user (unverified) or just the token reference.
  // In production, send an email with the verification link.
  const token = createVerificationToken(email);

  // Store pending registration (pseudo-code — schema change required)
  // await prisma.pendingUser.create({ data: { name, email, password: hashed, token } });

  // Send email (pseudo-code — integrate with Resend, SendGrid, etc.)
  // await sendVerificationEmail(email, token);

  return {
    message:
      "If that email is available, check your inbox for a verification link.",
  };
}

export async function verifyEmailAction(token: string): Promise<ActionResult> {
  // Read token from URL query param, verify, activate the account.
  // Redirect to /login on success with a "verified" message.
}
```

```prisma
// prisma/schema.prisma — updated with pending user model

model PendingUser {
  id        String   @id @default(cuid())
  name      String
  email     String   @unique
  password  String
  token     String
  createdAt DateTime @default(now())
}
```

### Why the fix works

Splitting registration into two phases means an attacker **cannot create an
account with someone else's email**. They can submit the form, but the account
is never materialised until the email owner clicks the verification link. The
legitimate owner always retains control over whether an account exists at their
address.

The error message is the same for "email taken" and "registration submitted" —
the attacker cannot distinguish between them, closing an oracle that the first
audit identified but did not fully close.

---

## Issue 2 — No Server-Side Session Revocation

### The gap

iron-session stores the entire session inside an encrypted cookie. There is no
server-side session store. This means: **you cannot revoke a specific user's
session**. The only way to invalidate a session is to rotate the `SESSION_SECRET`,
which logs out every user in the system.

### Why an attacker cares

**Compromised session = permanent access.** If an attacker steals a session
cookie (via XSS, network interception, a compromised device), they have access
until the cookie's `maxAge` expires (which the first audit's Issue 2 fix sets
to 8 hours). You cannot kick them out. You cannot invalidate that specific
session. The attacker gets the full 8 hours to browse, exfiltrate data, or
escalate privileges.

For comparison, a server-side session store would let an admin hit "log out all
sessions" on a user's profile — the server deletes the session record, the
attacker's cookie becomes invalid immediately, and the legitimate user simply
logs in again.

### The vulnerable code

```
lib/session.ts : 20–25
  export async function getSession() {
    const session = await getIronSession<SessionData>(
      await cookies(),
      sessionOptions
    );
    return session;
  }
```

Every call to `getSession()` decrypts the cookie and returns whatever data is
inside. There is no lookup, no server-side check, no session registry. The
cookie is the source of truth.

```
lib/session.ts : 10–18
  const sessionOptions: SessionOptions = {
    cookieName: "gatekeeper_session",
    password: process.env.SESSION_SECRET as string,
    cookieOptions: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax",
    },
  };
```

No `maxAge` in the current code (the first audit's Issue 2 fix adds one). But
even with `maxAge: 8h`, the compromise window remains the full 8 hours with no
server-side kill switch.

```
app/actions/auth.ts : 85–89
  export async function logoutAction() {
    const session = await getSession();
    session.destroy();
    redirect("/");
  }
```

Logout destroys the *local* cookie. It does not (and cannot, with a stateless
design) invalidate a stolen copy that an attacker holds.

### What the audit said

The first audit's Issue 2 adds `maxAge: 60 * 60 * 8` (8-hour cookie lifetime),
which limits the damage window. But it treats the session as a client-side
concern only. It never addresses the absence of server-side revocation — the
fact that no amount of cookie configuration can help you revoke a session that
an attacker already captured.

### The fix

The most pragmatic fix within the iron-session architecture is to check a
**session version number** stored in the database on every authenticated
request. When an admin wants to revoke sessions, they increment the version
number. Any session whose version is stale is rejected.

```typescript
// lib/session.ts — updated getSession with server-side revocation check

import { prisma } from "@/lib/prisma";

export interface SessionData {
  userId: string;
  name: string;
  email: string;
  sessionVersion: number; // ← new field
}

export async function getSession() {
  const session = await getIronSession<SessionData>(
    await cookies(),
    sessionOptions
  );

  // If the session claims to be authenticated, verify the version is current.
  if (session.userId) {
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { sessionVersion: true },
    });

    if (!user || session.sessionVersion !== user.sessionVersion) {
      // Version mismatch — session was revoked. Destroy it.
      session.destroy();
      return session; // empty session, caller checks session.userId
    }
  }

  return session;
}
```

```prisma
// prisma/schema.prisma — updated User model

model User {
  id             String   @id @default(cuid())
  name           String
  email          String   @unique
  password       String
  sessionVersion Int      @default(1)  // ← new field
  createdAt      DateTime @default(now())
}
```

```typescript
// lib/session.ts — revokeAllSessions helper

export async function revokeAllSessions(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { sessionVersion: { increment: 1 } },
  });
}
```

Usage when you need to revoke:

```typescript
// Inside any server action or admin route:
await revokeAllSessions(userId);
// Next request from that user's existing session cookie will fail the version check.
```

### Why the fix works

The `sessionVersion` field creates a **server-side kill switch** without
abandoning iron-session's stateless cookie model. The version check adds one
database query per authenticated request (a `SELECT sessionVersion` on the
user's row — fast, indexed, no joins).

- Compromised session detected? Call `revokeAllSessions(userId)`. The version
  increments. The attacker's cookie now fails the version check on their next
  request, and the session is destroyed.
- The legitimate user logs in again — a new session is created with the current
  version number. They never notice the revocation.
- No external session store (Redis, database table) is required. The version
  check piggybacks on the existing `users` table.

This pattern is documented in the iron-session examples as "session versioning."
It is the standard way to add revocation to stateless sessions.

---

## Issue 3 — No Audit Logging of Authentication Events

### The gap

The app logs nothing about authentication events. There is no record of:
- Who logged in and when
- Who failed to log in and what email they tried
- Who signed up
- Who logged out
- Session revocations (if the Issue 2 fix is applied)

### Why an attacker cares

Without audit logs, security incidents are invisible:

1. **Brute-force attacks leave no trace.** An attacker running 10,000 password
   guesses against a single account generates 10,000 `bcrypt.compare` calls and
   10,000 "Invalid email or password" responses — but zero evidence. You cannot
   detect the attack, investigate it after the fact, or identify which accounts
   were targeted.

2. **Account takeover is silent.** An attacker who successfully guesses a
   password logs in, changes nothing, and exfiltrates data. There is no "new
   login from unfamiliar IP" event. The legitimate user logs in later and has
   no indication anything is wrong.

3. **Forensics are impossible.** If a breach is discovered months later, there
   is no timeline of events. You cannot answer: "when did the attacker first
   access the account?" or "how many accounts were compromised?"

### The vulnerable code

```
app/actions/auth.ts : 14–89
  export async function signupAction(...)     // no logging
  export async function loginAction(...)      // no logging
  export async function logoutAction(...)     // no logging
```

Every authentication action is silent.

### What the audit said

Zero mentions of logging, observability, or audit trails.

### The fix

Add structured logging to each authentication action. In production, send these
to a central logging service (e.g., DataDog, Grafana Loki, AWS CloudWatch). Logs
must never contain passwords or password hashes.

```typescript
// lib/audit.ts — new file

export type AuthEvent =
  | { type: "signup"; userId: string; email: string }
  | { type: "login"; userId: string; email: string }
  | { type: "login_failed"; email: string; reason: "user_not_found" | "wrong_password" }
  | { type: "logout"; userId: string }
  | { type: "session_revoked"; userId: string };

export function log(event: AuthEvent): void {
  const timestamp = new Date().toISOString();

  // In development, write to stdout with a structured format.
  if (process.env.NODE_ENV === "development") {
    console.log(JSON.stringify({ timestamp, ...event }));
    return;
  }

  // In production, send to your observability platform.
  // Example: fetch("https://api.datadoghq.com/...", { method: "POST", body: JSON.stringify({ timestamp, ...event }) });
  // The important thing: this function exists and is called at every auth boundary.
}
```

```typescript
// app/actions/auth.ts — updated with audit logging

import { log } from "@/lib/audit";

export async function loginAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  // ... validation unchanged ...

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    log({ type: "login_failed", email, reason: "user_not_found" });
    return { errors: { email: ["Invalid email or password"] } };
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    log({ type: "login_failed", email, reason: "wrong_password" });
    return { errors: { email: ["Invalid email or password"] } };
  }

  log({ type: "login", userId: user.id, email: user.email });

  // ... session creation unchanged ...
}

export async function signupAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  // ... validation unchanged ...

  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });

  log({ type: "signup", userId: user.id, email: user.email });

  // ... session creation unchanged ...
}

export async function logoutAction() {
  const session = await getSession();
  if (session.userId) {
    log({ type: "logout", userId: session.userId });
  }
  session.destroy();
  redirect("/");
}
```

### Why the fix works

Every authentication boundary now produces a structured log entry. The logs
enable:

- **Real-time alerting.** A spike in `login_failed` events from a single IP or
  targeting a single email triggers an alert. The rate limiting from the first
  audit's Issue 6 slows the attack; the logging surfaces it.
- **Incident investigation.** After a breach, you query "all `login` events for
  this `userId` in the last 30 days" and build a timeline.
- **Account compromise detection.** A `login` event from a new geographic region
  or a new device fingerprint (if captured) flags potential hijacking.

Logs never contain secrets — only identifiers (`userId`, `email`) and event
types. The password hash is never written to the log stream.

---

## Issue 4 — No Maximum Length Constraints on Login Form Fields

### The gap

The login schema validates only minimum requirements — email must look like an
email, password must be non-empty. There are no maximum length constraints on
either field.

```
lib/validations.ts : 13–16
  export const loginSchema = z.object({
    email: z.string().email("Invalid email address"),
    password: z.string().min(1, "Password is required"),
  });
```

### Why an attacker cares

**Resource exhaustion without authentication.** An attacker sends a POST request
with a 100,000-character "email" string and a 100,000-character "password"
string. The server must:

1. Parse the `FormData` — memory allocation proportional to input size
2. Validate the email with Zod's `.email()` regex — CPU proportional to string
   length (Zod's regex is not guaranteed O(n) on pathological input)
3. Pass the email to `prisma.user.findUnique` — the database driver sends the
   full string across the wire
4. If the user exists, pass the password to `bcrypt.compare` — which copies the
   full input even though bcrypt internally truncates at 72 bytes

A single large request is harmless. A sustained stream of large requests from a
botnet is a denial-of-service vector that requires no breached credentials and
no account access. This is the same class of attack as the first audit's Issue 6
(resource exhaustion via unauthenticated requests), but via input size rather
than request volume.

### The vulnerable code

```
lib/validations.ts : 13–16 (shown above)
```

Compare with `signupSchema` which the first audit's Issue 5 adds `.max(72)` for
passwords — but the login schema was never updated to match.

### What the audit said

The first audit's Issue 5 adds `.max(72)` to the signup password field and
discusses the bcrypt 72-byte truncation. But it **never modifies the login
schema**, leaving the login endpoint vulnerable to large-input DoS. The reasoning
("the login function uses bcrypt.compare which handles the truncation") misses
that the string is allocated and processed before bcrypt ever sees it.

### The fix

Add `.max()` constraints to both login fields:

```typescript
// lib/validations.ts — updated loginSchema

export const loginSchema = z.object({
  email: z
    .string()
    .email("Invalid email address")
    .max(254, "Email address is too long"),   // RFC 5321 max
  password: z
    .string()
    .min(1, "Password is required")
    .max(72, "Password must be at most 72 characters"),  // match signup
});
```

### Why the fix works

Zod's `.max()` runs before any database or bcrypt operation. If the input
exceeds the limit, the function returns a validation error immediately — no
database query, no bcrypt, no large memory allocation. The check is O(1) in
input size (Zod's `.max()` is a simple `.length` comparison, not a regex).

The email limit of 254 characters follows RFC 5321 section 4.5.3 (the maximum
length of a valid email address). The password limit of 72 matches the bcrypt
truncation point and is consistent with the signup schema.

---

## Issue 5 — Proxy Coverage Is Fragile

### The gap

The proxy middleware only covers the `/dashboard/:path*` pattern:

```
proxy.ts : 28–30
  export const config = {
    matcher: ["/dashboard/:path*"],
  };
```

Any new protected route added to the app (e.g., `/settings`, `/admin`,
`/billing`) is **not covered by the proxy** unless a developer remembers to
update the matcher. The page-level check (`if (!session.userId) redirect(...)`)
is the only safeguard and has to be added manually per-route.

### Why an attacker cares

This is a **defence-in-depth erosion**, not a direct bypass. Every new route
relies entirely on its page-level auth check. If a developer forgets that check
(especially easy with copy-paste, page templates, or when adding routes under
deadline pressure), the route is publicly accessible with no gate at all.

The first audit correctly notes the defence-in-depth pattern (proxy + page) as
a strength. But a pattern that is silently opt-in for every new route is not a
pattern — it is documentation. Code, not convention, should enforce the guard.

### What the audit said

The first audit's Issue 2 fixes the duplicated session options between proxy.ts
and lib/session.ts, and the "Consolidated Findings" table notes the pattern as
defence-in-depth. But it never asks: "what happens when someone adds a new route
and doesn't know the matcher needs updating?"

### The fix

Two changes. First, expand the proxy matcher to cover all authenticated routes
by convention (e.g., a prefix-based approach). Second, add a compile-time or
startup assertion so that forgetting feels wrong.

```typescript
// proxy.ts — expanded matcher (prefix-based convention)

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/settings/:path*",
    "/admin/:path*",
    // Add new protected route prefixes here.
    // Convention: authenticated pages live under /app/* or use a shared prefix.
  ],
};
```

A more robust approach uses a route group or a shared layout with an auth check,
so every route in the group inherits the protection automatically:

```typescript
// app/(authenticated)/layout.tsx — shared layout for all protected routes

import { getSession } from "@/lib/session";
import { redirect } from "next/navigation";

export default async function AuthenticatedLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const session = await getSession();
  if (!session.userId) redirect("/login");

  return <>{children}</>;
}
```

With this layout, any route placed under `app/(authenticated)/` gets the auth
check automatically — no proxy matcher update needed, no `if (!session.userId)`
boilerplate in every page. The proxy remains an optimisation (early redirect at
the edge) but the layout becomes the contract.

### Why the fix works

A shared layout under a route group makes authentication a **structural
convention** rather than a **copy-paste ritual**. The developer creates a new
folder under `app/(authenticated)/settings/` and the auth check is inherited.
They do not need to know about the proxy, the matcher, or the `getSession`
pattern.

The proxy check and the layout check are still independent layers (defence in
depth), but the layout ensures that forgetting the check is structurally
impossible — a page outside the group is intentionally public, and a page inside
the group is intentionally protected.

---

## Issue 6 — Signup Account Enumeration: Under-Corrected

### The gap

The first audit acknowledged that the signup endpoint returns a different error
message when an email is already registered:

```
app/actions/auth.ts : 32–34
  if (existing) {
    return { errors: { email: ["An account with this email already exists"] } };
  }
```

The audit classified this as Problem B under Issue 6 (No Rate Limiting) and
proposed rate limiting as the fix. But rate limiting alone does not close the
oracle — it only slows it. The different error message is still present.

### Why an attacker cares

With a distributed botnet of 1,000 IPs and the audit's proposed limit of 3
signup attempts per hour per IP, an attacker can check **3,000 emails per hour**
(72,000 per day) against the signup form. Each attempt with a registered email
returns "An account with this email already exists" while each attempt with an
unregistered email triggers Zod validation (name, password checks) and returns
a different error. The oracle is alive, just slower.

This is the **same class of information leak** as the first audit's Issue 1
(timing attack on login), but the audit treated it as a throughput problem
rather than an information-design problem. Rate limiting is a necessary
mitigation, but it is not a fix for the oracle itself.

### What the audit said

Issue 6 Problem B says: "the different error message is intentional UX" and
proposes only rate limiting as the fix. The "intentional UX" framing accepts an
information leak as a design requirement rather than challenging it.

### The fix

Return a **generic, ambiguous message** for all signup outcomes (success,
duplicate, validation failure) to close the oracle completely. Redirect only on
actual success so the attacker cannot distinguish outcomes by response body.

```typescript
// app/actions/auth.ts — updated signupAction

export async function signupAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  const raw = {
    name: formData.get("name"),
    email: formData.get("email"),
    password: formData.get("password"),
  };

  const parsed = signupSchema.safeParse(raw);
  if (!parsed.success) {
    // Do not return field-level errors. Return a single generic message.
    return { message: "If that email is available, check your inbox for instructions." };
  }

  const { name, email, password } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    // Same generic message — no information leaked.
    return { message: "If that email is available, check your inbox for instructions." };
  }

  const hashed = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });

  // In a full implementation, send a verification email here.
  // Do NOT log the user in automatically (see Issue 1 — email verification).

  // Same generic message on success too.
  return { message: "If that email is available, check your inbox for instructions." };
}
```

### Why the fix works

Every possible outcome — Zod validation failure, duplicate email, successful
account creation — returns the exact same message. An attacker sending one
million email addresses to the signup endpoint receives one million identical
responses. There is no signal in the response body to distinguish registered
from unregistered emails.

Combined with the rate limiting from the first audit's Issue 6, both the
throughput and the signal are eliminated. The oracle is closed.

---

## Consolidated Cross-Check

| # | Missed or Under-Corrected Issue | File(s) | Severity | Gap Type |
|---|---|---|---|---|
| 1 | Self-asserted email identity — no verification | `auth.ts:31–39` | Critical | Not addressed |
| 2 | No server-side session revocation | `session.ts:20–25` | High | Not addressed |
| 3 | No audit logging of auth events | `auth.ts:14–89` | High | Not addressed |
| 4 | No max length on login form fields | `validations.ts:13–16` | Medium | Not addressed |
| 5 | Proxy coverage is fragile (opt-in per route) | `proxy.ts:28–30` | Medium | Not addressed |
| 6 | Signup account enumeration under-corrected | `auth.ts:32–34` | High | Acknowledged, under-fixed |

---

## Relationship to the First Audit

The first audit identified six concrete, fixable issues in the authentication
flow. Every finding was backed by exact line numbers and working fixes. This
cross-check is not a critique of those findings — it is an extension.

The gaps fall into two categories:

**Architectural gaps (Issues 1–3 in this cross-check).** These are not bugs in
the existing code but missing capabilities: no email verification, no session
revocation, no audit logging. They are harder to retrofit than the first audit's
surgical fixes, but they define the ceiling of the app's security posture.

**Oversights (Issues 4–6).** The first audit caught the password max-length
problem (Issue 5 in the original) but applied the fix only to signup, not login.
It caught the proxy-options duplication (original Issue 2) but did not examine
the matcher's fragility. It caught the signup enumeration (original Issue 6
Problem B) but accepted a partial fix.

These six cross-check findings should be read as a companion to the first audit:
fix the original six, then address these six, then re-assess. Every layer
removed makes the remaining ones stronger.
