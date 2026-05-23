# The Gatekeeper — Authentication Principles in Play

> Written for someone who wants to truly understand *why*, not just *what*.
> Every claim is backed by an exact file and line number you can open right now.

---

## How to Read This Document

Each section follows the same four-part structure:

1. **Plain definition** — what the principle actually means, no jargon
2. **Why it exists** — the real-world harm it prevents
3. **The exact lines** — where you can see it in the code
4. **What would break** — a concrete picture of what goes wrong if you remove it

That last part is important. Security principles can feel abstract until you see the specific disaster they're preventing.

---

## Principle 1 — Never Store Plaintext Passwords

### Plain definition

A plaintext password is the actual thing the user typed — `"Hello1234"`. Storing it plaintext means writing that exact string into the database. This principle says: **never do that**. Store a scrambled version instead, one that cannot be reversed.

### Why it exists

Databases get stolen. It happens to companies of every size, regularly, through SQL injection attacks, compromised backups, rogue employees, or misconfigured cloud storage. If you stored real passwords, every user's account — on *every other website where they reused that password* — would be immediately at risk. You'd have caused harm far beyond your own app.

The principle recognises that **you cannot guarantee your database will never be breached**, so you design as if it already has been. A stolen database should be useless to an attacker.

### The exact lines

**Step 1 — hashing on signup:**

```
app/actions/auth.ts : 36
  const hashed = await bcrypt.hash(password, 12);
```

`bcrypt.hash` is a one-way function. It takes `password` (the real thing the user typed) and produces a long scrambled string like `$2a$12$x9v3mL...eKjZ2`. The `12` is the cost factor — it controls how many internal rounds of scrambling happen (4,096 at cost 12). The higher the cost, the longer each guess takes for an attacker.

The word "one-way" is the key idea. You can go from password → hash. You cannot go from hash → password. There is no `bcrypt.unhash()`. It does not exist.

**Step 2 — only the hash is saved:**

```
app/actions/auth.ts : 37–39
  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });
```

`password: hashed` — the column gets the scrambled string, not what the user typed. The variable `password` (the real one) goes out of scope and is garbage collected. It never touches disk.

**Step 3 — verification without reversing:**

```
app/actions/auth.ts : 71
  const valid = await bcrypt.compare(password, user.password);
```

At login time we face a puzzle: we have what the user just typed (`password`) and the stored hash (`user.password`). We cannot decrypt the hash. So instead, bcrypt re-runs the same scrambling process on the freshly typed password, using the salt that was baked into the stored hash, and checks whether the output matches. If it does, the passwords are the same. If not, they aren't.

This is called **re-hashing to compare** rather than decrypting to compare. It is the only correct way to verify a hashed password.

### What would break if you removed it

If you wrote `password: password` on line 38 instead of `password: hashed`, the database would store `"Hello1234"` in plain text. Anyone who ran `SELECT * FROM User` — a developer, a hacker who got a backup, someone who found an unsecured database URL — would have every user's real password. Many people reuse passwords across sites. You would have handed over their Gmail, their bank, their everything.

### A note on salt

bcrypt automatically generates a unique random salt for every hash and bakes it into the hash string. This matters because two users with the same password end up with completely different hashes. An attacker cannot use precomputed tables of common password hashes ("rainbow tables") — they have to compute every guess individually, per hash, which at cost factor 12 is extremely slow.

---

## Principle 2 — Server-Side Validation

### Plain definition

Validation means checking that the data the user submitted follows the rules — right format, right length, not empty. **Server-side** means those checks run on the server, in code the user cannot touch or remove. The rule is: **never trust the client to enforce rules that matter**.

### Why it exists

Everything that runs in the browser is under the user's complete control. They can open developer tools, edit the HTML, delete a `required` attribute, intercept the network request with a proxy like Burp Suite, or call your API directly with curl. Any validation that only lives in the browser is purely cosmetic — it improves UX but provides zero security. The server is the only place where rules are actually enforced.

### The exact lines

**The validation schemas live in a dedicated file:**

```
lib/validations.ts : 3–11
  export const signupSchema = z.object({
    name: z.string().min(2, "Name must be at least 2 characters"),
    email: z.string().email("Invalid email address"),
    password: z
      .string()
      .min(8, "Password must be at least 8 characters")
      .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
      .regex(/[0-9]/, "Password must contain at least one number"),
  });
```

This is a Zod schema. Zod is a TypeScript-first validation library. The schema describes exactly what valid data looks like. Nothing here touches the browser — this file is imported only by the server action.

**The `"use server"` directive:**

```
app/actions/auth.ts : 1
  "use server";
```

This string at the top of the file is a Next.js directive. It tells the framework: every function exported from this file executes on the server. The browser can trigger these functions (by submitting a form), but the code itself never ships to the browser. The user cannot read it, modify it, or bypass it.

**Validation runs before anything else in `signupAction`:**

```
app/actions/auth.ts : 24–27
  const parsed = signupSchema.safeParse(raw);
  if (!parsed.success) {
    return { errors: parsed.error.flatten().fieldErrors };
  }
```

`safeParse` runs all the rules from the schema. If any rule fails, `parsed.success` is `false` and the function returns immediately — no database is touched, no bcrypt runs, nothing. The form gets back a structured error object so it can show the right message under the right field.

The same pattern for login:

```
app/actions/auth.ts : 59–62
  const parsed = loginSchema.safeParse(raw);
  if (!parsed.success) {
    return { errors: parsed.error.flatten().fieldErrors };
  }
```

**The browser has its own feedback too — but separately:**

```
app/signup/PasswordStrength.tsx : 9–17
  function score(password: string): number {
    if (!password) return 0;
    let s = 0;
    if (password.length >= 8) s++;
    if (password.length >= 12) s++;
    if (/[A-Z]/.test(password)) s++;
    if (/[0-9]/.test(password)) s++;
    if (/[^A-Za-z0-9]/.test(password)) s++;
    return s;
  }
```

```
app/signup/SignupForm.tsx : 25
  required
```

The `required` attribute and the password strength meter both run in the browser. They help the user form a good password before hitting submit. But they are purely UX. If someone deleted the `required` attribute in devtools and submitted an empty form, the server-side Zod check on line 8 of `validations.ts` would still catch it and return an error. The browser checks are a courtesy; the server checks are the law.

### What would break if you removed it

Remove `signupSchema.safeParse` on line 24 and send a request directly with `curl`:

```bash
curl -X POST /signup -d "name=&email=notanemail&password=a"
```

Without server-side validation, this would reach line 31 (`prisma.user.findUnique`) with an invalid email, potentially reach line 36 (`bcrypt.hash`) with a one-character password, and write a garbage user record to the database. You can't prevent `curl` from skipping your browser's `required` attribute.

---

## Principle 3 — Defense in Depth

### Plain definition

Defense in depth means having **multiple independent layers of protection**, each of which would stop an attack on its own. If one layer fails, the next one catches it. You do not assume any single control is perfect.

The name comes from military strategy: instead of one large wall, you build multiple concentric fortifications. An attacker who breaches the outer wall still faces the inner wall, the moat, and the guards.

### Why it exists

Every security control has failure modes. Middleware might not run in all deployment configurations. A library might have a bug. A future developer might accidentally misconfigure something. By stacking independent checks, you ensure that a single point of failure does not become a breach. The cost of an extra check is negligible; the cost of a bypassed single check can be catastrophic.

### The exact lines

The dashboard is protected in two entirely independent places.

**Layer 1 — The proxy (runs at the edge, before the page code starts):**

```
proxy.ts : 15–23
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
```

```
proxy.ts : 28–30
  export const config = {
    matcher: ["/dashboard/:path*"],
  };
```

The `matcher` tells Next.js to run `proxy` for every request to `/dashboard` and every path under it (`/dashboard/settings`, `/dashboard/profile`, etc.) before any page code runs. If `session.userId` is missing or if the cookie was tampered with and decryption fails, the user gets a redirect immediately. The page never renders. The React component never runs. The database is never queried.

**Layer 2 — The page itself (runs inside the Next.js render pipeline):**

```
app/dashboard/page.tsx : 8–9
  const session = await getSession();
  if (!session.userId) redirect("/login");
```

These two lines are the second independent check. Even if a request somehow reached the page despite the proxy (a future misconfiguration, a direct server-render call in a test, a bug in the routing layer), the page would still catch it and redirect.

**The two layers use the same mechanism but are triggered at different stages:**

- The proxy uses `getIronSession(req, res, sessionOptions)` — it reads cookies directly from the raw request object, before Next.js routing processes the request fully.
- The page uses `getSession()` from `lib/session.ts` — it calls `getIronSession` using `cookies()` from `next/headers`, which is the idiomatic way to read cookies inside a Server Component.

Both decrypt the same `gatekeeper_session` cookie with the same `SESSION_SECRET`. They are independent code paths reaching the same answer.

**A third layer — the "Invalid email or password" phrasing:**

```
app/actions/auth.ts : 67–68
  if (!user) {
    return { errors: { email: ["Invalid email or password"] } };
  }
```

```
app/actions/auth.ts : 72–73
  if (!valid) {
    return { errors: { email: ["Invalid email or password"] } };
  }
```

Notice both the "email not found" case and the "wrong password" case return the **exact same error message**. This is also a defense-in-depth decision — it is a specific form of a principle called **information hiding** layered inside defense in depth. If we returned "email not found" for one case and "wrong password" for the other, an attacker could use your login form as an email-enumeration tool: they try different emails until they stop getting "email not found" and start getting "wrong password" — now they know a valid account exists. By being deliberately vague, both failure modes are equally unhelpful to an attacker.

### What would break if you removed it

Remove the proxy check in `proxy.ts` entirely. If a deployment platform for any reason skips loading proxy files (it has happened with certain edge runtimes and misconfigured vercel.json rules), the dashboard would have no gating at all. The page check on lines 8–9 of `dashboard/page.tsx` would be the only protection. Now remove that too — and the dashboard renders its content for any anonymous visitor. Two missing lines, complete bypass.

With both layers present, removing either one still leaves the other in place. The attacker has to defeat both.

---

## Principle 4 — Least Privilege

### Plain definition

Least privilege means: **give each part of the system only the access it actually needs, and no more**. A component that needs to read your name should not have access to your password hash. A process that needs to display a page should not be able to write to the database. Limit access to the minimum required to do the job.

### Why it exists

When a component is compromised — through a bug, a supply-chain attack, or developer error — the damage it can do is bounded by what it can access. A compromised component with minimal privileges causes minimal harm. A compromised component with root access causes total harm.

### The exact lines

**The session stores the minimum needed identity — not the full user record:**

```
app/actions/auth.ts : 42–44
  session.userId = user.id;
  session.name = user.name;
  session.email = user.email;
```

The server action retrieved the full user record from the database — including `user.password` (the bcrypt hash) and `user.createdAt`. But only three fields are written into the session: `userId`, `name`, and `email`. The password hash is intentionally excluded. It is not needed anywhere in the session, so it is not included.

**The session data type enforces this boundary:**

```
lib/session.ts : 4–8
  export interface SessionData {
    userId: string;
    name: string;
    email: string;
  }
```

This TypeScript interface defines the shape of what can live in the session. `password` is not in it. If a future developer accidentally wrote `session.password = user.password`, TypeScript would refuse to compile. The type definition is not just documentation — it is a compile-time enforcement of least privilege.

**The dashboard reads from session, not from the database:**

```
app/dashboard/page.tsx : 8
  const session = await getSession();
```

```
app/dashboard/page.tsx : 22–24
  <h1>Welcome, {session.name}</h1>
  <p>{session.email}</p>
```

The dashboard page never calls `prisma.user.findUnique` or queries the database at all. It reads `session.name` and `session.email` from the decrypted cookie. It has exactly the data it needs — display name and email — and no access to anything else about the user. The page cannot access the password hash even if it wanted to, because the hash was never put in the session.

**The password field is write-only at signup:**

```
app/actions/auth.ts : 36–39
  const hashed = await bcrypt.hash(password, 12);
  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });
```

The hash is written to the database and then the variable `hashed` goes out of scope. There is no `return hashed`, no `session.password = hashed`, no logging. Once written, the hash is only ever read in one specific place: inside `loginAction` during `bcrypt.compare`. No other code path in the app touches it.

### What would break if you removed it

Imagine if the session stored `session.passwordHash = user.password`. Now the encrypted bcrypt hash travels in the cookie to the browser on every request. If iron-session were ever broken or misconfigured, or if the `SESSION_SECRET` were leaked, an attacker would receive the hash — which they could then take offline and brute-force at their leisure. By not storing it in the session at all, there is nothing to leak.

More broadly: if the dashboard made a database query and `SELECT *`'d the user, it would fetch the hash unnecessarily. Any log statement printing that response would expose it. Least privilege means not fetching data you don't need — the session pattern achieves this naturally.

---

## Principle 5 — Secure Defaults

### Plain definition

Secure defaults means: **when you configure something, the safe option should be what you get without extra effort**. The insecure option should require deliberate, explicit action to enable. Systems should fail in a safe direction, not a permissive one.

This principle matters because developers make mistakes, forget configuration options, or are under time pressure. If the default is safe, forgetting to configure something leaves you protected. If the default is insecure, forgetting to configure something leaves you exposed.

### Why it exists

Most security incidents involve misconfiguration, not novel exploits. "I forgot to set `httpOnly`" is a common cause of session hijacking. "I forgot to hash the password" is a common cause of credential database breaches. Secure defaults reduce the blast radius of configuration mistakes — and they make doing the right thing the path of least resistance.

### The exact lines

**Cookie flags are set explicitly and all default to the safe option:**

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

Let's go through each flag:

- **`httpOnly: true`** — JavaScript in the browser cannot read this cookie. This is the single most important cookie flag for session security. If a cross-site scripting (XSS) attack injects malicious JavaScript into your page, that JavaScript cannot steal the session cookie because the browser itself hides `httpOnly` cookies from `document.cookie`. The default for a cookie is `httpOnly: false` (readable by JavaScript). We override that to `true`.

- **`secure: process.env.NODE_ENV === "production"`** — in production, this cookie will only travel over HTTPS. The browser will refuse to send it over plain HTTP. This prevents a network-level attacker from reading the cookie by intercepting unencrypted traffic. It is conditionally set to `false` in development because local development typically does not use HTTPS. Explicitly conditional is better than forgetting it.

- **`sameSite: "lax"`** — the browser will not attach this cookie to cross-site requests. This mitigates CSRF (Cross-Site Request Forgery) attacks, where a malicious website tricks your browser into making authenticated requests to our app without your knowledge. `"lax"` allows the cookie on top-level navigations (clicking a link) but blocks it on embedded cross-site requests (images, iframes, forms on other sites).

The same options are mirrored in the proxy:

```
proxy.ts : 5–13
  const sessionOptions = {
    cookieName: "gatekeeper_session",
    password: process.env.SESSION_SECRET as string,
    cookieOptions: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      sameSite: "lax" as const,
    },
  };
```

**The session secret comes from an environment variable, never hardcoded:**

```
lib/session.ts : 12
  password: process.env.SESSION_SECRET as string,
```

`SESSION_SECRET` is defined in `.env` and is never committed to the repository. If the code were published to GitHub, the secret would not be exposed. The default position is: the secret is external to the code. If a developer forgets to set it, iron-session will fail at startup with an error rather than silently use an empty string — iron-session enforces a minimum password length.

**The proxy defaults to redirecting — it only allows access when explicitly verified:**

```
proxy.ts : 19–23
  if (!session.userId) {
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("from", req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }

  return res;
```

The logic is structured as: **default to blocking, only pass if explicitly authenticated**. If `session.userId` is truthy, allow. If it is anything else — empty string, `undefined`, `null`, completely missing cookie, tampered cookie — the `if` block fires and redirects. There is no "if something weird happens, let them through." The safe action (redirect) is the default; the permissive action (pass) requires a positive check.

Compare this to the dangerous alternative:

```ts
// WRONG — defaults to allowing, blocks only on explicit failure
if (session.userId === "bad") {
  return NextResponse.redirect(loginUrl);
}
return res;
```

That pattern has a secure default problem: any unusual state would fall through to the `return res` — allowing access. Our code does the opposite.

**bcrypt's cost factor defaults high:**

```
app/actions/auth.ts : 36
  const hashed = await bcrypt.hash(password, 12);
```

A cost factor of `12` is deliberately chosen to be slow. In 2026, cost 10 takes roughly 65ms per hash; cost 12 takes roughly 260ms. From the user's perspective, a quarter-second login is imperceptible. From an attacker's perspective, trying ten million passwords takes 260 million milliseconds — about 3 days. The slow default protects against brute force without meaningfully affecting the user experience.

### What would break if you removed it

Remove `httpOnly: true` — now `document.cookie` contains the session token in the browser. Any XSS vulnerability anywhere on your site (even a third-party script you load) can immediately steal every logged-in user's session.

Remove `secure: true` in production — someone on the same Wi-Fi network can intercept the plain HTTP traffic and read the session cookie. They replay it in their own browser and are now logged in as you.

Remove `sameSite: "lax"` — a malicious website can embed a form that POSTs to your `/logout` (or worse, to any state-changing endpoint) with the victim's session cookie attached automatically. The user visits the malicious site and gets logged out — or worse, their account is modified.

Each flag is a separate defense. Removing any one of them opens a specific, well-documented attack class.

---

## Summary Table

| Principle | Core Rule | Where in the Code | Attack Prevented |
|---|---|---|---|
| Never store plaintext passwords | Hash with bcrypt, store the hash only | `auth.ts:36–38`, `auth.ts:71` | Database breach exposes real passwords |
| Server-side validation | Zod schemas run inside `"use server"` functions | `validations.ts:3–11`, `auth.ts:24–27`, `auth.ts:59–62` | Bypassed browser checks, malformed data, direct API abuse |
| Defense in depth | Two independent session checks on the dashboard | `proxy.ts:19–23`, `dashboard/page.tsx:8–9` | Single point of failure, misconfigured middleware |
| Least privilege | Session holds only id/name/email, not the hash | `session.ts:4–8`, `auth.ts:42–44` | Session leak exposing crackable password hash |
| Secure defaults | `httpOnly`, `secure`, `sameSite` all set safely; block-then-allow logic in proxy | `session.ts:14–16`, `proxy.ts:19–23` | XSS session theft, network interception, CSRF |

---

## A Closing Thought from a Patient Teacher

Security principles are not a checklist you tick once and forget. They are habits of thinking. Every time you store data, ask: "does this component need this?" Every time you write a conditional, ask: "does the default let people in or keep them out?" Every time you move data to the client, ask: "could this be misused if someone intercepted it?"

The five principles above are not separate things — they reinforce each other. Least privilege means the session doesn't hold the hash. That makes the secure-defaults cookie flag protection more valuable, because even if the cookie were somehow exposed, there's less inside it. Defense in depth means the proxy and the page both check independently. Server-side validation means neither check can be bypassed by a browser hack. And hashing passwords means even if all the other protections fail and the database is stolen, the attacker still has nothing they can use.

Good security is not one strong wall. It is many overlapping ones, each cheap to build, all making the others stronger.
