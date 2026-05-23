# The Gatekeeper — How It All Works

> Explained like you're seven years old. No really.

---

## The Big Picture First

Imagine a clubhouse. The clubhouse has:

1. A **front door** — anyone can look at it (the landing page).
2. A **sign-up desk** — where you write your name and make a secret password.
3. A **check-in desk** — where you show your password to get in.
4. A **secret room** — only members can enter (the dashboard).
5. A **bouncer at the secret room door** — who checks your member badge before letting you through.

The code does exactly these five things. Let's walk through every file.

---

## File Map

```
lib/
  prisma.ts          ← opens the database (the filing cabinet)
  session.ts         ← makes and reads the member badge (cookie)
  validations.ts     ← checks that what you typed makes sense

app/actions/auth.ts  ← the brains: signup, login, logout

app/signup/
  SignupForm.tsx     ← the HTML sign-up form (browser side)
  PasswordStrength.tsx ← the little coloured bars under the password box

app/login/
  LoginForm.tsx      ← the HTML login form (browser side)

app/dashboard/
  page.tsx           ← the secret room page

proxy.ts             ← the bouncer standing at the secret room door
```

---

## 1. The Filing Cabinet — `lib/prisma.ts`

```ts
import { PrismaClient } from "@/app/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";

function createPrismaClient() {
  const url = process.env.DATABASE_URL ?? "file:./prisma/dev.db";
  const adapter = new PrismaLibSql({ url });
  return new PrismaClient({ adapter });
}

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient };

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== "production") globalForPrisma.prisma = prisma;
```

**Line by line:**

- `PrismaClient` is the thing that talks to our database. Think of it as a librarian who knows where every book (user record) lives.
- `PrismaLibSql` is an adapter — a translator — because our database is a SQLite file and Prisma 7 can't talk to it directly without one. Like how you need a plug adaptor in another country.
- `process.env.DATABASE_URL` is a secret note in the `.env` file that says `file:./prisma/dev.db`. That's the path to the actual database file on disk.
- `createPrismaClient()` builds the librarian, hands it the adaptor, and says "here's where the filing cabinet lives."
- The `globalForPrisma` trick is because Next.js restarts your server code a lot during development, and you don't want to make one hundred librarians — just one shared one.
- `globalForPrisma.prisma ?? createPrismaClient()` means: "if we already have a librarian, use them; otherwise hire a new one."
- The last `if` line only stores the librarian globally during development, not in production (production doesn't have the restart problem).

---

## 2. The Rulebook — `lib/validations.ts`

```ts
import { z } from "zod";

export const signupSchema = z.object({
  name: z.string().min(2, "Name must be at least 2 characters"),
  email: z.string().email("Invalid email address"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
    .regex(/[0-9]/, "Password must contain at least one number"),
});

export const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required"),
});
```

**Line by line:**

- Zod is like a picky teacher who checks your homework before you hand it in.
- `signupSchema` is the list of rules for signing up:
  - Name must be at least 2 letters — "Jo" is fine, one letter is not.
  - Email must look like an email — it must have an `@` sign.
  - Password must be at least 8 characters, have one capital letter, and have one number. "hello" fails. "Hello1234" passes.
- `loginSchema` is shorter because we're just checking the format — the *real* check (is this actually your password?) happens later.
- `z.string().email()` doesn't send a letter to verify — it just checks the *shape* looks right.
- `.regex(/[A-Z]/)` is a pattern. The computer looks at every letter and asks "is any of you a capital?" If none raise their hand, the check fails.
- **Crucially, this runs on the server** (inside `signupAction`), never just in the browser. Even if someone hacks the browser and removes the rules, the server still catches it.

---

## 3. The Member Badge Shop — `lib/session.ts`

```ts
import { getIronSession, type SessionOptions } from "iron-session";
import { cookies } from "next/headers";

export interface SessionData {
  userId: string;
  name: string;
  email: string;
}

const sessionOptions: SessionOptions = {
  cookieName: "gatekeeper_session",
  password: process.env.SESSION_SECRET as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "lax",
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

This is the most important file for understanding sessions. Read it slowly.

**What is a cookie?**

When you log in, the server needs a way to remember you on the *next* request. HTTP doesn't have memory — every request starts fresh, like meeting a stranger. The solution: the server puts a little sticky note (a cookie) in your browser. Your browser sends that sticky note back with every future request, like wearing a wristband at an amusement park.

**What is iron-session?**

iron-session takes your data (`userId`, `name`, `email`) and locks it inside a box that is scrambled with a secret password (`SESSION_SECRET`). The scrambled box is what gets stored in the cookie. Nobody — not even the user — can read or tamper with it unless they know the secret password.

**Line by line:**

- `SessionData` is the shape of what we store in the badge: a user ID, a name, and an email. Just enough to know who you are.
- `cookieName: "gatekeeper_session"` — this is what the cookie is called in the browser. Like writing a name on a wristband.
- `password: process.env.SESSION_SECRET` — this is the scramble key. It lives in `.env` and is never committed to git. If someone stole the cookie, they couldn't read it without this key.
- `httpOnly: true` — **this is a security lock**. It means JavaScript running in the browser cannot read this cookie. A hacker injecting `<script>` into your page cannot steal it, because it's invisible to JavaScript.
- `secure: process.env.NODE_ENV === "production"` — in production, the cookie can only travel over HTTPS (encrypted), not plain HTTP. In development it's fine without it.
- `sameSite: "lax"` — the browser will not send this cookie to *other* websites, so a sneaky site can't trick your browser into making requests on your behalf (that attack is called CSRF).
- `getSession()` is the function everything else calls. It reads the current request's cookies, finds the one named `gatekeeper_session`, and decrypts it using the secret password. If no cookie exists, it returns an empty session object.

---

## 4. ★ THE BIG THREE ★ — `app/actions/auth.ts`

This file has three functions. We'll go deep on all of them.

### 4a. Signing Up — `signupAction`

```ts
"use server";
```

This magic string at the top of the file tells Next.js: "every function in here runs on the server, never in the browser." The browser can *call* these functions (when you submit a form), but the code itself runs on the server. The user never sees it.

```ts
export async function signupAction(_prev: ActionResult, formData: FormData) {
  const raw = {
    name: formData.get("name"),
    email: formData.get("email"),
    password: formData.get("password"),
  };
```

When you fill in the sign-up form and hit submit, the browser sends all the form fields to the server. `formData.get("name")` picks out whatever you typed in the name box. `raw` is just a plain object holding those three values before we check them.

```ts
  const parsed = signupSchema.safeParse(raw);
  if (!parsed.success) {
    return { errors: parsed.error.flatten().fieldErrors };
  }
```

`safeParse` runs the rulebook from `validations.ts`. If any rule fails, `parsed.success` is `false` and we return the errors immediately — no database is touched. `flatten().fieldErrors` turns the Zod error into a neat object like `{ password: ["must be at least 8 characters"] }` so the form can show it under the right box.

```ts
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return { errors: { email: ["An account with this email already exists"] } };
  }
```

Ask the database: "is there already a user with this exact email?" `findUnique` returns `null` if nobody has it, or the user row if someone does. If it exists, we stop and tell you — no duplicate accounts allowed.

---

#### ★ AREA 1: How Passwords Get Hashed ★

```ts
  const hashed = await bcrypt.hash(password, 12);
```

This is the most important security step in the whole signup flow. Here's what happens:

**What is hashing?**

Hashing is a one-way blender. You put your password in, and out comes a jumbled mess. You can NEVER un-blend it back to the original. The scrambled result is called a "hash."

Example (not real bcrypt, but same idea):
```
password: "Hello1234"
hash:     "$2a$12$x9v3mLqP...eKjZ2mRvQ7" ← looks like random noise
```

**What is the 12?**

The `12` is called the "cost factor" or "work factor." It tells bcrypt how many times to scramble. Each increment *doubles* the work:
- `10` = 1,024 rounds of scrambling
- `11` = 2,048 rounds
- `12` = 4,096 rounds

Why does this matter? Because if a hacker steals the database and tries to guess passwords, they'd have to do 4,096 rounds of scrambling for *every single guess*. That makes cracking extremely slow — hours or days instead of seconds.

**Why don't we store the real password?**

If someone breaks into the database, they get the hash — total gibberish. They cannot work backwards from the hash to find "Hello1234". The real password never lives in the database at all.

```ts
  const user = await prisma.user.create({
    data: { name, email, password: hashed },
  });
```

Save the user to the database. Notice: `password: hashed`. We store the scrambled hash, not what you typed. The original "Hello1234" is thrown away immediately after hashing.

---

#### ★ AREA 2: Creating the Session Cookie ★

```ts
  const session = await getSession();
  session.userId = user.id;
  session.name = user.name;
  session.email = user.email;
  await session.save();
```

After saving the user, we immediately log them in by creating their session. Here's what happens step by step:

1. `getSession()` reads the cookie jar for this request. Since this is a brand new user, there's no cookie yet — `getSession()` returns an empty session object.
2. We write three things into it: the user's ID (a unique string like `clx3abc123`), their name, and their email.
3. `session.save()` — this is where the magic happens. iron-session takes those three values, scrambles them using `SESSION_SECRET`, and tells Next.js to set a cookie called `gatekeeper_session` in the browser's response.

The browser receives the response and stores the cookie. From this moment on, every request the browser makes to our site will include that cookie in the `Cookie:` header, like this:

```
Cookie: gatekeeper_session=Fe26.2**abc123def...scrambled...xyz
```

The `Fe26.2**` prefix is iron-session's signature — it marks the format it uses.

```ts
  redirect("/dashboard");
```

The server tells the browser: "go to /dashboard." The browser follows the instruction, and because it now has the session cookie, the dashboard knows who you are.

---

### 4b. Logging In — `loginAction`

```ts
export async function loginAction(_prev: ActionResult, formData: FormData) {
  const raw = { email: formData.get("email"), password: formData.get("password") };
  const parsed = loginSchema.safeParse(raw);
  if (!parsed.success) {
    return { errors: parsed.error.flatten().fieldErrors };
  }
```

Same pattern as signup: collect the form data, run it through Zod. If Zod says "the email doesn't look like an email," we stop right there.

```ts
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return { errors: { email: ["Invalid email or password"] } };
  }
```

Ask the database: "do we have a user with this email?" Notice the error message says "Invalid email **or** password" — not "email not found." This is intentional. If we said "email not found," a hacker could learn which emails are registered. By being vague, we give nothing away.

---

#### ★ AREA 1 (continued): How Passwords Get Verified ★

```ts
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    return { errors: { email: ["Invalid email or password"] } };
  }
```

This is the verification step. We have:
- `password` — what the user just typed into the login form
- `user.password` — the scrambled hash we stored in the database during signup

`bcrypt.compare` does something clever. Remember, you can't un-scramble a hash. So instead of unscrambling, bcrypt **re-scrambles** the typed password using the *same recipe* that was baked into the stored hash. If the result matches the stored hash, the password is correct.

```
User types:      "Hello1234"
bcrypt rescrambles with stored salt → "$2a$12$x9v3mLqP...eKjZ2mRvQ7"
                                              ↑
                              matches the stored hash? YES → valid = true
```

The salt (random noise baked into the hash during signup) ensures that even two users with the same password end up with completely different hashes, so hackers can't use "rainbow tables" (pre-computed lists of common hashes).

```ts
  const session = await getSession();
  session.userId = user.id;
  session.name = user.name;
  session.email = user.email;
  await session.save();

  redirect("/dashboard");
```

Exact same as signup: write the user data into the session, save the cookie, go to dashboard.

---

### 4c. Logging Out — `logoutAction`

```ts
export async function logoutAction() {
  const session = await getSession();
  session.destroy();
  redirect("/");
}
```

- `getSession()` reads the existing session cookie.
- `session.destroy()` tells iron-session to wipe the cookie — it sends a `Set-Cookie` header that expires the cookie immediately, so the browser deletes it.
- `redirect("/")` sends you back to the landing page.

After this, the browser has no session cookie. The next request looks like a stranger again.

---

## 5. The Coloured Bars — `app/signup/PasswordStrength.tsx`

```ts
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

`score` adds up points:
- 8+ characters → +1
- 12+ characters → +1 more (long passwords are way better)
- Has a capital letter → +1
- Has a number → +1
- Has a symbol like `!`, `@`, `#` → +1 (`[^A-Za-z0-9]` means "anything that's not a letter or number")

Maximum score: 5.

```ts
const levels = [
  { label: "Too weak", color: "bg-red-500" },
  ...
  { label: "Very strong", color: "bg-emerald-500" },
];
```

Six levels because score goes 0–5. Score 0 = "Too weak" (red). Score 5 = "Very strong" (emerald green).

```ts
const s = useMemo(() => score(password), [password]);
```

`useMemo` recalculates the score only when `password` changes — not on every single render. This keeps it fast.

```ts
{Array.from({ length: 5 }).map((_, i) => (
  <div className={i < filled ? color : "bg-zinc-700"} />
))}
```

Draws 5 little bars. If `i < filled` (the bar's position is less than the score), paint it the strength colour. Otherwise paint it grey. So a score of 3 lights up 3 bars.

This whole component runs **live in the browser** as you type — it's a `"use client"` component and never talks to the server. The server-side validation in Zod is completely separate and runs independently when you actually submit.

---

## 6. The Sign-Up Form — `app/signup/SignupForm.tsx`

```ts
"use client";

const [state, action, pending] = useActionState(signupAction, initial);
```

`useActionState` is a React hook that wires a Server Action to a form. It gives us three things:
- `state` — the current result from the last time the action ran (errors or nothing)
- `action` — a wrapped version of `signupAction` that React knows about
- `pending` — `true` while the form is waiting for the server to respond

```ts
<form action={action}>
```

Instead of `onSubmit` (which would need JavaScript to intercept), we use `action={action}`. This means the form works even without JavaScript — it submits like a normal HTML form. React upgrades it to an async in-page submission when JavaScript is available.

```ts
{state.errors?.name && (
  <p className="mt-1 text-xs text-red-400">{state.errors.name[0]}</p>
)}
```

If `signupAction` returned errors (from Zod failing on the server), `state.errors.name` will have an array of error strings. We show the first one under the relevant field.

```ts
<button disabled={pending}>
  {pending ? "Creating account…" : "Create account"}
</button>
```

While the server is processing (Zod + database + bcrypt + session), the button goes grey and the text changes. Stops you from submitting twice.

---

## ★ AREA 3: How the Protected Route Knows You Are Logged In ★

There are **two separate checkpoints** protecting the dashboard. Think of them as:
1. A bouncer at the building entrance (the proxy)
2. A second check at the door of the specific room (the page itself)

### Checkpoint 1 — The Bouncer at the Entrance: `proxy.ts`

```ts
export const config = {
  matcher: ["/dashboard/:path*"],
};
```

This tells Next.js: "run the `proxy` function for EVERY request that starts with `/dashboard/`." Before the page code runs — before React renders anything — the proxy intercepts.

```ts
export async function proxy(req: NextRequest) {
  const res = NextResponse.next();
  const session = await getIronSession<SessionData>(req, res, sessionOptions);
```

The proxy runs at the **edge** — very early in the request lifecycle, before most of the app loads. It calls `getIronSession` directly, passing it the raw request (which contains the browser's cookies). It decrypts the `gatekeeper_session` cookie using the same `SESSION_SECRET`.

```ts
  if (!session.userId) {
    const loginUrl = new URL("/login", req.url);
    loginUrl.searchParams.set("from", req.nextUrl.pathname);
    return NextResponse.redirect(loginUrl);
  }
```

If `session.userId` is empty (no cookie, or the cookie was tampered with and decryption failed), we redirect to `/login` immediately — with a `?from=/dashboard` query param so after login you can be sent right back.

The browser never even sees the dashboard HTML. A `307 Temporary Redirect` is sent instead.

```ts
  return res;
```

If `session.userId` exists, `NextResponse.next()` lets the request continue to the actual page.

### Checkpoint 2 — Double-Check Inside the Room: `app/dashboard/page.tsx`

```ts
export default async function DashboardPage() {
  const session = await getSession();
  if (!session.userId) redirect("/login");
```

Even though the proxy already checked, the page checks again. Why? Defence in depth. If someone somehow bypassed the proxy (maybe a future middleware bug, a misconfigured deployment, a test environment without the proxy), this check ensures the dashboard page will never render for a logged-out user under any circumstances.

```ts
  <h1>Welcome, {session.name}</h1>
  <p>{session.email}</p>
```

The session already holds the name and email — we put them there during login. No extra database query needed. The session is the source of truth for "who is currently logged in."

```ts
  <form action={logoutAction}>
    <button type="submit">Log Out</button>
  </form>
```

The logout button is wrapped in a `<form>` with a Server Action. Same pattern as the login form. Clicking the button sends a POST to the server, `logoutAction` destroys the cookie, and you're sent home.

---

## The Full Journey — All Together

Here's the complete flow from "I want to sign up" to "I am in the dashboard."

```
SIGN UP
──────
1. User fills in form → browser
2. Form submits → server (signupAction)
3. Zod checks the shape → server
4. Database checks for duplicate email → server
5. bcrypt.hash(password, 12) → server
   └─ original password is discarded, only hash saved
6. prisma.user.create({ name, email, hash }) → database
7. getSession() → empty session object → server
8. session.userId = newUser.id → server memory
9. session.save() → iron-session encrypts with SESSION_SECRET
   └─ Set-Cookie: gatekeeper_session=Fe26.2**... (httpOnly, secure, sameSite)
   └─ cookie sent back to browser
10. redirect("/dashboard") → browser follows
11. Browser visits /dashboard WITH the cookie

DASHBOARD ACCESS
────────────────
12. Request hits proxy.ts first
13. getIronSession reads Cookie header, decrypts with SESSION_SECRET
14. session.userId exists → proxy lets request through
15. DashboardPage runs, getSession() decrypts again, double-checks
16. Renders "Welcome, [name]" using session.name

LOG IN (next visit)
───────────────────
1. User submits email + password
2. Zod checks format
3. prisma.user.findUnique({ email }) → get stored hash from DB
4. bcrypt.compare(typedPassword, storedHash)
   └─ re-scrambles typedPassword, compares to storedHash
   └─ if they match → valid = true
5–10. Same as sign up steps 7–10

LOG OUT
───────
1. Button submits form → logoutAction
2. session.destroy() → iron-session expires the cookie
3. redirect("/") → browser has no cookie now
4. Next visit to /dashboard → proxy sees empty session → redirects to /login
```

---

## Why Each Security Decision Was Made

| Decision | Why |
|---|---|
| `bcrypt.hash(password, 12)` | Slows down brute-force guessing enormously |
| Store hash, not password | Database breach reveals nothing usable |
| `bcrypt.compare` not string equality | The only safe way to check a hash — you re-hash and compare |
| `httpOnly: true` cookie | JavaScript can't steal the cookie, so XSS attacks can't hijack sessions |
| `secure: true` in production | Cookie only travels encrypted — prevents network sniffing |
| `sameSite: "lax"` | Stops other websites from riding your session (CSRF protection) |
| iron-session encryption | Even if someone reads the cookie value, it's ciphertext — meaningless without `SESSION_SECRET` |
| Zod on the server | Client validation is cosmetic; only server validation actually counts |
| Proxy + page double-check | Two layers mean no single point of failure for auth bypass |
| "Invalid email or password" for both failures | Attackers can't enumerate which emails are registered |
