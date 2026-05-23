# 06 – Lie Detector: Auth Flow Edition

Five statements about how the authentication flow works in this app.
Four are true. One is false.

Read the code, find the lie, and write down which statement you think
is wrong and why. The answer is hidden at the bottom.

---

## The Statements

**Statement 1**

Both a wrong email address and a wrong password return the exact same
error message: `"Invalid email or password"`. There is no way to tell
from the server's response which one failed.

---

**Statement 2**

Passwords in this app are hashed with bcrypt using a cost factor
(salt rounds) of **10**.

---

**Statement 3**

A successful signup does not just create an account — it also
immediately starts a session and redirects the user to `/dashboard`,
so the user is logged in the moment registration completes.

---

**Statement 4**

The session cookie is marked `httpOnly: true` in all environments,
but the `secure` flag is only set to `true` when
`NODE_ENV === "production"` — in local development the cookie is
sent over plain HTTP.

---

**Statement 5**

The Zod schema used to validate the login form only checks that the
password field is non-empty (`min(1, "Password is required")`). It
does **not** re-apply the signup rules — no uppercase requirement,
no number requirement.

---

## Your Turn

Which statement is the lie? Write your answer here and explain your
reasoning before scrolling down.

```
My answer: Statement #2

Reasoning: The code uses 12 as observed from this line 
const hashed = await bcrypt.hash(password, 12);
```

---
---
---
---
---
---
---
---
---
---

## Reveal

**The lie is Statement 2.**

The code in `app/actions/auth.ts` line 36 reads:

```ts
const hashed = await bcrypt.hash(password, 12);
```

The cost factor is **12**, not 10. Ten is the default that many
tutorials and libraries use, so it is a believable wrong answer — but
this codebase deliberately chose 12, which means each hash takes
roughly 4× longer to compute than at cost 10 (every +1 doubles the
work). That extra cost is intentional: it slows down brute-force
attacks proportionally.

---

### Why the other four are true

| # | Claim | Where to verify |
|---|---|---|
| 1 | Same generic error for wrong email OR wrong password | `auth.ts` lines 67–68, 72–73 — identical string both times |
| 3 | Signup auto-logs you in and redirects to `/dashboard` | `auth.ts` lines 41–47 — session is set, then `redirect("/dashboard")` |
| 4 | `httpOnly: true` always; `secure` only in production | `lib/session.ts` line 14 — `secure: process.env.NODE_ENV === "production"` |
| 5 | Login Zod schema only checks `min(1)` | `lib/validations.ts` lines 13–16 — no regex rules on the login schema |
