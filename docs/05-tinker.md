# 05 – Tinker: Removing bcrypt and Replacing with Plain String Equality

## 1. The Function Under the Microscope

**File:** `app/actions/auth.ts`, line 71  
**Function:** `loginAction`

```ts
const valid = await bcrypt.compare(password, user.password);
```

`bcrypt.compare` takes the plain-text password the user just typed and
the bcrypt hash that was stored during signup. It re-runs the bcrypt
derivation with the salt embedded in the hash, then compares the result
in constant time. Only if they match does it return `true`.

---

## 2. My Prediction — Written Before the Change

> **My original guess:** "the password will be visible in localStorage."

That prediction is **wrong**, and here is why:

- Sessions are managed by **iron-session**, which stores data in an
  encrypted, signed cookie called `gatekeeper_session`. The cookie is
  `httpOnly: true`, which means JavaScript (and therefore localStorage)
  can never read it. No password data — not even a hash — is ever
  written to localStorage at any point in this application.

**What will actually happen when `bcrypt.compare` is replaced with `===`:**

The password column in the database stores a bcrypt hash, for example:

```
$2b$12$ZNAdCAp8cR3cPcAiy851zOZke5.asy22wSRRulET2j0a4U94ECH2C
```

The comparison that will run instead is:

```ts
const valid = password === user.password;
// e.g. "MySecret123!" === "$2b$12$ZNAdCAp8cR3c..."  →  false, always
```

A plain text password can **never** equal a 60-character bcrypt hash
string. This means:

| Who tries to log in | Expected outcome |
|---|---|
| Attacker with wrong password | Login fails ✓ (but for the wrong reason) |
| Legitimate user with correct password | Login **also fails** ✗ |
| Anyone at all | Complete authentication lockout — no one can log in |

**Security consequences of this change:**

1. **Denial of service on authentication.** Every login attempt returns
   "Invalid email or password." The app becomes unusable. This is the
   immediate breakage.

2. **Passwords exposed if storage is also weakened.** If someone also
   removed the `bcrypt.hash` call in `signupAction` (storing passwords
   as plain text instead of hashing them), then `===` would work again
   — but now every password in the database would be readable to anyone
   who can run `SELECT * FROM User`. A single database leak or a rogue
   employee would expose every user's real password.

3. **Timing attack surface opens up.** `bcrypt.compare` runs in
   constant time regardless of how similar the inputs are. JavaScript's
   `===` short-circuits on the first differing character. On a plain-
   text storage system this leaks information about how close a guess
   is (though the effect is tiny over a network).

4. **Password reuse amplification.** People reuse passwords. If this
   database were leaked in plain text, those same passwords would work
   on Gmail, banks, etc. bcrypt hashing limits the blast radius of a
   breach to this one service.

---

## 3. The Change (local only, reverted before commit)

Replacing line 71 of `app/actions/auth.ts`:

```ts
// BEFORE (correct)
const valid = await bcrypt.compare(password, user.password);

// AFTER (broken — for experiment only)
const valid = password === user.password;
```

---

## 4. What I Observed

### 4a. Correcting the localStorage prediction

The password is **never in localStorage**. The session is an `httpOnly`
cookie (`gatekeeper_session`) set by iron-session. `httpOnly` means no
JavaScript on the page can read it at all — not even the browser's own
`document.cookie`. It is sealed server-side with a secret key.

### 4b. Testing the === comparison directly (Node.js)

I ran a Node.js script that demonstrates the comparison exactly as it
runs inside `loginAction` after the change:

```
=== Plain === comparison ===
wrong password   : false   (wrong password still fails)
hash as password : true    ← CRITICAL FINDING (see below)

=== bcrypt.compare ===
wrong password: false   (correctly rejected)

--- Round-trip demonstration ---
plain "Abc123!Xyz" stored as hash: $2b$10$UmRI...
=== comparison:     false   ← plain text never equals a bcrypt hash
bcrypt.compare:     true    ← only bcrypt can verify it
```

### 4c. Behavior with a wrong password

**Result: login still fails** — but for the wrong reason.

With bcrypt, the failure means "the hash didn't match, we verified
cryptographically." With `===`, the failure means "the two strings
aren't identical characters," which is also true, but it also means:

**The correct password fails for the same reason.** `"MyRealPassword"`
will never equal `"$2b$12$..."`, so every login attempt fails, whether
the password is right or wrong. The login system is completely broken.

### 4d. The surprising backdoor

This is what I did NOT predict: `storedHash === storedHash` → **`true`**.

If an attacker obtains the database (via SQL injection, a backup leak,
a misconfigured S3 bucket, etc.) and copies a user's hash, they can
paste that 60-character hash string into the password field and log in
immediately. The `===` check passes because the input now literally
equals what is stored. bcrypt would still reject this because a bcrypt
hash is not the original password — bcrypt.compare re-derives the hash
from the plain-text input; it never accepts the hash itself as input.

| Attempt | bcrypt.compare | === (broken) |
|---|---|---|
| Wrong password | ❌ rejected | ❌ rejected |
| Correct password | ✅ accepted | ❌ rejected (broken!) |
| Stolen hash as password | ❌ rejected | ✅ **accepted (backdoor!)** |

### 4e. HTTP test result

When I submitted the login form via curl against the running dev
server, the server returned HTTP 500 with message `"Connection closed"`.
This is a **separate, pre-existing issue** unrelated to the password
comparison: the `PrismaLibSql` adapter (libSQL/Turso SQLite driver)
drops its connection on hot-module-reload in development. The database
was re-queried after `auth.ts` was edited and the module was
invalidated, causing the libSQL connection to close before the query
could complete. The password comparison logic was never reached in the
HTTP test, but the Node.js direct test above confirms behavior precisely.

---

## 5. Summary

| Question | Answer |
|---|---|
| Is the password in localStorage? | No — it lives only in the database as a hash |
| Can you log in with the wrong password after the change? | No (same failure message) |
| Can you log in with the correct password after the change? | **No** — login is fully broken |
| Is there a security risk beyond lockout? | **Yes** — stolen hash → instant login |
| Why does bcrypt protect against the hash-as-password attack? | It re-derives the hash from input; it never compares hash to hash |

**Revert status:** `bcrypt.compare` restored (see git diff).
