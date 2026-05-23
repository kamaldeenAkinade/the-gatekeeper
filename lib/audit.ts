export type AuthEvent =
  | { type: "signup"; userId: string; email: string }
  | { type: "login"; userId: string; email: string }
  | { type: "login_failed"; email: string; reason: "user_not_found" | "wrong_password" }
  | { type: "logout"; userId: string }
  | { type: "session_revoked"; userId: string };

export function log(event: AuthEvent): void {
  const timestamp = new Date().toISOString();

  if (process.env.NODE_ENV === "development") {
    console.log(JSON.stringify({ timestamp, ...event }));
    return;
  }
}
