import { getIronSession, type SessionOptions } from "iron-session";
import { cookies } from "next/headers";
import { prisma } from "@/lib/prisma";

export interface SessionData {
  userId: string;
  name: string;
  email: string;
  sessionVersion?: number;
}

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

export const sessionOptions: SessionOptions = {
  cookieName: "gatekeeper_session",
  password: process.env.SESSION_SECRET as string,
  cookieOptions: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    sameSite: "strict",
    maxAge: 60 * 60 * 8,
  },
};

export async function getSession() {
  const session = await getIronSession<SessionData>(
    await cookies(),
    sessionOptions
  );

  if (session.userId) {
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      select: { sessionVersion: true },
    });

    if (!user || session.sessionVersion !== user.sessionVersion) {
      session.destroy();
      return session;
    }
  }

  return session;
}

export async function revokeAllSessions(userId: string): Promise<void> {
  await prisma.user.update({
    where: { id: userId },
    data: { sessionVersion: { increment: 1 } },
  });
}
