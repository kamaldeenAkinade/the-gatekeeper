"use server";

import { redirect } from "next/navigation";
import bcrypt from "bcryptjs";
import { prisma } from "@/lib/prisma";
import { getSession } from "@/lib/session";
import { signupSchema, loginSchema } from "@/lib/validations";
import { allow } from "@/lib/rateLimit";
import { log } from "@/lib/audit";
import { createVerificationToken, verifyEmailToken } from "@/lib/verification";
import { headers } from "next/headers";

const DUMMY_HASH =
  "$2a$12$ZeU7mxBVhNsXTZaGM3NuJ.LJv3mq9YPlOd5WtmGYjmKrv6rkuGOaS";

export type ActionResult = {
  errors?: Record<string, string[]>;
  message?: string;
};

export async function signupAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  const ip = (await headers()).get("x-forwarded-for") ?? "127.0.0.1";

  if (!allow(`signup:ip:${ip}`, 3, 60 * 60 * 1000)) {
    return { message: "Too many signup attempts from this location. Please try again later." };
  }

  const raw = {
    name: formData.get("name"),
    email: formData.get("email"),
    password: formData.get("password"),
  };

  const parsed = signupSchema.safeParse(raw);
  if (!parsed.success) {
    return { message: "If that email is available, check your inbox for instructions." };
  }

  const { name, email, password } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    return { message: "If that email is available, check your inbox for instructions." };
  }

  const pendingExists = await prisma.pendingUser.findUnique({ where: { email } });
  if (pendingExists) {
    return { message: "If that email is available, check your inbox for instructions." };
  }

  const hashed = await bcrypt.hash(password, 12);
  const token = createVerificationToken(email);

  await prisma.pendingUser.create({
    data: { name, email, password: hashed, token },
  });

  log({ type: "signup", userId: "", email });

  return { message: "If that email is available, check your inbox for instructions." };
}

export async function verifyEmailAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  const token = String(formData.get("token") ?? "");
  const email = String(formData.get("email") ?? "");

  const pending = await prisma.pendingUser.findUnique({ where: { email } });
  if (!pending) {
    return { message: "Invalid or expired verification link." };
  }

  if (!verifyEmailToken(token, email)) {
    return { message: "Invalid or expired verification link." };
  }

  const user = await prisma.user.create({
    data: {
      name: pending.name,
      email: pending.email,
      password: pending.password,
    },
  });

  await prisma.pendingUser.delete({ where: { id: pending.id } });

  log({ type: "signup", userId: user.id, email: user.email });

  return { message: "Email verified! You can now log in." };
}

export async function loginAction(
  _prev: ActionResult,
  formData: FormData
): Promise<ActionResult> {
  const ip = (await headers()).get("x-forwarded-for") ?? "127.0.0.1";
  const email = String(formData.get("email") ?? "").toLowerCase();

  if (!allow(`login:ip:${ip}`) || !allow(`login:email:${email}`, 10)) {
    return {
      message: "Too many login attempts. Please wait 15 minutes before trying again.",
    };
  }

  const raw = {
    email: formData.get("email"),
    password: formData.get("password"),
  };

  const parsed = loginSchema.safeParse(raw);
  if (!parsed.success) {
    return { errors: parsed.error.flatten().fieldErrors };
  }

  const { email: parsedEmail, password } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email: parsedEmail } });

  const hashToCompare = user?.password ?? DUMMY_HASH;
  const valid = await bcrypt.compare(password, hashToCompare);

  if (!user || !valid) {
    log({
      type: "login_failed",
      email: parsedEmail,
      reason: !user ? "user_not_found" : "wrong_password",
    });
    return { errors: { email: ["Invalid email or password"] } };
  }

  log({ type: "login", userId: user.id, email: user.email });

  const session = await getSession();
  session.userId = user.id;
  session.name = user.name;
  session.email = user.email;
  session.sessionVersion = user.sessionVersion;
  await session.save();

  redirect("/dashboard");
}

export async function logoutAction() {
  const session = await getSession();
  if (session.userId) {
    log({ type: "logout", userId: session.userId });
  }
  session.destroy();
  redirect("/");
}
