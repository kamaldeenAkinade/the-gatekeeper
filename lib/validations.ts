import { z } from "zod";

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

export const loginSchema = z.object({
  email: z
    .string()
    .email("Invalid email address")
    .max(254, "Email address is too long"),
  password: z
    .string()
    .min(1, "Password is required")
    .max(72, "Password must be at most 72 characters"),
});

export type SignupInput = z.infer<typeof signupSchema>;
export type LoginInput = z.infer<typeof loginSchema>;
