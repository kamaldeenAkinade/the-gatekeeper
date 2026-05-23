"use client";

import { useMemo } from "react";

interface Props {
  password: string;
}

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

const levels = [
  { label: "Too weak", color: "bg-red-500" },
  { label: "Weak", color: "bg-orange-500" },
  { label: "Fair", color: "bg-yellow-500" },
  { label: "Good", color: "bg-lime-500" },
  { label: "Strong", color: "bg-green-500" },
  { label: "Very strong", color: "bg-emerald-500" },
];

export default function PasswordStrength({ password }: Props) {
  const s = useMemo(() => score(password), [password]);
  const { label, color } = levels[s];
  const filled = s;

  if (!password) return null;

  return (
    <div className="mt-2 space-y-1">
      <div className="flex gap-1">
        {Array.from({ length: 5 }).map((_, i) => (
          <div
            key={i}
            className={`h-1.5 flex-1 rounded-full transition-colors duration-300 ${
              i < filled ? color : "bg-zinc-700"
            }`}
          />
        ))}
      </div>
      <p className={`text-xs font-medium ${s <= 1 ? "text-red-400" : s <= 2 ? "text-yellow-400" : "text-green-400"}`}>
        {label}
      </p>
    </div>
  );
}
