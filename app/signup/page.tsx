import { getSession } from "@/lib/session";
import { redirect } from "next/navigation";
import SignupForm from "./SignupForm";
import Link from "next/link";

export const metadata = { title: "Sign Up — The Gatekeeper" };

export default async function SignupPage() {
  const session = await getSession();
  if (session.userId) redirect("/dashboard");

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="mb-8 text-center">
          <Link href="/" className="inline-flex items-center gap-2 text-zinc-400 hover:text-zinc-200 text-sm mb-6">
            ← Back
          </Link>
          <h1 className="text-2xl font-bold text-white">Create your account</h1>
          <p className="mt-1 text-sm text-zinc-400">Join The Gatekeeper today</p>
        </div>

        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-8 shadow-xl backdrop-blur-sm">
          <SignupForm />
        </div>
      </div>
    </main>
  );
}
