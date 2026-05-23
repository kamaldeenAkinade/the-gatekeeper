import { verifyEmailAction } from "@/app/actions/auth";
import Link from "next/link";

export const metadata = { title: "Verify Email — The Gatekeeper" };

export default async function VerifyPage(props: {
  searchParams: Promise<{ token?: string; email?: string }>;
}) {
  const { token, email } = await props.searchParams;

  if (!token || !email) {
    return (
      <main className="flex min-h-screen flex-col items-center justify-center px-4">
        <div className="w-full max-w-md text-center">
          <h1 className="text-2xl font-bold text-white">Invalid verification link</h1>
          <p className="mt-2 text-sm text-zinc-400">
            This link is missing required parameters. Check your email for the full link.
          </p>
          <Link
            href="/login"
            className="mt-6 inline-block rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-indigo-500"
          >
            Go to login
          </Link>
        </div>
      </main>
    );
  }

  const formData = new FormData();
  formData.set("token", token);
  formData.set("email", email);

  const result = await verifyEmailAction({}, formData);

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-md text-center">
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-10 shadow-xl">
          <h1 className="text-2xl font-bold text-white">
            {result.message?.includes("verified") ? "Email Verified" : "Verification failed"}
          </h1>
          <p className="mt-2 text-sm text-zinc-400">{result.message}</p>
          {result.message?.includes("verified") && (
            <Link
              href="/login"
              className="mt-6 inline-block rounded-xl bg-indigo-600 px-6 py-3 text-sm font-semibold text-white transition hover:bg-indigo-500"
            >
              Log in
            </Link>
          )}
        </div>
      </div>
    </main>
  );
}
