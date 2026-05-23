import { getSession } from "@/lib/session";
import { redirect } from "next/navigation";
import { logoutAction } from "@/app/actions/auth";

export const metadata = { title: "Dashboard — The Gatekeeper" };

export default async function DashboardPage() {
  const session = await getSession();
  if (!session.userId) redirect("/login");

  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4">
      <div className="w-full max-w-lg">
        <div className="rounded-2xl border border-zinc-800 bg-zinc-900/50 p-10 shadow-xl text-center">
          <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-full bg-indigo-600/20 ring-2 ring-indigo-600/40">
            <span className="text-2xl font-bold text-indigo-400">
              {session.name.charAt(0).toUpperCase()}
            </span>
          </div>

          <h1 className="text-2xl font-bold text-white">
            Welcome, {session.name}
          </h1>
          <p className="mt-2 text-sm text-zinc-400">{session.email}</p>

          <div className="mt-8 rounded-xl border border-zinc-800 bg-zinc-950/60 px-6 py-4 text-left">
            <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500 mb-3">
              Session info
            </p>
            <dl className="space-y-2 text-sm">
              <div className="flex justify-between">
                <dt className="text-zinc-400">Name</dt>
                <dd className="text-zinc-200 font-medium">{session.name}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-zinc-400">Email</dt>
                <dd className="text-zinc-200 font-medium">{session.email}</dd>
              </div>
              <div className="flex justify-between">
                <dt className="text-zinc-400">Status</dt>
                <dd className="inline-flex items-center gap-1.5 text-green-400 font-medium">
                  <span className="h-1.5 w-1.5 rounded-full bg-green-400 animate-pulse" />
                  Authenticated
                </dd>
              </div>
            </dl>
          </div>

          <form action={logoutAction} className="mt-8">
            <button
              type="submit"
              className="w-full rounded-xl border border-zinc-700 bg-zinc-900 py-3 text-sm font-semibold text-zinc-300 transition hover:bg-zinc-800 hover:text-white"
            >
              Log Out
            </button>
          </form>
        </div>
      </div>
    </main>
  );
}
