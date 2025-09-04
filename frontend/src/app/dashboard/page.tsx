import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { validateSession } from "@/lib/actions";

export default async function DashboardPage() {
  const cookieStore = await cookies();
  let token = cookieStore.get("__Host-hm_session")?.value;
  if (!token && process.env.NODE_ENV !== "production") {
    token = cookieStore.get("hm_session")?.value;
  }
  if (!token) {
    redirect("/signin");
  }

  const session = await validateSession(token!);
  if (!session.valid) {
    redirect("/signin");
  }

  return (
    <main className="mx-auto max-w-2xl p-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      <p className="mt-2 text-sm text-gray-500">You are signed in.</p>
      <div className="mt-6 rounded-md border p-4">
        <div className="text-sm">
          <div>
            <span className="font-medium">User ID:</span> {session.userId}
          </div>
          {session.expiresAt ? (
            <div>
              <span className="font-medium">Session expires:</span> {new Date(session.expiresAt).toLocaleString()}
            </div>
          ) : null}
        </div>
        <div className="mt-4">
          <a
            href="/api/auth/signout?redirect=/signin"
            className="inline-flex items-center rounded-md bg-black px-3 py-2 text-sm font-medium text-white hover:bg-black/80"
          >
            Sign out
          </a>
        </div>
      </div>
    </main>
  );
}
