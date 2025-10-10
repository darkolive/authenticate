import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { validateSession, getLinkedChannels, listMergeCandidates, listPasskeys, getUserPII } from "@/lib/actions";
import AddChannelCard from "@/components/AddChannelCard";

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

  // Fetch decrypted persona (non-fatal if unavailable)
  let pii: { firstName?: string; lastName?: string; displayName?: string; firstName_enc?: string; lastName_enc?: string; displayName_enc?: string; message?: string } = {};
  try {
    pii = await getUserPII(session.userId!);
  } catch {}

  let linked: { channels: Array<{ uid: string; channelType: string; verified: boolean; normalizedValue: string; lastVerifiedAt?: string }>; clusterUID?: string; message?: string } = { channels: [] };
  try {
    linked = await getLinkedChannels(session.userId!);
  } catch {
    // If backend hasn't exposed getLinkedChannels yet, render gracefully without the list
    linked = { channels: [], message: "linked channels unavailable" };
  }

  // Fetch pending merge candidates (non-fatal if unavailable)
  let candidates: Array<{ uid: string; candidateDID: string; score: number; signals: string[] }> = [];
  try {
    const res = await listMergeCandidates(session.userId!);
    candidates = (res.items || []).map((i) => ({ uid: i.uid, candidateDID: i.candidateDID, score: i.score, signals: i.signals || [] }));
  } catch {}

  // Fetch passkeys (non-fatal if unavailable)
  let passkeys: Array<{ credentialId: string; addedAt?: string; revoked: boolean; revokedAt?: string; transports?: string }> = [];
  try {
    const res = await listPasskeys(session.userId!);
    passkeys = res.items || [];
  } catch {}

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
          <div className="mt-2 space-y-1">
            <div>
              <span className="font-medium">First Name:</span> {pii.firstName || "—"}
            </div>
            <div>
              <span className="font-medium">Last Name:</span> {pii.lastName || "—"}
            </div>
            <div>
              <span className="font-medium">First Name (as stored encrypted on Dgraph):</span> {pii.firstName_enc || "—"}
            </div>
            <div>
              <span className="font-medium">Last Name (as stored encrypted on Dgraph):</span> {pii.lastName_enc || "—"}
            </div>
          </div>
        </div>
        <div className="mt-4">
          <a
            href="/api/auth/signout?redirect=/signin"
            className="inline-flex items-center rounded-md bg-black px-3 py-2 text-sm font-medium text-white hover:bg-black/80"
          >
            Sign out
          </a>
        </div>
        {session.userId ? (
          <div className="mt-8">
            <AddChannelCard userId={session.userId} />
          </div>
        ) : null}
        {candidates.length > 0 && (
          <div className="mt-8">
            <h2 className="text-lg font-medium">Possible account links</h2>
            <ul className="mt-3 space-y-2">
              {candidates.map((mc) => (
                <li key={mc.uid} className="rounded-md border p-3 text-sm">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="font-medium">We detected a possible link</div>
                      <div className="text-gray-600">
                        Score {mc.score}
                        {mc.signals?.length ? ` · ${mc.signals.join(", ")}` : ""}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <form action="/api/merge/confirm" method="POST">
                        <input type="hidden" name="mergeCandidateUID" value={mc.uid} />
                        <input type="hidden" name="decision" value="confirm" />
                        <button className="inline-flex items-center rounded-md bg-black px-3 py-1.5 text-white hover:bg-black/80" type="submit">
                          Confirm
                        </button>
                      </form>
                      <form action="/api/merge/confirm" method="POST">
                        <input type="hidden" name="mergeCandidateUID" value={mc.uid} />
                        <input type="hidden" name="decision" value="dismiss" />
                        <button className="inline-flex items-center rounded-md border px-3 py-1.5 hover:bg-gray-50" type="submit">
                          Dismiss
                        </button>
                      </form>
                    </div>
                  </div>
                  <p className="mt-2 text-xs text-gray-500">No changes will be made to your channels without OTP verification.</p>
                </li>
              ))}
            </ul>
          </div>
        )}
        <div className="mt-8">
          <h2 className="text-lg font-medium">Linked channels</h2>
          {linked.channels && linked.channels.length > 0 ? (
            <ul className="mt-3 space-y-2">
              {linked.channels.map((ch) => (
                <li key={ch.uid} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                  <div>
                    <div className="font-medium capitalize">{ch.channelType}</div>
                    <div className="text-gray-600">
                      {maskValue(ch.channelType, ch.normalizedValue)}
                    </div>
                  </div>
                  <div className="text-right text-xs text-gray-600">
                    <div>{ch.verified ? "Verified" : "Unverified"}</div>
                    {ch.lastVerifiedAt ? (
                      <div>Last verified: {new Date(ch.lastVerifiedAt).toLocaleString()}</div>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-gray-500">No linked channels yet.</p>
          )}
        </div>
        <div className="mt-8">
          <h2 className="text-lg font-medium">Passkeys (WebAuthn)</h2>
          {passkeys && passkeys.length > 0 ? (
            <div className="mt-3 space-y-2">
              <div className="flex items-center justify-between">
                <div className="text-sm text-gray-600">
                  Manage your passkeys. You can revoke an individual passkey if lost/compromised, or revoke all.
                </div>
                <form action="/api/passkeys/revoke" method="POST">
                  <input type="hidden" name="credentialId" value="" />
                  <button className="inline-flex items-center rounded-md border px-3 py-1.5 text-sm hover:bg-gray-50" type="submit">
                    Revoke all
                  </button>
                </form>
              </div>
              <ul className="space-y-2">
                {passkeys.map((pk) => (
                  <li key={pk.credentialId} className="flex items-center justify-between rounded-md border px-3 py-2 text-sm">
                    <div>
                      <div className="font-medium">{maskCred(pk.credentialId)}</div>
                      <div className="text-xs text-gray-600">
                        {pk.revoked ? (
                          <span className="text-red-600">Revoked{pk.revokedAt ? ` · ${new Date(pk.revokedAt).toLocaleString()}` : ""}</span>
                        ) : (
                          <span className="text-green-700">Active{pk.addedAt ? ` · added ${new Date(pk.addedAt).toLocaleString()}` : ""}</span>
                        )}
                        {pk.transports ? ` · ${pk.transports}` : ""}
                      </div>
                    </div>
                    <div>
                      {!pk.revoked ? (
                        <form action="/api/passkeys/revoke" method="POST">
                          <input type="hidden" name="credentialId" value={pk.credentialId} />
                          <button className="inline-flex items-center rounded-md bg-black px-3 py-1.5 text-white hover:bg-black/80" type="submit">
                            Revoke
                          </button>
                        </form>
                      ) : (
                        <span className="text-xs text-gray-500">No actions</span>
                      )}
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="mt-3 text-sm text-gray-500">No passkeys found.</p>
          )}
        </div>
      </div>
    </main>
  );
}

function maskValue(channelType: string, value: string) {
  const v = (value || "").trim();
  if (channelType.toLowerCase() === "email") {
    const [local, domain] = v.split("@");
    if (!local || !domain) return "***";
    if (local.length <= 2) return `***@${domain}`;
    return `${local[0]}***${local[local.length - 1]}@${domain}`;
  }
  if (v.length <= 2) return "***";
  return `***${v.slice(-2)}`;
}

function maskCred(credentialId: string) {
  const v = (credentialId || "").trim();
  if (v.length <= 8) return "***";
  return `${v.slice(0, 4)}…${v.slice(-4)}`;
}
