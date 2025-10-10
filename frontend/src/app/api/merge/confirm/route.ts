import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { validateSession, confirmMergeCandidate } from "@/lib/actions";

export async function POST(req: Request) {
  try {
    const form = await req.formData();
    const mergeCandidateUID = String(form.get("mergeCandidateUID") || "").trim();
    const decision = String(form.get("decision") || "").trim().toLowerCase();

    if (!mergeCandidateUID || (decision !== "confirm" && decision !== "dismiss")) {
      return NextResponse.json({ error: "mergeCandidateUID and decision are required" }, { status: 400 });
    }

    // Validate session and get userId (DID) for auditing
    const cookieStore = await cookies();
    const token = cookieStore.get("__Host-hm_session")?.value || cookieStore.get("hm_session")?.value;
    if (!token) {
      return NextResponse.redirect(new URL("/signin", req.url));
    }
    const session = await validateSession(token);
    if (!session.valid || !session.userId) {
      return NextResponse.redirect(new URL("/signin", req.url));
    }

    const res = await confirmMergeCandidate({
      mergeCandidateUID,
      decision: decision as "confirm" | "dismiss",
      userId: session.userId,
    });
    if (!res?.success) {
      return NextResponse.json({ error: res?.message || "Failed to update merge candidate" }, { status: 400 });
    }

    // Redirect back to dashboard
    return NextResponse.redirect(new URL("/dashboard", req.url));
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process request";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
