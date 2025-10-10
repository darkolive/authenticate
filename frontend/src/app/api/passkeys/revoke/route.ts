import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { validateSession, revokePasskeys } from "@/lib/actions";

export async function POST(req: Request) {
  try {
    const form = await req.formData();
    const credentialId = String(form.get("credentialId") ?? "").trim();

    // Validate session and get userId
    const cookieStore = await cookies();
    const token =
      cookieStore.get("__Host-hm_session")?.value ||
      cookieStore.get("hm_session")?.value;
    if (!token) {
      return NextResponse.redirect(new URL("/signin", req.url));
    }
    const session = await validateSession(token);
    if (!session.valid || !session.userId) {
      return NextResponse.redirect(new URL("/signin", req.url));
    }

    const ipAddress = req.headers.get("x-forwarded-for") || "";
    const userAgent = req.headers.get("user-agent") || "";

    const res = await revokePasskeys({
      userId: session.userId,
      credentialId: credentialId || undefined, // empty means revoke all
      reason: "user-initiated",
      ipAddress,
      userAgent,
    });

    if (!res?.success) {
      return NextResponse.json(
        { error: res?.message || "Failed to revoke passkeys" },
        { status: 400 }
      );
    }

    return NextResponse.redirect(new URL("/dashboard", req.url));
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process request";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
