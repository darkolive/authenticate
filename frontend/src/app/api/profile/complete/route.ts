import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { updateUserpersona, validateSession } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const headers = req.headers;
    const body = (await req.json().catch(() => ({}))) as {
      firstName?: string;
      lastName?: string;
      displayName?: string;
    };

    const cookieStore = await cookies();
    let token = cookieStore.get("__Host-hm_session")?.value;
    if (!token && process.env.NODE_ENV !== "production") {
      token = cookieStore.get("hm_session")?.value;
    }
    if (!token) {
      return NextResponse.json(
        { error: "missing session token" },
        { status: 401 }
      );
    }

    const session = await validateSession(token);
    if (!session?.valid || !session?.userId) {
      return NextResponse.json({ error: "invalid session" }, { status: 401 });
    }

    // Persist persona to backend (strict)
    const ipAddress = getClientIp(req) ?? "";
    const userAgent = headers.get("user-agent") ?? "";
    const up = await updateUserpersona({
      userId: session.userId,
      firstName: body.firstName,
      lastName: body.lastName,
      displayName: body.displayName,
      ipAddress,
      userAgent,
    });
    if (!up?.success) {
      return NextResponse.json(
        { error: up?.message || "Failed to update persona" },
        { status: 400 }
      );
    }

    const res = NextResponse.json({ success: true, updatedAt: up.updatedAt });
    // Clear the legacy gating cookie (no longer relied upon; kept for backward compatibility)
    const secure = process.env.NODE_ENV === "production";
    res.cookies.set("needs_onboarding", "", {
      httpOnly: true,
      secure,
      sameSite: "lax",
      path: "/",
      maxAge: 0,
    });
    return res;
  } catch (e: unknown) {
    const message =
      e instanceof Error ? e.message : "Failed to complete persona";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
