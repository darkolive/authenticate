import { NextResponse } from "next/server";
import { beginWebAuthnRegistration } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      userId?: string;
      displayName?: string;
    };
    if (!body.userId) {
      return NextResponse.json({ error: "userId is required" }, { status: 400 });
    }
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const data = await beginWebAuthnRegistration({
      userId: body.userId,
      displayName: body.displayName,
      ipAddress,
      userAgent,
    });
    return NextResponse.json({
      success: true,
      options: JSON.parse(data.optionsJSON),
      challenge: data.challenge,
      expiresAt: data.expiresAt,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to begin WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
