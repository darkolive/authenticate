import { NextResponse } from "next/server";
import { beginWebAuthnRegistration } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { userId, displayName } = (body as { userId?: string; displayName?: string }) ?? {};

    // Extract client metadata
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";

    if (!userId) {
      return NextResponse.json(
        { error: "userId is required to begin WebAuthn registration (obtain via CerberusGate or prior step)" },
        { status: 400 }
      );
    }

    const data = await beginWebAuthnRegistration({ userId, displayName, ipAddress, userAgent });
    return NextResponse.json({
      success: true,
      options: JSON.parse(data.optionsJSON),
      challenge: data.challenge,
      expiresAt: data.expiresAt,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
