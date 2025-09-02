import { NextResponse } from "next/server";
import { beginWebAuthnLogin } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { userId } = (body as { userId?: string }) ?? {};

    // Extract client metadata
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";

    if (!userId) {
      // We currently require a userId to begin WebAuthn login. If only channelDID was provided,
      // obtain userId upstream (e.g., via CerberusGate) and retry.
      return NextResponse.json(
        { error: "userId is required to begin WebAuthn login (obtain via CerberusGate or prior step)" },
        { status: 400 }
      );
    }

    const data = await beginWebAuthnLogin({ userId, ipAddress, userAgent });
    return NextResponse.json({
      success: true,
      options: JSON.parse(data.optionsJSON),
      challenge: data.challenge,
      expiresAt: data.expiresAt,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process WebAuthn login";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

