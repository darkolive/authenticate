import { NextResponse } from "next/server";
import { finishWebAuthnRegistration } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      userId?: string;
      challenge?: string;
      credentialJSON?: string;
      credential?: unknown;
    };
    const { userId, challenge } = body;
    if (!userId || !challenge) {
      return NextResponse.json(
        { error: "userId and challenge are required" },
        { status: 400 }
      );
    }
    const credentialJSON =
      typeof body.credentialJSON === "string"
        ? body.credentialJSON
        : JSON.stringify(body.credential ?? {});

    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const data = await finishWebAuthnRegistration({
      userId,
      challenge,
      credentialJSON,
      ipAddress,
      userAgent,
    });
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message =
      e instanceof Error ? e.message : "Failed to finish WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

