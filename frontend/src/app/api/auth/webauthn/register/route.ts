import { NextResponse } from "next/server";
import { beginjanusfaceRegistration, cerberusGate } from "@/lib/actions";
import { getClientIp } from "@/lib/utils";
import { cookies } from "next/headers";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { displayName } = (body as { displayName?: string }) ?? {};
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    // Resolve userId from cookies via CerberusGate
    const cookieStore = await cookies();
    const channelDID = cookieStore.get("channelDID")?.value;
    const recipient = cookieStore.get("authRecipient")?.value;
    const channelType = cookieStore.get("authChannelType")?.value as
      | "email"
      | "phone"
      | undefined;
    if (!channelDID || !recipient || !channelType) {
      return NextResponse.json(
        {
          error:
            "Missing authentication context. Verify OTP or complete registration first.",
        },
        { status: 401 }
      );
    }
    const gate = await cerberusGate({
      channelDID,
      channelType,
      recipient,
      ipAddress: ipAddress ?? "",
      userAgent,
    });
    if (!gate?.userId) {
      return NextResponse.json(
        { error: "Unable to resolve user. Complete user registration first." },
        { status: 400 }
      );
    }
    const data = await beginjanusfaceRegistration({
      userId: gate.userId,
      displayName,
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
    const message =
      e instanceof Error
        ? e.message
        : "Failed to process janusface registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
