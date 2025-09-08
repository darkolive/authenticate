import { NextResponse } from "next/server";
import { beginjanusfaceLogin, cerberusGate } from "@/lib/actions";
import {
  getClientIp,
  normalizeRecipient,
  maybeDecodeURIComponent,
} from "@/lib/utils";
import { cookies } from "next/headers";

export async function POST(req: Request) {
  try {
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    // Resolve userId from cookies via CerberusGate
    const cookieStore = await cookies();
    const channelDID = cookieStore.get("channelDID")?.value;
    const recipientRaw = cookieStore.get("authRecipient")?.value;
    const channelType = cookieStore.get("authChannelType")?.value as
      | "email"
      | "phone"
      | undefined;
    if (!channelDID || !recipientRaw || !channelType) {
      return NextResponse.json(
        { error: "Missing authentication context. Verify OTP first." },
        { status: 401 }
      );
    }
    const recipientDecoded = maybeDecodeURIComponent(recipientRaw);
    const recipient = normalizeRecipient(channelType, recipientDecoded);
    const gate = await cerberusGate({
      channelDID,
      channelType,
      recipient,
      ipAddress: ipAddress ?? "",
      userAgent,
    });
    if (!gate?.userId) {
      return NextResponse.json(
        { error: "Unable to resolve userId from authentication context" },
        { status: 400 }
      );
    }
    const data = await beginjanusfaceLogin({
      userId: gate.userId,
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
      e instanceof Error ? e.message : "Failed to process janusface login";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
