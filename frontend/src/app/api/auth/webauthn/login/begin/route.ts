import { NextResponse } from "next/server";
import { beginjanusfaceLogin, cerberusGate } from "@/lib/actions";
import {
  getClientIp,
  normalizeRecipient,
  maybeDecodeURIComponent,
} from "@/lib/utils";
import { cookies } from "next/headers";
import { createHash } from "crypto";

export async function POST(req: Request) {
  try {
    // Optionally accept context via body, fallback to cookies
    const body = (await req.json().catch(() => ({}))) as {
      channelDID?: string;
      channelType?: "email" | "phone";
      recipient?: string;
    };
    const cookieStore = await cookies();
    const channelType = (body.channelType ||
      cookieStore.get("authChannelType")?.value ||
      "") as "email" | "phone";
    const recipientRaw =
      body.recipient || cookieStore.get("authRecipient")?.value || "";
    const recipientDecoded = maybeDecodeURIComponent(recipientRaw);
    const recipient = normalizeRecipient(channelType, recipientDecoded);
    let channelDID =
      body.channelDID || cookieStore.get("channelDID")?.value || "";
    if (!channelDID && channelType && recipient) {
      channelDID = createHash("sha256")
        .update(`${channelType}:${recipient}`)
        .digest("hex");
    }
    if (!channelDID || !recipient || !channelType) {
      return NextResponse.json(
        { error: "Missing authentication context. Verify OTP first." },
        { status: 401 }
      );
    }
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    // Resolve userId via CerberusGate
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
      userId: gate.userId,
    });
  } catch (e: unknown) {
    const message =
      e instanceof Error ? e.message : "Failed to begin janusface login";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
