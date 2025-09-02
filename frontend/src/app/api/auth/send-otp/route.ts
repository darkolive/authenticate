import { NextResponse } from "next/server";
import { sendOTP, type OTPRequest } from "@/lib/actions";
import { normalizeRecipient, getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as OTPRequest;
    // Force channel to email unless specified
    const channel = body.channel ?? "email";
    if (!body.recipient) {
      return NextResponse.json({ error: "recipient is required" }, { status: 400 });
    }
    const recipient = normalizeRecipient(channel, body.recipient);
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const payload: OTPRequest = { channel, recipient, ipAddress, userAgent };
    const data = await sendOTP(payload);
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to send OTP";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
