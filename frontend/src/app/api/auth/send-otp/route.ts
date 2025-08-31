import { NextResponse } from "next/server";
import { sendOTP, type OTPRequest } from "@/lib/actions";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as OTPRequest;
    // Force channel to email unless specified
    const payload: OTPRequest = {
      channel: body.channel ?? "email",
      recipient: body.recipient,
    };
    const data = await sendOTP(payload);
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to send OTP";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
