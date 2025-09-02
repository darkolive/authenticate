import { NextResponse } from "next/server";
import { verifyOTP, type VerifyOTPRequest } from "@/lib/actions";
import { normalizeRecipient, getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as VerifyOTPRequest;
    if (!body?.otpCode || !body?.recipient) {
      return NextResponse.json({ error: "otpCode and recipient are required" }, { status: 400 });
    }
    const recipient = normalizeRecipient("email", body.recipient);
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const data = await verifyOTP({ otpCode: body.otpCode, recipient, ipAddress, userAgent });
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to verify OTP";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
