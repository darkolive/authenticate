import { NextResponse } from "next/server";
import { verifyOTP, type VerifyOTPRequest } from "@/lib/actions";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as VerifyOTPRequest;
    if (!body?.otpCode || !body?.recipient) {
      return NextResponse.json({ error: "otpCode and recipient are required" }, { status: 400 });
    }
    const data = await verifyOTP(body);
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to verify OTP";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
