import { NextResponse } from "next/server";
import { verifyOTP, type VerifyOTPRequest } from "@/lib/actions";
import { normalizeRecipient, getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as VerifyOTPRequest & { channel?: "email" | "sms" | "whatsapp" };
    if (!body?.otpCode || !body?.recipient) {
      return NextResponse.json({ error: "otpCode and recipient are required" }, { status: 400 });
    }
    // Map SMS/WhatsApp to phone for server normalization and cookies
    const chan = (body.channel || "email").toLowerCase();
    const channelType = chan === "email" ? "email" : "phone";
    const recipient = normalizeRecipient(channelType, body.recipient);
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const data = await verifyOTP({ otpCode: body.otpCode, recipient, ipAddress, userAgent });
    const res = NextResponse.json(data);
    // Set secure, HttpOnly channelDID cookie on successful OTP verification
    if (data?.verified && data?.channelDID) {
      const secure = process.env.NODE_ENV === "production";
      res.cookies.set("channelDID", data.channelDID, {
        httpOnly: true,
        secure,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15, // 15 minutes
      });
      // Also persist normalized recipient and channel type to support CerberusGate resolution server-side
      res.cookies.set("authRecipient", recipient, {
        httpOnly: true,
        secure,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15,
      });
      res.cookies.set("authChannelType", channelType, {
        httpOnly: true,
        secure,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 15,
      });
    }
    return res;
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to verify OTP";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

