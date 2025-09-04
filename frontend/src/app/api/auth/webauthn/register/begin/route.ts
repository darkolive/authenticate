import { NextResponse } from "next/server";
import { beginWebAuthnRegistration, cerberusGate, registerUser } from "@/lib/actions";
import { getClientIp, normalizeRecipient, maybeDecodeURIComponent } from "@/lib/utils";
import { cookies } from "next/headers";

export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => ({}))) as { displayName?: string };

    // Resolve userId from cookies via CerberusGate
    const cookieStore = await cookies();
    const channelDID = cookieStore.get("channelDID")?.value;
    const recipientRaw = cookieStore.get("authRecipient")?.value;
    const channelType = cookieStore.get("authChannelType")?.value as "email" | "phone" | undefined;
    if (!channelDID || !recipientRaw || !channelType) {
      return NextResponse.json(
        { error: "Missing authentication context. Verify OTP or complete registration first." },
        { status: 401 }
      );
    }
    const recipientDecoded = maybeDecodeURIComponent(recipientRaw);
    const recipient = normalizeRecipient(channelType, recipientDecoded);
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";
    const gate = await cerberusGate({
      channelDID,
      channelType,
      recipient,
      ipAddress: ipAddress ?? "",
      userAgent,
    });
    let resolvedUserId = gate?.userId;
    let didAutoRegister = false;
    if (!resolvedUserId) {
      // If CerberusGate indicates this is a registration flow, lazily create the user so passkey registration can proceed.
      // This supports the passkey-first UX after OTP verification.
      if (gate?.action === "register") {
        const headers = req.headers;
        const normalizedRecipient = recipient;
        const displayNameSafe = (body.displayName ?? normalizedRecipient ?? "").trim();
        const tzResolved = (() => {
          try {
            return Intl.DateTimeFormat().resolvedOptions().timeZone || undefined;
          } catch {
            return undefined;
          }
        })();
        const timezoneSafe = tzResolved || "UTC";
        const languageSafe = (headers.get("accept-language") || "").split(",")[0]?.trim() || "en-US";

        const reg = await registerUser({
          channelDID,
          channelType,
          recipient: normalizedRecipient,
          firstName: "",
          lastName: "",
          displayName: displayNameSafe,
          timezone: timezoneSafe,
          language: languageSafe,
          ipAddress: ipAddress ?? "",
          userAgent,
        });
        if (!reg?.success || !reg?.userId) {
          return NextResponse.json(
            { error: reg?.message || "Failed to auto-register user for WebAuthn" },
            { status: 400 }
          );
        }
        resolvedUserId = reg.userId;
        didAutoRegister = true;
      } else {
        return NextResponse.json(
          { error: "Unable to resolve user. Complete user registration first." },
          { status: 400 }
        );
      }
    }
    const data = await beginWebAuthnRegistration({
      userId: resolvedUserId,
      displayName: body.displayName,
      ipAddress,
      userAgent,
    });
    const res = NextResponse.json({
      success: true,
      options: JSON.parse(data.optionsJSON),
      challenge: data.challenge,
      expiresAt: data.expiresAt,
      userId: resolvedUserId,
    });
    if (didAutoRegister) {
      // Mark that the user needs to complete onboarding before accessing dashboard
      const secure = process.env.NODE_ENV === "production";
      res.cookies.set("needs_onboarding", "true", {
        httpOnly: true,
        secure,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 60 * 24, // 1 day
      });
    }
    return res;
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to begin WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

