import { NextResponse } from "next/server";
import { finishWebAuthnRegistration, cerberusGate } from "@/lib/actions";
import { getClientIp, normalizeRecipient, maybeDecodeURIComponent } from "@/lib/utils";
import { cookies } from "next/headers";
import { createHash } from "crypto";

export async function POST(req: Request) {
  try {
    const body = (await req.json().catch(() => ({}))) as {
      challenge?: string;
      credentialJSON?: string;
      credential?: unknown;
      userId?: string;
      channelDID?: string;
      channelType?: "email" | "phone";
      recipient?: string;
    };
    const { challenge } = body;
    if (!challenge) {
      return NextResponse.json(
        { error: "challenge is required" },
        { status: 400 }
      );
    }
    const credentialJSON =
      typeof body.credentialJSON === "string"
        ? body.credentialJSON
        : JSON.stringify(body.credential ?? {});
    const ipAddress = getClientIp(req);
    const userAgent = req.headers.get("user-agent") ?? "";

    // Resolve userId from explicit body or via CerberusGate using cookies/body context
    let resolvedUserId = body.userId;
    if (!resolvedUserId) {
      const cookieStore = await cookies();
      const channelType = (body.channelType || cookieStore.get("authChannelType")?.value || "") as
        | "email"
        | "phone";
      const recipientRaw = body.recipient || cookieStore.get("authRecipient")?.value || "";
      const recipientDecoded = maybeDecodeURIComponent(recipientRaw);
      const recipient = normalizeRecipient(channelType, recipientDecoded);
      let channelDID = body.channelDID || cookieStore.get("channelDID")?.value || "";
      if (!channelDID && channelType && recipient) {
        channelDID = createHash("sha256").update(`${channelType}:${recipient}`).digest("hex");
      }
      if (!channelDID || !recipient || !channelType) {
        return NextResponse.json(
          { error: "Missing authentication context. Verify OTP or complete registration first." },
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
          { error: "Unable to resolve userId from authentication context" },
          { status: 400 }
        );
      }
      resolvedUserId = gate.userId;
    }
    const data = await finishWebAuthnRegistration({
      userId: resolvedUserId,
      challenge,
      credentialJSON,
      ipAddress,
      userAgent,
    });
    const res = NextResponse.json(data);
    if (data?.success && data.sessionToken) {
      const cookieOptions = {
        httpOnly: true,
        secure: true,
        sameSite: "lax" as const,
        path: "/",
        expires: undefined as Date | undefined,
      };
      if (data.sessionExpiresAt) {
        const exp = new Date(data.sessionExpiresAt);
        if (!isNaN(exp.getTime())) {
          cookieOptions.expires = exp;
        }
      }
      res.cookies.set("__Host-hm_session", data.sessionToken, cookieOptions);
      // Dev-only fallback: also set a non-Host cookie over HTTP for local testing
      if (process.env.NODE_ENV !== "production") {
        res.cookies.set("hm_session", data.sessionToken, {
          httpOnly: true,
          secure: false,
          sameSite: "lax",
          path: "/",
          ...(cookieOptions.expires ? { expires: cookieOptions.expires } : {}),
        });
      }
    }
    return res;
  } catch (e: unknown) {
    const message =
      e instanceof Error ? e.message : "Failed to finish WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}

