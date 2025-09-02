import { NextResponse } from "next/server";
import { registerUser, type UserRegistrationRequest } from "@/lib/actions";
import { normalizeRecipient, getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const headers = req.headers;
    const body = (await req.json()) as UserRegistrationRequest;

    if (!body?.channelDID || !body?.recipient || !body?.channelType) {
      return NextResponse.json(
        { error: "channelDID, channelType and recipient are required" },
        { status: 400 }
      );
    }

    const ipAddress = getClientIp(req) ?? "";
    const userAgent = headers.get("user-agent") ?? "";

    // Ensure displayName is non-null for GraphQL (String!)
    const fallbackDisplay = [
      (body as { firstName?: string }).firstName,
      (body as { lastName?: string }).lastName,
    ]
      .filter(Boolean)
      .join(" ")
      .trim();
    const displayNameSafe = (body as { displayName?: string }).displayName ?? fallbackDisplay ?? body.recipient ?? "";

    // Ensure timezone and language are non-null (String!)
    const tzFromBody = (body as { timezone?: string }).timezone;
    const tzResolved = (() => {
      try {
        return Intl.DateTimeFormat().resolvedOptions().timeZone || undefined;
      } catch {
        return undefined;
      }
    })();
    const timezoneSafe = (tzFromBody && tzFromBody.trim()) || tzResolved || "UTC";

    const langFromBody = (body as { language?: string }).language;
    const langFromHeader = headers.get("accept-language") || "";
    const langParsed = langFromHeader.split(",")[0]?.trim();
    const languageSafe = (langFromBody && langFromBody.trim()) || langParsed || "en-US";

    const channelType = (body.channelType || "").toLowerCase() as UserRegistrationRequest["channelType"];
    const recipient = normalizeRecipient(channelType, body.recipient);

    const payload: UserRegistrationRequest = {
      channelDID: body.channelDID,
      channelType,
      recipient,
      firstName: body.firstName,
      lastName: body.lastName,
      displayName: displayNameSafe,
      timezone: timezoneSafe,
      language: languageSafe,
      ipAddress,
      userAgent,
    };

    // Debug: ensure we're not sending unexpected fields like metadata
    console.debug("[api/register] payload", payload);

    const data = await registerUser(payload);
    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to register user";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
