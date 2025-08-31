import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { channelDID, displayName } = (body as {
      channelDID?: string;
      displayName?: string;
    }) ?? {};

    if (!channelDID) {
      return NextResponse.json(
        { error: "channelDID is required" },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `WebAuthn register is stubbed${displayName ? ` for ${displayName}` : ""}. Backend integration pending.`,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process WebAuthn registration";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
