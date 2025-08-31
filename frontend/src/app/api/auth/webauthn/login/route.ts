import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { userId, channelDID } = (body as { userId?: string; channelDID?: string }) ?? {};

    if (!userId && !channelDID) {
      return NextResponse.json(
        { error: "userId or channelDID is required" },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: "WebAuthn login is stubbed. Backend integration pending.",
      redirect: "/",
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to process WebAuthn login";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
