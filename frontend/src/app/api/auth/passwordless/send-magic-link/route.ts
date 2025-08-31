import { NextResponse } from "next/server";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({} as unknown));
    const { recipient } = (body as { recipient?: string }) ?? {};

    if (!recipient) {
      return NextResponse.json(
        { error: "recipient is required" },
        { status: 400 }
      );
    }

    return NextResponse.json({
      success: true,
      message: `Magic link sent to ${recipient}. This is a stub implementation.`,
    });
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to send magic link";
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
