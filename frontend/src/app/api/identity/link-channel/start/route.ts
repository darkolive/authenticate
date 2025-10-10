import { NextRequest, NextResponse } from "next/server";
import { linkChannelStart } from "@/lib/actions";

export async function POST(req: NextRequest) {
  try {
    const { userId, channelType, value } = await req.json();
    if (!userId || !channelType || !value) {
      return NextResponse.json(
        { error: "userId, channelType and value are required" },
        { status: 400 }
      );
    }
    const resp = await linkChannelStart({ userId, channelType, value });
    return NextResponse.json(resp);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to start link channel";
    return NextResponse.json(
      { error: message },
      { status: 500 }
    );
  }
}
