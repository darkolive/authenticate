import { NextRequest, NextResponse } from "next/server";
import { linkChannelConfirm } from "@/lib/actions";

export async function POST(req: NextRequest) {
  try {
    const { userId, channelType, value, otpCode } = await req.json();
    if (!userId || !channelType || !value || !otpCode) {
      return NextResponse.json(
        { error: "userId, channelType, value and otpCode are required" },
        { status: 400 }
      );
    }
    const resp = await linkChannelConfirm({ userId, channelType, value, otpCode });
    return NextResponse.json(resp);
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Failed to confirm link channel";
    return NextResponse.json(
      { error: message },
      { status: 500 }
    );
  }
}
