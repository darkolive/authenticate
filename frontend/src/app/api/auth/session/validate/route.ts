import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { validateSession } from "@/lib/actions";

export async function GET() {
  try {
    const cookieStore = await cookies();
    let token = cookieStore.get("__Host-hm_session")?.value;
    if (!token && process.env.NODE_ENV !== "production") {
      token = cookieStore.get("hm_session")?.value;
    }
    if (!token) {
      return NextResponse.json(
        { valid: false, message: "missing session token" },
        { status: 401 }
      );
    }
    const data = await validateSession(token);
    const status = data.valid ? 200 : 401;
    return NextResponse.json({ ...data }, { status });
  } catch (e: unknown) {
    const message =
      e instanceof Error ? e.message : "Failed to validate session";
    return NextResponse.json({ valid: false, message }, { status: 400 });
  }
}
