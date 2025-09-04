import { NextResponse } from "next/server";

async function signout(req: Request) {
  const url = new URL(req.url);
  const redirectTo = url.searchParams.get("redirect");
  const res = redirectTo
    ? NextResponse.redirect(new URL(redirectTo, url))
    : NextResponse.json({ success: true });

  res.cookies.set("__Host-hm_session", "", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    expires: new Date(0),
  });

  // Clear dev-only fallback cookie as well (if present)
  res.cookies.set("hm_session", "", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
    path: "/",
    expires: new Date(0),
  });

  return res;
}

export async function GET(req: Request) {
  return signout(req);
}

export async function POST(req: Request) {
  return signout(req);
}
