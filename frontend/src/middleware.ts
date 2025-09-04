import { NextRequest, NextResponse } from "next/server";

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Only protect /dashboard (extend this list as needed)
  if (pathname.startsWith("/dashboard")) {
    let token = req.cookies.get("__Host-hm_session")?.value;
    // Dev fallback: allow non-Host cookie for local HTTP testing
    if (!token && process.env.NODE_ENV !== "production") {
      token = req.cookies.get("hm_session")?.value;
    }
    if (!token) {
      const url = req.nextUrl.clone();
      url.pathname = "/signin";
      url.search = "";
      return NextResponse.redirect(url);
    }

    try {
      // Validate the session via our API route, forwarding cookies
      const res = await fetch(new URL("/api/auth/session/validate", req.nextUrl.origin), {
        method: "GET",
        headers: {
          cookie: req.headers.get("cookie") || "",
        },
        cache: "no-store",
      });

      if (res.ok) {
        const data = (await res.json()) as { valid?: boolean };
        if (data?.valid) {
          return NextResponse.next();
        }
      }

      const url = req.nextUrl.clone();
      url.pathname = "/signin";
      url.search = "";
      return NextResponse.redirect(url);
    } catch {
      const url = req.nextUrl.clone();
      url.pathname = "/signin";
      url.search = "";
      return NextResponse.redirect(url);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/dashboard"],
};
