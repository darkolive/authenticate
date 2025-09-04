import { NextRequest, NextResponse } from "next/server";

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  // Protect /dashboard and /onboarding (extend this list as needed)
  if (pathname.startsWith("/dashboard") || pathname.startsWith("/onboarding")) {
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
        const data = (await res.json()) as { valid?: boolean; profileComplete?: boolean };
        if (data?.valid) {
          // Server-side gating based on profile completeness
          if (pathname.startsWith("/dashboard")) {
            if (data.profileComplete === false) {
              const url = req.nextUrl.clone();
              url.pathname = "/onboarding";
              url.search = "";
              return NextResponse.redirect(url);
            }
            // Fallback: if profile completeness is unknown, honor legacy cookie for now
            if (typeof data.profileComplete === "undefined") {
              const needs = req.cookies.get("needs_onboarding")?.value;
              if (needs === "true") {
                const url = req.nextUrl.clone();
                url.pathname = "/onboarding";
                url.search = "";
                return NextResponse.redirect(url);
              }
            }
          }
          if (pathname.startsWith("/onboarding")) {
            if (data.profileComplete === true) {
              const url = req.nextUrl.clone();
              url.pathname = "/dashboard";
              url.search = "";
              return NextResponse.redirect(url);
            }
            // Fallback: if unknown, and cookie not set to true, allow dashboard
            if (typeof data.profileComplete === "undefined") {
              const needs = req.cookies.get("needs_onboarding")?.value;
              if (needs !== "true") {
                const url = req.nextUrl.clone();
                url.pathname = "/dashboard";
                url.search = "";
                return NextResponse.redirect(url);
              }
            }
          }
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
  matcher: ["/dashboard", "/onboarding"],
};
