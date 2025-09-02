import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Normalize an email address for consistent hashing and comparisons
export function normalizeEmail(value: string): string {
  return (value || "").trim().toLowerCase();
}

// Normalize a recipient based on channel type. For email, lowercase; for others, trim.
export function normalizeRecipient(channelType: string, recipient: string): string {
  if (!recipient) return "";
  if ((channelType || "").toLowerCase() === "email") {
    return normalizeEmail(recipient);
  }
  return recipient.trim();
}

// Extract client IP from a Next.js Request headers in a proxy-friendly way
export function getClientIp(req: Request): string {
  try {
    const h = req.headers;
    const xff = h.get("x-forwarded-for");
    if (xff) {
      const first = xff.split(",")[0]?.trim();
      if (first) return first;
    }
    return (
      h.get("x-real-ip") ??
      h.get("cf-connecting-ip") ??
      h.get("true-client-ip") ??
      ""
    );
  } catch {
    return "";
  }
}
