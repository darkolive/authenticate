import { NextResponse } from "next/server";
import { createHash } from "crypto";
import { cerberusGate, type CerberusGateRequest } from "@/lib/actions";
import { normalizeRecipient, getClientIp } from "@/lib/utils";

export async function POST(req: Request) {
  try {
    const body = (await req.json()) as Partial<CerberusGateRequest>;

    const channelType = (body.channelType || "").toLowerCase() as CerberusGateRequest["channelType"];
    const recipientRaw = body.recipient;

    if (!channelType || !recipientRaw) {
      return NextResponse.json(
        { error: "channelType and recipient are required" },
        { status: 400 }
      );
    }

    // Best-effort headers for audit context (must be non-empty strings for GraphQL String!)
    const ipAddress = getClientIp(req) ?? "";
    const userAgent = req.headers.get("user-agent") ?? "";

    // Normalize recipient before hashing/lookup
    const recipient = normalizeRecipient(channelType, recipientRaw);
    // channelDID is required by GraphQL schema; compute if missing
    const did = body.channelDID ?? createHash("sha256").update(`${channelType}:${recipient}`).digest("hex");

    const payload = {
      channelDID: did,
      channelType,
      recipient,
      ipAddress,
      userAgent,
    } as const;

    console.debug("[api/cerberus-gate] payload", payload);

    const data = await cerberusGate(payload);

    return NextResponse.json(data);
  } catch (e: unknown) {
    const message = e instanceof Error ? e.message : "Failed to evaluate CerberusGate";
    console.error("[api/cerberus-gate] error", e);
    return NextResponse.json({ error: message }, { status: 400 });
  }
}
