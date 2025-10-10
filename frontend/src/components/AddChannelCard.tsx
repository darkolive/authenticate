"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

type ChannelType = "email" | "sms" | "whatsapp";

export default function AddChannelCard({ userId }: { userId: string }) {
  const router = useRouter();
  const [channelType, setChannelType] = useState<ChannelType>("email");
  const [value, setValue] = useState("");
  const [otpCode, setOtpCode] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [step, setStep] = useState<"start" | "confirm">("start");
  const [maskedDest, setMaskedDest] = useState<string>("");
  const [expiresAt, setExpiresAt] = useState<string>("");
  const [secondsLeft, setSecondsLeft] = useState<number>(0);
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  const canStart = useMemo(() => userId && channelType && value.trim().length > 0, [userId, channelType, value]);
  const canConfirm = useMemo(() => step === "confirm" && otpCode.trim().length >= 4, [step, otpCode]);

  useEffect(() => {
    if (!expiresAt) return;
    const end = new Date(expiresAt).getTime();
    const tick = () => {
      const now = Date.now();
      const left = Math.max(0, Math.floor((end - now) / 1000));
      setSecondsLeft(left);
      if (left <= 0 && timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
    tick();
    timerRef.current = setInterval(tick, 1000);
    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
      timerRef.current = null;
    };
  }, [expiresAt]);

  async function handleStart(e: React.FormEvent) {
    e.preventDefault();
    if (!canStart) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/identity/link-channel/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, channelType, value }),
      });
      const json = await res.json();
      if (!res.ok || json.error || json.success === false) {
        throw new Error(json.error || json.message || res.statusText);
      }
      setMaskedDest(json.destination || "");
      setExpiresAt(json.expiresAt || "");
      setStep("confirm");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to start link";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  async function handleConfirm(e: React.FormEvent) {
    e.preventDefault();
    if (!canConfirm) return;
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/identity/link-channel/confirm", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, channelType, value, otpCode }),
      });
      const json = await res.json();
      if (!res.ok || json.error || json.success === false) {
        throw new Error(json.error || json.message || res.statusText);
      }
      // Success: refresh linked channels (server components)
      router.refresh();
      // Reset form
      setStep("start");
      setOtpCode("");
      setValue("");
      setMaskedDest("");
      setExpiresAt("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to confirm link";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="p-4">
      <h2 className="text-lg font-medium">Add channel</h2>
      <p className="mt-1 text-sm text-gray-500">Link an additional email, phone (SMS), or WhatsApp to your account.</p>

      <form className="mt-4 space-y-3" onSubmit={step === "start" ? handleStart : handleConfirm}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <div>
            <Label htmlFor="channelType">Channel</Label>
            <select
              id="channelType"
              className="mt-1 w-full rounded-md border px-2 py-2 text-sm"
              value={channelType}
              onChange={(e) => setChannelType(e.target.value as ChannelType)}
              disabled={step === "confirm" || loading}
            >
              <option value="email">Email</option>
              <option value="sms">SMS</option>
              <option value="whatsapp">WhatsApp</option>
            </select>
          </div>
          <div className="sm:col-span-2">
            <Label htmlFor="value">{channelType === "email" ? "Email address" : "Phone number"}</Label>
            <Input
              id="value"
              type="text"
              placeholder={channelType === "email" ? "user@example.com" : "+1 555 555 0100"}
              value={value}
              onChange={(e) => setValue(e.target.value)}
              disabled={step === "confirm" || loading}
            />
          </div>
        </div>

        {step === "confirm" && (
          <div className="rounded-md bg-gray-50 p-3 text-sm">
            <div>We sent a code to: <span className="font-medium">{maskedDest || "(destination)"}</span></div>
            <div className="mt-1 text-xs text-gray-600">Expires in: {secondsLeft}s</div>
            <div className="mt-3">
              <Label htmlFor="otp">Verification code</Label>
              <Input
                id="otp"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={6}
                placeholder="123456"
                value={otpCode}
                onChange={(e) => setOtpCode(e.target.value)}
                disabled={loading}
              />
            </div>
          </div>
        )}

        {error && <div className="text-sm text-red-600">{error}</div>}

        <div className="flex items-center gap-2">
          {step === "start" ? (
            <Button type="submit" disabled={!canStart || loading}>
              {loading ? "Sending..." : "Send code"}
            </Button>
          ) : (
            <>
              <Button type="submit" disabled={!canConfirm || loading}>
                {loading ? "Verifying..." : "Verify & Link"}
              </Button>
              <Button
                type="button"
                variant="secondary"
                disabled={loading}
                onClick={() => {
                  setStep("start");
                  setOtpCode("");
                  setMaskedDest("");
                  setExpiresAt("");
                }}
              >
                Start over
              </Button>
            </>
          )}
        </div>
      </form>
    </Card>
  );
}
