"use client";

import React from "react";
import { useRouter } from "next/navigation";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { toast } from "sonner";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { decodeRequestOptionsFromServer, decodeCreationOptionsFromServer, serializePublicKeyCredential } from "@/lib/webauthn";
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp";

// Local types for API responses
type VerifyResp = {
  verified: boolean;
  message: string;
  userId?: string;
  action?: "signin" | "register";
  channelDID?: string;
};

type CerberusResp = {
  userExists: boolean;
  action: "signin" | "register";
  userId?: string;
  availableMethods: string[];
  nextStep: string;
  message?: string;
};

type RegisterResp = {
  success: boolean;
  userId: string;
  message: string;
};

type ErrorResp = { error: string };

function isErrorResp(v: unknown): v is ErrorResp {
  if (!v || typeof v !== "object" || !("error" in v)) return false;
  const { error } = v as { error?: unknown };
  return typeof error === "string";
}

const emailSchema = z.object({
  email: z.string().email(),
});

const otpSchema = z.object({
  code: z.string().min(6, "Enter the 6-digit code").max(6),
});

const registerSchema = z.object({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  displayName: z.string().optional(),
});

type Step = "email" | "otp" | "signin" | "register" | "success";

export default function SignInPage() {
  const router = useRouter();
  const [step, setStep] = React.useState<Step>("email");
  const [email, setEmail] = React.useState("");
  const [channelDID, setChannelDID] = React.useState<string | undefined>(undefined);
  const [userId, setUserId] = React.useState<string | undefined>(undefined);
  const [webauthnLoading, setWebauthnLoading] = React.useState(false);
  const [magicLoading, setMagicLoading] = React.useState(false);

  // Email form
  const emailForm = useForm<z.infer<typeof emailSchema>>({
    resolver: zodResolver(emailSchema),
    defaultValues: { email: "" },
    mode: "onSubmit",
  });

  // OTP form
  const otpForm = useForm<z.infer<typeof otpSchema>>({
    resolver: zodResolver(otpSchema),
    defaultValues: { code: "" },
    mode: "onSubmit",
  });

  // Register form
  const regForm = useForm<z.infer<typeof registerSchema>>({
    resolver: zodResolver(registerSchema),
    defaultValues: { firstName: "", lastName: "", displayName: "" },
    mode: "onSubmit",
  });

  // --- WebAuthn flows ---
  async function performWebAuthnLoginFlow(): Promise<boolean> {
    // Begin login
    const beginRes = await fetch("/api/auth/webauthn/login/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({}),
    });
    const begin = await beginRes.json();
    if (!beginRes.ok) throw new Error(begin?.error || "Unable to start passkey login");
    const publicKey = decodeRequestOptionsFromServer(begin.options);

    // Get assertion
    const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
    if (!cred) throw new Error("No credential returned");
    const credentialJSON = JSON.stringify(serializePublicKeyCredential(cred));

    // Finish login
    const finishRes = await fetch("/api/auth/webauthn/login/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: begin.challenge, credentialJSON, userId: begin.userId }),
    });
    const finish = await finishRes.json();
    if (!finishRes.ok || !finish?.success) throw new Error(finish?.error || finish?.message || "Passkey verification failed");
    return true;
  }

  async function performWebAuthnRegisterFlow(displayName?: string): Promise<boolean> {
    // Begin registration (server will auto-register user if needed)
    const beginRes = await fetch("/api/auth/webauthn/register/begin", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ displayName }),
    });
    const begin = await beginRes.json();
    if (!beginRes.ok) throw new Error(begin?.error || "Unable to start passkey registration");
    const publicKey = decodeCreationOptionsFromServer(begin.options);

    // Create credential
    const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
    if (!cred) throw new Error("No credential returned");
    const credentialJSON = JSON.stringify(serializePublicKeyCredential(cred));

    // Finish registration
    const finishRes = await fetch("/api/auth/webauthn/register/finish", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challenge: begin.challenge, credentialJSON, userId: begin.userId }),
    });
    const finish = await finishRes.json();
    if (!finishRes.ok || !finish?.success) throw new Error(finish?.error || finish?.message || "Passkey registration failed");
    return true;
  }

  async function attemptPasskeyFlow(action: "signin" | "register", displayName?: string) {
    try {
      setWebauthnLoading(true);
      if (action === "signin") {
        try {
          const ok = await performWebAuthnLoginFlow();
          if (ok) {
            toast.success("Signed in with passkey");
            router.push("/dashboard");
            return;
          }
        } catch (e) {
          // If login fails (no credential or cancelled), try registration as fallback
          const errMsg = e instanceof Error ? e.message : String(e);
          console.warn("[webauthn] login failed, falling back to registration", errMsg);
        }
      }

      // Registration path (either action === 'register' or login fallback)
      const registered = await performWebAuthnRegisterFlow(displayName);
      if (registered) {
        toast.success("Passkey added to your account");
        // After creating a new passkey (usually for new users), send them to onboarding to complete profile details.
        router.push("/onboarding");
        return;
      }
      throw new Error("Passkey flow did not complete");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to complete biometric flow";
      toast.error(msg);
    } finally {
      setWebauthnLoading(false);
    }
  }

  async function onSendOTP(values: z.infer<typeof emailSchema>) {
    try {
      const res = await fetch("/api/auth/send-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ channel: "email", recipient: values.email }),
      });
      if (!res.ok) throw new Error((await res.json()).error || "Failed to send OTP");
      toast.success("OTP sent. Check your inbox.");
      setEmail(values.email);
      setStep("otp");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to send OTP";
      toast.error(msg);
    }
  }

  async function onCreatePasskey() {
    try {
      setWebauthnLoading(true);
      await attemptPasskeyFlow("register");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to create passkey";
      toast.error(msg);
    } finally {
      setWebauthnLoading(false);
    }
  }

  async function onVerifyOTP(values: z.infer<typeof otpSchema>) {
    try {
      const res = await fetch("/api/auth/verify-otp", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ otpCode: values.code, recipient: email }),
      });
      const data = (await res.json()) as VerifyResp | ErrorResp;
      if (!res.ok || isErrorResp(data)) throw new Error(isErrorResp(data) ? data.error : "Verification failed");

      toast.success((data as VerifyResp).message || "Verified");
      const v = data as VerifyResp;
      setChannelDID(v.channelDID);
      setUserId(v.userId);

      // Call CerberusGate to determine the next step (per backend/agents/auth/CerberusMFA/readme.md)
      const cerbRes = await fetch("/api/auth/cerberus-gate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          channelDID: v.channelDID,
          channelType: "email",
          recipient: email,
        }),
      });
      const cerb = (await cerbRes.json()) as CerberusResp | ErrorResp;
      if (!cerbRes.ok || isErrorResp(cerb)) {
        throw new Error(isErrorResp(cerb) ? cerb.error : "Cerberus evaluation failed");
      }
      const c = cerb as CerberusResp;
      if (c.userId) setUserId(c.userId);
      if (c.message) toast.message(c.message);
      // Immediately attempt biometric flow based on Cerberus decision
      await attemptPasskeyFlow(c.action);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to verify";
      toast.error(msg);
    }
  }

  async function onRegister(values: z.infer<typeof registerSchema>) {
    try {
      if (!channelDID) throw new Error("Missing channelDID from verification");
      const payload = {
        channelDID,
        channelType: "email" as const,
        recipient: email,
        firstName: values.firstName,
        lastName: values.lastName,
        displayName: values.displayName,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: typeof navigator !== "undefined" ? navigator.language : undefined,
      };
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = (await res.json()) as RegisterResp | ErrorResp;
      if (!res.ok || isErrorResp(data)) throw new Error(isErrorResp(data) ? data.error : "Registration failed");
      const r = data as RegisterResp;
      setUserId(r.userId);
      toast.success("Registration complete");
      setStep("success");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to register";
      toast.error(msg);
    }
  }

  async function onPasskeySignIn() {
    try {
      setWebauthnLoading(true);
      await attemptPasskeyFlow("signin");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to sign in";
      toast.error(msg);
    } finally {
      setWebauthnLoading(false);
    }
  }

  async function onMagicLink() {
    try {
      setMagicLoading(true);
      const res = await fetch("/api/auth/passwordless/send-magic-link", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ recipient: email }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data?.error || "Failed to send magic link");
      toast.success(data?.message || "Magic link sent (stub)");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to send magic link";
      toast.error(msg);
    } finally {
      setMagicLoading(false);
    }
  }

  function SignInStubs() {
    return (
      <div className="grid gap-4">
        <Button type="button" onClick={onPasskeySignIn} className="w-full" disabled={webauthnLoading}>
          {webauthnLoading ? "Signing in..." : "Sign in with Passkey (WebAuthn)"}
        </Button>
        <Button
          type="button"
          variant="secondary"
          onClick={onMagicLink}
          className="w-full"
          disabled={magicLoading}
        >
          {magicLoading ? "Sending..." : "Use passwordless fallback"}
        </Button>
      </div>
    );
  }

  return (
    <div className="container mx-auto max-w-md py-10">
      <Card>
        <CardHeader>
          <CardTitle>Authenticate</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {step === "email" && (
            <Form {...emailForm}>
              <form onSubmit={emailForm.handleSubmit(onSendOTP)} className="space-y-4">
                <FormField
                  control={emailForm.control}
                  name="email"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Email</FormLabel>
                      <FormControl>
                        <Input type="email" placeholder="you@example.com" {...field} />
                      </FormControl>
                      <FormDescription>We&apos;ll send a one-time code to this address.</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <Button type="submit" className="w-full" disabled={emailForm.formState.isSubmitting}>
                  {emailForm.formState.isSubmitting ? "Sending..." : "Send OTP"}
                </Button>
              </form>
            </Form>
          )}

          {step === "otp" && (
            <Form {...otpForm}>
              <form onSubmit={otpForm.handleSubmit(onVerifyOTP)} className="space-y-4">
                <FormField
                  control={otpForm.control}
                  name="code"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Enter 6-digit code</FormLabel>
                      <FormControl>
                        <InputOTP maxLength={6} value={field.value} onChange={field.onChange}>
                          <InputOTPGroup>
                            <InputOTPSlot index={0} />
                            <InputOTPSlot index={1} />
                            <InputOTPSlot index={2} />
                          </InputOTPGroup>
                          <InputOTPSeparator />
                          <InputOTPGroup>
                            <InputOTPSlot index={3} />
                            <InputOTPSlot index={4} />
                            <InputOTPSlot index={5} />
                          </InputOTPGroup>
                        </InputOTP>
                      </FormControl>
                      <FormDescription>
                        We sent a code to {email}. It expires soon.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <div className="flex gap-2">
                  <Button type="submit" className="flex-1" disabled={otpForm.formState.isSubmitting}>
                    {otpForm.formState.isSubmitting ? "Verifying..." : "Verify"}
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => setStep("email")}
                  >
                    Change email
                  </Button>
                </div>
              </form>
            </Form>
          )}

          {step === "signin" && (
            <div className="space-y-4">
              <p className="text-sm text-muted-foreground">User found. Continue with sign-in.</p>
              <SignInStubs />
            </div>
          )}

          {step === "register" && (
            <Form {...regForm}>
              <form onSubmit={regForm.handleSubmit(onRegister)} className="space-y-4">
                <div className="grid grid-cols-1 gap-4">
                  <FormField
                    control={regForm.control}
                    name="firstName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>First name</FormLabel>
                        <FormControl>
                          <Input placeholder="Jane" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={regForm.control}
                    name="lastName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Last name</FormLabel>
                        <FormControl>
                          <Input placeholder="Doe" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                  <FormField
                    control={regForm.control}
                    name="displayName"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Display name (optional)</FormLabel>
                        <FormControl>
                          <Input placeholder="Jane D." {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
                <Button type="submit" className="w-full" disabled={regForm.formState.isSubmitting}>
                  {regForm.formState.isSubmitting ? "Registering..." : "Complete registration"}
                </Button>
              </form>
            </Form>
          )}

          {step === "success" && (
            <div className="space-y-4">
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">Success.</p>
                <p className="text-sm">User ID: {userId}</p>
              </div>
              <Button type="button" onClick={onCreatePasskey} disabled={webauthnLoading} className="w-full">
                {webauthnLoading ? "Working..." : "Add a Passkey (Recommended)"}
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
