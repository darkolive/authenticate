// Client-side janusface helpers
// Transform server JSON options to proper PublicKeyCredential*Options
// and serialize credentials to JSON-safe payloads.

export function base64urlToBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(base64url.length / 4) * 4, "=");
  if (typeof atob !== "function")
    throw new Error("atob is not available in this environment");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++)
    binary += String.fromCharCode(bytes[i]);
  if (typeof btoa !== "function")
    throw new Error("btoa is not available in this environment");
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

type DescriptorLike = {
  type: PublicKeyCredentialType;
  id: string | ArrayBuffer;
  transports?: AuthenticatorTransport[];
};

type CreationOptionsFromServer = Omit<
  PublicKeyCredentialCreationOptions,
  "challenge" | "user" | "excludeCredentials"
> & {
  challenge: string | ArrayBuffer;
  user: { id: string | ArrayBuffer; name: string; displayName: string };
  excludeCredentials?: DescriptorLike[];
};

export function decodeCreationOptionsFromServer(
  options: CreationOptionsFromServer
): PublicKeyCredentialCreationOptions {
  const o: CreationOptionsFromServer = structuredClone(options);
  const out: PublicKeyCredentialCreationOptions = {
    ...o,
    challenge:
      typeof o.challenge === "string"
        ? base64urlToBuffer(o.challenge)
        : o.challenge,
    user: {
      ...o.user,
      id:
        typeof o.user.id === "string"
          ? base64urlToBuffer(o.user.id)
          : o.user.id,
    },
    excludeCredentials: Array.isArray(o.excludeCredentials)
      ? o.excludeCredentials.map((c) => ({
          ...c,
          id: typeof c.id === "string" ? base64urlToBuffer(c.id) : c.id,
        }))
      : undefined,
  } as PublicKeyCredentialCreationOptions;
  return out;
}

type RequestOptionsFromServer = Omit<
  PublicKeyCredentialRequestOptions,
  "challenge" | "allowCredentials"
> & {
  challenge: string | ArrayBuffer;
  allowCredentials?: DescriptorLike[];
};

export function decodeRequestOptionsFromServer(
  options: RequestOptionsFromServer
): PublicKeyCredentialRequestOptions {
  const o: RequestOptionsFromServer = structuredClone(options);
  const out: PublicKeyCredentialRequestOptions = {
    ...o,
    challenge:
      typeof o.challenge === "string"
        ? base64urlToBuffer(o.challenge)
        : o.challenge,
    allowCredentials: Array.isArray(o.allowCredentials)
      ? o.allowCredentials.map((c) => ({
          ...c,
          id: typeof c.id === "string" ? base64urlToBuffer(c.id) : c.id,
        }))
      : undefined,
  } as PublicKeyCredentialRequestOptions;
  return out;
}

export type SerializedPublicKeyCredential = {
  id: string;
  type: PublicKeyCredentialType;
  rawId: string; // base64url
  clientExtensionResults: AuthenticationExtensionsClientOutputs;
  attestationObject?: string;
  clientDataJSON?: string;
  authenticatorData?: string;
  signature?: string;
  userHandle?: string;
  transports?: string[];
};

type AttestationWithTransports = AuthenticatorAttestationResponse & {
  getTransports?: () => string[];
};

export function serializePublicKeyCredential(
  cred: PublicKeyCredential
): SerializedPublicKeyCredential {
  const result: SerializedPublicKeyCredential = {
    id: cred.id,
    type: cred.type as PublicKeyCredentialType,
    rawId: bufferToBase64url(cred.rawId),
    clientExtensionResults: cred.getClientExtensionResults(),
  };
  const resp = cred.response as
    | AuthenticatorAttestationResponse
    | AuthenticatorAssertionResponse;
  // Attestation
  if ("attestationObject" in resp) {
    result.attestationObject = bufferToBase64url(
      (resp as AuthenticatorAttestationResponse).attestationObject
    );
    result.clientDataJSON = bufferToBase64url(resp.clientDataJSON);
    const tr = (resp as AttestationWithTransports).getTransports?.();
    if (Array.isArray(tr)) result.transports = tr;
  }
  // Assertion
  if ("authenticatorData" in resp) {
    result.authenticatorData = bufferToBase64url(
      (resp as AuthenticatorAssertionResponse).authenticatorData
    );
    result.signature = bufferToBase64url(
      (resp as AuthenticatorAssertionResponse).signature
    );
    if ((resp as AuthenticatorAssertionResponse).userHandle) {
      result.userHandle = bufferToBase64url(
        (resp as AuthenticatorAssertionResponse).userHandle as ArrayBuffer
      );
    }
    result.clientDataJSON = bufferToBase64url(resp.clientDataJSON);
  }
  return result;
}
