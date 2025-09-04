"use server";
import "server-only";

// Centralized GraphQL client for Modus backend
// Reads server-only environment variables
const GRAPHQL_URL = process.env.BACKEND_GRAPHQL_URL;
const MODUS_API_KEY = process.env.MODUS_API_KEY;

if (!GRAPHQL_URL) {
  console.warn("[actions] BACKEND_GRAPHQL_URL is not set. Set it in .env.local");
}
if (!MODUS_API_KEY) {
  console.warn("[actions] MODUS_API_KEY is not set. Set it in .env.local");
}

export type OTPRequest = {
  channel: "email" | "sms" | "whatsapp" | "telegram";
  recipient: string;
  ipAddress?: string;
  userAgent?: string;
};

export type OTPResponse = {
  otpId: string;
  sent: boolean;
  verified: boolean;
  channel: string;
  expiresAt: string;
  message?: string;
};

export type VerifyOTPRequest = {
  otpCode: string;
  recipient: string;
  ipAddress?: string;
  userAgent?: string;
};

export type VerifyOTPResponse = {
  verified: boolean;
  message: string;
  userId?: string;
  action?: "signin" | "register";
  channelDID?: string;
};

export type CerberusGateRequest = {
  channelDID?: string;
  channelType: "email" | "phone";
  recipient: string;
  ipAddress: string;
  userAgent: string;
};

export type CerberusGateResponse = {
  userExists: boolean;
  action: "signin" | "register";
  userId?: string;
  availableMethods: string[];
  nextStep: string;
  message?: string;
  auditEventId?: string;
};

export type UserRegistrationRequest = {
  channelDID: string;
  channelType: "email" | "phone";
  recipient: string;
  firstName: string;
  lastName: string;
  displayName?: string;
  timezone?: string;
  language?: string;
  ipAddress?: string;
  userAgent?: string;
};

export type UserRegistrationResponse = {
  success: boolean;
  userId: string;
  message: string;
  piiTokens?: { key: string; value: string }[];
  identityCheckId?: string;
  auditEventId?: string;
  createdAt: string;
};

async function fetchGraphQL<T>(query: string, variables?: Record<string, unknown>): Promise<T> {
  if (!GRAPHQL_URL) {
    throw new Error("GraphQL environment not configured. Set BACKEND_GRAPHQL_URL");
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (MODUS_API_KEY) {
    headers.Authorization = `Bearer ${MODUS_API_KEY}`;
  }
  const res = await fetch(GRAPHQL_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
    cache: "no-store",
  });
  const json = await res.json();
  if (!res.ok || json.errors) {
    const err = json.errors?.[0]?.message || res.statusText;
    throw new Error(err);
  }
  return json.data as T;
}

export async function sendOTP(req: OTPRequest): Promise<OTPResponse> {
  const query = /* GraphQL */ `
    query SendOTP($channel: String!, $recipient: String!) {
      sendOTP(req: { channel: $channel, recipient: $recipient }) {
        otpId: oTPID
        sent
        verified
        channel
        expiresAt
        message
      }
    }
  `;
  type Data = { sendOTP: OTPResponse };
  const data = await fetchGraphQL<Data>(query, {
    channel: req.channel,
    recipient: req.recipient,
  });
  return data.sendOTP;
}

export async function verifyOTP(req: VerifyOTPRequest): Promise<VerifyOTPResponse> {
  const query = /* GraphQL */ `
    query VerifyOTP($otpCode: String!, $recipient: String!) {
      verifyOTP(req: { oTPCode: $otpCode, recipient: $recipient }) {
        verified
        message
        userId: userID
        action
        channelDID
      }
    }
  `;
  type Data = { verifyOTP: VerifyOTPResponse };
  const data = await fetchGraphQL<Data>(query, {
    otpCode: req.otpCode,
    recipient: req.recipient,
  });
  return data.verifyOTP;
}

export async function registerUser(req: UserRegistrationRequest): Promise<UserRegistrationResponse> {
  const query = /* GraphQL */ `
    query RegisterUser(
      $channelDID: String!,
      $channelType: String!,
      $recipient: String!,
      $firstName: String!,
      $lastName: String!,
      $displayName: String!,
      $timezone: String!,
      $language: String!,
      $ipAddress: String!,
      $userAgent: String!
    ) {
      registerUser(
        req: {
          channelDID: $channelDID,
          channelType: $channelType,
          recipient: $recipient,
          firstName: $firstName,
          lastName: $lastName,
          displayName: $displayName,
          timezone: $timezone,
          language: $language,
          iPAddress: $ipAddress,
          userAgent: $userAgent,
          metadata: []
        }
      ) {
        success
        userId: userID
        message
        piiTokens: pIITokens {
          key
          value
        }
        identityCheckId: identityCheckID
        auditEventId: auditEventID
        createdAt
      }
    }
  `;
  type Data = { registerUser: UserRegistrationResponse };
  const data = await fetchGraphQL<Data>(query, {
    channelDID: req.channelDID,
    channelType: req.channelType,
    recipient: req.recipient,
    firstName: req.firstName,
    lastName: req.lastName,
    displayName: req.displayName,
    timezone: req.timezone,
    language: req.language,
    ipAddress: req.ipAddress,
    userAgent: req.userAgent,
  });
  return data.registerUser;
}

export async function cerberusGate(req: CerberusGateRequest): Promise<CerberusGateResponse> {
  const query = /* GraphQL */ `
    query CerberusGate(
      $channelDID: String!,
      $channelType: String!,
      $recipient: String!,
      $ipAddress: String!,
      $userAgent: String!
    ) {
      cerberusGate(
        req: {
          channelDID: $channelDID,
          channelType: $channelType,
          recipient: $recipient,
          iPAddress: $ipAddress,
          userAgent: $userAgent
        }
      ) {
        userExists
        action
        userId: userID
        availableMethods
        nextStep
        message
        auditEventId: auditEventID
      }
    }
  `;
  type Data = { cerberusGate: CerberusGateResponse };
  const data = await fetchGraphQL<Data>(query, {
    channelDID: req.channelDID,
    channelType: req.channelType,
    recipient: req.recipient,
    ipAddress: req.ipAddress,
    userAgent: req.userAgent,
  });
  return data.cerberusGate;
}

// WebAuthn actions
export type BeginWebAuthnRegistrationRequest = {
  userId: string;
  displayName?: string;
  ipAddress?: string;
  userAgent?: string;
};
export type BeginWebAuthnRegistrationResponse = {
  optionsJSON: string;
  challenge: string;
  expiresAt: string;
};

export async function beginWebAuthnRegistration(
  req: BeginWebAuthnRegistrationRequest
): Promise<BeginWebAuthnRegistrationResponse> {
  const query = /* GraphQL */ `
    query BeginWebAuthnRegistration($userID: String!, $displayName: String!, $ipAddress: String!, $userAgent: String!) {
      beginWebAuthnRegistration(
        req: { userID: $userID, displayName: $displayName, iPAddress: $ipAddress, userAgent: $userAgent }
      ) {
        optionsJSON
        challenge
        expiresAt
      }
    }
  `;
  type Data = { beginWebAuthnRegistration: BeginWebAuthnRegistrationResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    displayName: req.displayName ?? "",
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.beginWebAuthnRegistration;
}

export type FinishWebAuthnRegistrationRequest = {
  userId: string;
  challenge: string;
  credentialJSON: string;
  ipAddress?: string;
  userAgent?: string;
};
export type FinishWebAuthnRegistrationResponse = {
  success: boolean;
  message: string;
  credentialId?: string;
  sessionToken?: string;
  sessionExpiresAt?: string;
};

export async function finishWebAuthnRegistration(
  req: FinishWebAuthnRegistrationRequest
): Promise<FinishWebAuthnRegistrationResponse> {
  const query = /* GraphQL */ `
    query FinishWebAuthnRegistration(
      $userID: String!,
      $challenge: String!,
      $credentialJSON: String!,
      $ipAddress: String!, $userAgent: String!
    ) {
      finishWebAuthnRegistration(
        req: { userID: $userID, challenge: $challenge, credentialJSON: $credentialJSON, iPAddress: $ipAddress, userAgent: $userAgent }
      ) {
        success
        message
        credentialId: credentialID
        sessionToken
        sessionExpiresAt
      }
    }
  `;
  type Data = { finishWebAuthnRegistration: FinishWebAuthnRegistrationResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    challenge: req.challenge,
    credentialJSON: req.credentialJSON,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.finishWebAuthnRegistration;
}

export type BeginWebAuthnLoginRequest = {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
};
export type BeginWebAuthnLoginResponse = {
  optionsJSON: string;
  challenge: string;
  expiresAt: string;
};

export async function beginWebAuthnLogin(
  req: BeginWebAuthnLoginRequest
): Promise<BeginWebAuthnLoginResponse> {
  const query = /* GraphQL */ `
    query BeginWebAuthnLogin($userID: String!, $ipAddress: String!, $userAgent: String!) {
      beginWebAuthnLogin(req: { userID: $userID, iPAddress: $ipAddress, userAgent: $userAgent }) {
        optionsJSON
        challenge
        expiresAt
      }
    }
  `;
  type Data = { beginWebAuthnLogin: BeginWebAuthnLoginResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.beginWebAuthnLogin;
}

export type FinishWebAuthnLoginRequest = {
  userId: string;
  challenge: string;
  credentialJSON: string;
  ipAddress?: string;
  userAgent?: string;
};
export type FinishWebAuthnLoginResponse = {
  success: boolean;
  message: string;
  sessionToken?: string;
  sessionExpiresAt?: string;
};

export async function finishWebAuthnLogin(
  req: FinishWebAuthnLoginRequest
): Promise<FinishWebAuthnLoginResponse> {
  const query = /* GraphQL */ `
    query FinishWebAuthnLogin(
      $userID: String!,
      $challenge: String!,
      $credentialJSON: String!,
      $ipAddress: String!, $userAgent: String!
    ) {
      finishWebAuthnLogin(
        req: { userID: $userID, challenge: $challenge, credentialJSON: $credentialJSON, iPAddress: $ipAddress, userAgent: $userAgent }
      ) {
        success
        message
        sessionToken
        sessionExpiresAt
      }
    }
  `;
  type Data = { finishWebAuthnLogin: FinishWebAuthnLoginResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    challenge: req.challenge,
    credentialJSON: req.credentialJSON,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.finishWebAuthnLogin;
}

// Session validation
export type ValidateSessionResponse = {
  valid: boolean;
  userId?: string;
  expiresAt?: string;
  message?: string;
};

export async function validateSession(token: string): Promise<ValidateSessionResponse> {
  const query = /* GraphQL */ `
    query ValidateSession($token: String!) {
      validateSession(req: { token: $token }) {
        valid
        userId: userID
        expiresAt
        message
      }
    }
  `;
  type Data = { validateSession: ValidateSessionResponse };
  const data = await fetchGraphQL<Data>(query, { token });
  return data.validateSession;
}
