"use server";
import "server-only";

// Centralized GraphQL client for Modus backend
// Reads server-only environment variables
const GRAPHQL_URL = process.env.BACKEND_GRAPHQL_URL;
const MODUS_API_KEY = process.env.MODUS_API_KEY;

if (!GRAPHQL_URL) {
  console.warn(
    "[actions] BACKEND_GRAPHQL_URL is not set. Set it in .env.local"
  );
}

// Decrypt persona (self-service)
export type GetUserPIIResponse = {
  firstName?: string;
  lastName?: string;
  displayName?: string;
  firstName_enc?: string;
  lastName_enc?: string;
  displayName_enc?: string;
  message?: string;
};

export async function getUserPII(userId: string): Promise<GetUserPIIResponse> {
  const query = /* GraphQL */ `
    query GetUserPII($userID: String!) {
      getUserPII(req: { userID: $userID }) {
        firstName
        lastName
        displayName
        firstName_enc
        lastName_enc
        displayName_enc
        message
      }
    }
  `;
  type Data = { getUserPII: GetUserPIIResponse };
  const data = await fetchGraphQL<Data>(query, { userID: userId });
  return data.getUserPII;
}

// List passkeys
export type PasskeyItem = {
  credentialId: string;
  addedAt?: string;
  revoked: boolean;
  revokedAt?: string;
  transports?: string;
};

export type ListPasskeysResponse = {
  items: PasskeyItem[];
  message?: string;
};

export async function listPasskeys(userId: string): Promise<ListPasskeysResponse> {
  const query = /* GraphQL */ `
    query ListPasskeys($userID: String!) {
      listjanusfacePasskeys(req: { userID: $userID }) {
        items {
          credentialId
          addedAt
          revoked
          revokedAt
          transports
        }
        message
      }
    }
  `;
  type Data = { listjanusfacePasskeys: ListPasskeysResponse };
  const data = await fetchGraphQL<Data>(query, { userID: userId });
  return data.listjanusfacePasskeys;
}

// Passkey management (janusface)
export type RevokePasskeysRequest = {
  userId: string;
  credentialId?: string;
  reason?: string;
  ipAddress?: string;
  userAgent?: string;
};

export type RevokePasskeysResponse = {
  success: boolean;
  message?: string;
  count: number;
};

export async function revokePasskeys(
  req: RevokePasskeysRequest
): Promise<RevokePasskeysResponse> {
  const query = /* GraphQL */ `
    query RevokePasskeys(
      $userID: String!
      $credentialId: String!
      $reason: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      revokejanusfacePasskeys(
        req: {
          userID: $userID
          credentialId: $credentialId
          reason: $reason
          iPAddress: $ipAddress
          userAgent: $userAgent
        }
      ) {
        success
        message
        count
      }
    }
  `;
  type Data = { revokejanusfacePasskeys: RevokePasskeysResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    credentialId: req.credentialId ?? "",
    reason: req.reason ?? "",
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.revokejanusfacePasskeys;
}

// Merge candidates
export type MergeCandidateItem = {
  uid: string;
  candidateUser: string;
  candidateDID: string;
  channelType: string;
  channelHash: string;
  signals: string[];
  score: number;
  status: string;
  createdAt?: string;
};

export type ListMergeCandidatesResponse = {
  items: MergeCandidateItem[];
  message?: string;
};

export async function listMergeCandidates(
  userId: string
): Promise<ListMergeCandidatesResponse> {
  const query = /* GraphQL */ `
    query ListMergeCandidates($userID: String!) {
      listMergeCandidates(req: { userID: $userID }) {
        items {
          uid: uID
          candidateUser
          candidateDID
          channelType
          channelHash
          signals
          score
          status
          createdAt
        }
        message
      }
    }
  `;
  type Data = { listMergeCandidates: ListMergeCandidatesResponse };
  const data = await fetchGraphQL<Data>(query, { userID: userId });
  return data.listMergeCandidates;
}

export type ConfirmMergeCandidateRequest = {
  mergeCandidateUID: string;
  decision: "confirm" | "dismiss";
  userId: string;
};

export type ConfirmMergeCandidateResponse = {
  success: boolean;
  message?: string;
};

export async function confirmMergeCandidate(
  req: ConfirmMergeCandidateRequest
): Promise<ConfirmMergeCandidateResponse> {
  const query = /* GraphQL */ `
    query ConfirmMergeCandidate(
      $mergeCandidateUID: String!
      $decision: String!
      $userID: String!
    ) {
      confirmMergeCandidate(
        req: { mergeCandidateUID: $mergeCandidateUID, decision: $decision, userID: $userID }
      ) {
        success
        message
      }
    }
  `;
  type Data = { confirmMergeCandidate: ConfirmMergeCandidateResponse };
  const data = await fetchGraphQL<Data>(query, {
    mergeCandidateUID: req.mergeCandidateUID,
    decision: req.decision,
    userID: req.userId,
  });
  return data.confirmMergeCandidate;
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

export type LinkChannelStartRequest = {
  userId: string;
  channelType: "email" | "sms" | "whatsapp";
  value: string;
};

export type LinkChannelStartResponse = {
  success: boolean;
  message?: string;
  linkId?: string;
  challengeType?: string;
  destination?: string;
  expiresAt?: string;
};

export type LinkChannelConfirmRequest = {
  userId: string;
  channelType: "email" | "sms" | "whatsapp";
  value: string;
  otpCode: string;
};

export type LinkChannelConfirmResponse = {
  success: boolean;
  message?: string;
  channelUID?: string;
  clusterUID?: string;
};

// Linked channels
export type LinkedChannel = {
  uid: string;
  channelType: string;
  verified: boolean;
  normalizedValue: string;
  provider?: string;
  subject?: string;
  lastVerifiedAt?: string;
};

export type GetLinkedChannelsResponse = {
  clusterUID?: string;
  channels: LinkedChannel[];
  message?: string;
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
  // Optional merge hints (if backend supports)
  mergeCandidate?: boolean;
  mergeScore?: number;
  mergeSignals?: string[];
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

type GraphQLErrorItem = { message?: string };
type GraphQLResponse<T> = { data?: T; errors?: GraphQLErrorItem[]; error?: string };

async function fetchGraphQL<T>(
  query: string,
  variables?: Record<string, unknown>
): Promise<T> {
  if (!GRAPHQL_URL) {
    throw new Error(
      "GraphQL environment not configured. Set BACKEND_GRAPHQL_URL"
    );
  }
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  // Only attach Authorization if the token looks like a JWT (three segments)
  const token = (MODUS_API_KEY || "").trim();
  if (token && token.split(".").length === 3) {
    headers.Authorization = `Bearer ${token}`;
  }
  const res = await fetch(GRAPHQL_URL, {
    method: "POST",
    headers,
    body: JSON.stringify({ query, variables }),
    cache: "no-store",
  });

  // Read raw text first for better diagnostics if JSON parsing fails
  const raw = await res.text();
  let json: unknown;
  try {
    json = raw ? JSON.parse(raw) : {};
  } catch {
    const snippet = raw?.slice(0, 300) || "<empty body>";
    const ct = res.headers.get("content-type") || "";
    throw new Error(
      `Backend GraphQL returned non-JSON (status ${res.status}) [${ct}]: ${snippet}`
    );
  }

  const parsed = json as GraphQLResponse<T>;
  if (!res.ok || parsed.errors || parsed.data == null) {
    const snippet = raw?.slice(0, 300) || "<empty body>";
    const err = parsed.errors?.[0]?.message || parsed.error || res.statusText || "No data returned from GraphQL";
    throw new Error(`${err} :: ${snippet}`);
  }
  return parsed.data as T;
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
  type Data = { sendOTP?: OTPResponse };
  const data = await fetchGraphQL<Data>(query, {
    channel: req.channel,
    recipient: req.recipient,
  });
  if (!data || !data.sendOTP) {
    throw new Error("GraphQL response missing sendOTP field");
  }
  return data.sendOTP;
}

export async function verifyOTP(
  req: VerifyOTPRequest
): Promise<VerifyOTPResponse> {
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

export async function linkChannelStart(
  req: LinkChannelStartRequest
): Promise<LinkChannelStartResponse> {
  const query = /* GraphQL */ `
    query LinkChannelStart($userID: String!, $channelType: String!, $value: String!) {
      linkChannelStart(req: { userID: $userID, channelType: $channelType, value: $value }) {
        success
        message
        linkId: linkID
        challengeType
        destination
        expiresAt
      }
    }
  `;
  type Data = { linkChannelStart: LinkChannelStartResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    channelType: req.channelType,
    value: req.value,
  });
  return data.linkChannelStart;
}

export async function linkChannelConfirm(
  req: LinkChannelConfirmRequest
): Promise<LinkChannelConfirmResponse> {
  const query = /* GraphQL */ `
    query LinkChannelConfirm(
      $userID: String!,
      $channelType: String!,
      $value: String!,
      $oTPCode: String!,
      $provider: String!,
      $subject: String!
    ) {
      linkChannelConfirm(
        req: { userID: $userID, channelType: $channelType, value: $value, oTPCode: $oTPCode, provider: $provider, subject: $subject }
      ) {
        success
        message
        channelUID
        clusterUID
      }
    }
  `;
  type Data = { linkChannelConfirm: LinkChannelConfirmResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    channelType: req.channelType,
    value: req.value,
    oTPCode: req.otpCode,
    provider: "",
    subject: "",
  });
  return data.linkChannelConfirm;
}

export async function getLinkedChannels(
  userId: string
): Promise<GetLinkedChannelsResponse> {
  // Primary: try getLinkedChannels
  const queryPrimary = /* GraphQL */ `
    query GetLinkedChannels($userID: String!) {
      getLinkedChannels(req: { userID: $userID }) {
        clusterUID
        channels {
          uid: uID
          channelType
          verified
          normalizedValue
          provider
          subject
          lastVerifiedAt
        }
        message
      }
    }
  `;
  const variables = { userID: userId } as const;
  try {
    type DataPrimary = { getLinkedChannels: GetLinkedChannelsResponse };
    const data = await fetchGraphQL<DataPrimary>(queryPrimary, variables);
    return data.getLinkedChannels;
  } catch {
    // Fallback: some runtimes expose this resolver as 'linkedChannels'
    const queryFallback = /* GraphQL */ `
      query LinkedChannels($userID: String!) {
        linkedChannels(req: { userID: $userID }) {
          clusterUID
          channels {
            uid: uID
            channelType
            verified
            normalizedValue
            provider
            subject
            lastVerifiedAt
          }
          message
        }
      }
    `;
    type DataFallback = { linkedChannels: GetLinkedChannelsResponse };
    const data = await fetchGraphQL<DataFallback>(queryFallback, variables);
    return data.linkedChannels;
  }
}

export async function registerUser(
  req: UserRegistrationRequest
): Promise<UserRegistrationResponse> {
  const query = /* GraphQL */ `
    query RegisterUser(
      $channelDID: String!
      $channelType: String!
      $recipient: String!
      $firstName: String!
      $lastName: String!
      $displayName: String!
      $timezone: String!
      $language: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      registerUser(
        req: {
          channelDID: $channelDID
          channelType: $channelType
          recipient: $recipient
          firstName: $firstName
          lastName: $lastName
          displayName: $displayName
          timezone: $timezone
          language: $language
          iPAddress: $ipAddress
          userAgent: $userAgent
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

export async function cerberusGate(
  req: CerberusGateRequest
): Promise<CerberusGateResponse> {
  const vars = {
    channelDID: req.channelDID,
    channelType: req.channelType,
    recipient: req.recipient,
    ipAddress: req.ipAddress,
    userAgent: req.userAgent,
  } as const;

  // Primary: request merge fields if backend supports them
  const queryWithMerge = /* GraphQL */ `
    query CerberusGate(
      $channelDID: String!
      $channelType: String!
      $recipient: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      cerberusGate(
        req: {
          channelDID: $channelDID
          channelType: $channelType
          recipient: $recipient
          iPAddress: $ipAddress
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
        mergeCandidate
        mergeScore
        mergeSignals
      }
    }
  `;
  try {
    type Data = { cerberusGate: CerberusGateResponse };
    const data = await fetchGraphQL<Data>(queryWithMerge, vars);
    return data.cerberusGate;
  } catch {
    // Fallback: legacy backend without merge fields
    const queryLegacy = /* GraphQL */ `
      query CerberusGate(
        $channelDID: String!
        $channelType: String!
        $recipient: String!
        $ipAddress: String!
        $userAgent: String!
      ) {
        cerberusGate(
          req: {
            channelDID: $channelDID
            channelType: $channelType
            recipient: $recipient
            iPAddress: $ipAddress
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
    type DataLegacy = { cerberusGate: CerberusGateResponse };
    const data = await fetchGraphQL<DataLegacy>(queryLegacy, vars);
    return data.cerberusGate;
  }
}

// janusface actions
export type BeginjanusfaceRegistrationRequest = {
  userId: string;
  displayName?: string;
  ipAddress?: string;
  userAgent?: string;
};
export type BeginjanusfaceRegistrationResponse = {
  optionsJSON: string;
  challenge: string;
  expiresAt: string;
};

export async function beginjanusfaceRegistration(
  req: BeginjanusfaceRegistrationRequest
): Promise<BeginjanusfaceRegistrationResponse> {
  const query = /* GraphQL */ `
    query BeginjanusfaceRegistration(
      $userID: String!
      $displayName: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      beginjanusfaceRegistration(
        req: {
          userID: $userID
          displayName: $displayName
          iPAddress: $ipAddress
          userAgent: $userAgent
        }
      ) {
        optionsJSON
        challenge
        expiresAt
      }
    }
  `;
  type Data = {
    beginjanusfaceRegistration: BeginjanusfaceRegistrationResponse;
  };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    displayName: req.displayName ?? "",
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.beginjanusfaceRegistration;
}

export type FinishjanusfaceRegistrationRequest = {
  userId: string;
  challenge: string;
  credentialJSON: string;
  ipAddress?: string;
  userAgent?: string;
};
export type FinishjanusfaceRegistrationResponse = {
  success: boolean;
  message: string;
  credentialId?: string;
  sessionToken?: string;
  sessionExpiresAt?: string;
};

export async function finishjanusfaceRegistration(
  req: FinishjanusfaceRegistrationRequest
): Promise<FinishjanusfaceRegistrationResponse> {
  const query = /* GraphQL */ `
    query FinishjanusfaceRegistration(
      $userID: String!
      $challenge: String!
      $credentialJSON: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      finishjanusfaceRegistration(
        req: {
          userID: $userID
          challenge: $challenge
          credentialJSON: $credentialJSON
          iPAddress: $ipAddress
          userAgent: $userAgent
        }
      ) {
        success
        message
        credentialId: credentialID
        sessionToken
        sessionExpiresAt
      }
    }
  `;
  type Data = {
    finishjanusfaceRegistration: FinishjanusfaceRegistrationResponse;
  };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    challenge: req.challenge,
    credentialJSON: req.credentialJSON,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.finishjanusfaceRegistration;
}

export type BeginjanusfaceLoginRequest = {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
};
export type BeginjanusfaceLoginResponse = {
  optionsJSON: string;
  challenge: string;
  expiresAt: string;
};

export async function beginjanusfaceLogin(
  req: BeginjanusfaceLoginRequest
): Promise<BeginjanusfaceLoginResponse> {
  const query = /* GraphQL */ `
    query BeginjanusfaceLogin(
      $userID: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      beginjanusfaceLogin(
        req: { userID: $userID, iPAddress: $ipAddress, userAgent: $userAgent }
      ) {
        optionsJSON
        challenge
        expiresAt
      }
    }
  `;
  type Data = { beginjanusfaceLogin: BeginjanusfaceLoginResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.beginjanusfaceLogin;
}

export type FinishjanusfaceLoginRequest = {
  userId: string;
  challenge: string;
  credentialJSON: string;
  ipAddress?: string;
  userAgent?: string;
};
export type FinishjanusfaceLoginResponse = {
  success: boolean;
  message: string;
  sessionToken?: string;
  sessionExpiresAt?: string;
};

export async function finishjanusfaceLogin(
  req: FinishjanusfaceLoginRequest
): Promise<FinishjanusfaceLoginResponse> {
  const query = /* GraphQL */ `
    query FinishjanusfaceLogin(
      $userID: String!
      $challenge: String!
      $credentialJSON: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      finishjanusfaceLogin(
        req: {
          userID: $userID
          challenge: $challenge
          credentialJSON: $credentialJSON
          iPAddress: $ipAddress
          userAgent: $userAgent
        }
      ) {
        success
        message
        sessionToken
        sessionExpiresAt
      }
    }
  `;
  type Data = { finishjanusfaceLogin: FinishjanusfaceLoginResponse };
  const data = await fetchGraphQL<Data>(query, {
    userID: req.userId,
    challenge: req.challenge,
    credentialJSON: req.credentialJSON,
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  });
  return data.finishjanusfaceLogin;
}

// Session validation
export type ValidateSessionResponse = {
  valid: boolean;
  userId?: string;
  expiresAt?: string;
  message?: string;
};

export async function validateSession(
  token: string
): Promise<ValidateSessionResponse> {
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

// persona management
export type UpdatepersonaRequest = {
  userId: string;
  firstName?: string;
  lastName?: string;
  displayName?: string;
  ipAddress?: string;
  userAgent?: string;
};

export type UpdatepersonaResponse = {
  success: boolean;
  message?: string;
  userId?: string;
  updatedAt?: string;
};

export async function updateUserpersona(
  req: UpdatepersonaRequest
): Promise<UpdatepersonaResponse> {
  const vars = {
    userID: req.userId,
    firstName: req.firstName ?? "",
    lastName: req.lastName ?? "",
    displayName: req.displayName ?? "",
    ipAddress: req.ipAddress ?? "",
    userAgent: req.userAgent ?? "",
  };

  // Prefer persona naming
  const queryPersona = /* GraphQL */ `
    query UpdateUserpersona(
      $userID: String!
      $firstName: String!
      $lastName: String!
      $displayName: String!
      $ipAddress: String!
      $userAgent: String!
    ) {
      updateUserpersona(
        req: {
          userID: $userID
          firstName: $firstName
          lastName: $lastName
          displayName: $displayName
          iPAddress: $ipAddress
          userAgent: $userAgent
        }
      ) {
        success
        message
        userId: userID
        updatedAt
      }
    }
  `;
  try {
    type DataPersona = { updateUserpersona: UpdatepersonaResponse };
    const data = await fetchGraphQL<DataPersona>(queryPersona, vars);
    return data.updateUserpersona;
  } catch {
    // Fallback to older profile naming
    const queryProfile = /* GraphQL */ `
      query UpdateUserProfile(
        $userID: String!
        $firstName: String!
        $lastName: String!
        $displayName: String!
        $ipAddress: String!
        $userAgent: String!
      ) {
        updateUserProfile(
          req: {
            userID: $userID
            firstName: $firstName
            lastName: $lastName
            displayName: $displayName
            iPAddress: $ipAddress
            userAgent: $userAgent
          }
        ) {
          success
          message
          userId: userID
          updatedAt
        }
      }
    `;
    type DataProfile = { updateUserProfile: UpdatepersonaResponse };
    const data = await fetchGraphQL<DataProfile>(queryProfile, vars);
    return data.updateUserProfile;
  }
}

export type CompletepersonaResponse = {
  complete: boolean;
  hasDisplayName: boolean;
  hasName: boolean;
  status?: string;
  message?: string;
};

export async function ispersonaComplete(
  userId: string
): Promise<CompletepersonaResponse> {
  const vars = { userID: userId };
  const queryPersona = /* GraphQL */ `
    query IspersonaComplete($userID: String!) {
      ispersonaComplete(req: { userID: $userID }) {
        complete
        hasDisplayName
        hasName
        status
        message
      }
    }
  `;
  try {
    type DataPersona = { ispersonaComplete: CompletepersonaResponse };
    const data = await fetchGraphQL<DataPersona>(queryPersona, vars);
    return data.ispersonaComplete;
  } catch {
    const queryProfile = /* GraphQL */ `
      query IsProfileComplete($userID: String!) {
        isProfileComplete(req: { userID: $userID }) {
          complete
          hasDisplayName
          hasName
          status
          message
        }
      }
    `;
    type DataProfile = { isProfileComplete: CompletepersonaResponse };
    const data = await fetchGraphQL<DataProfile>(queryProfile, vars);
    return data.isProfileComplete;
  }
}
