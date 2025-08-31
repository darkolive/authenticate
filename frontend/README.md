This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.

---

## Authentication Frontend (project-specific)

### Environment variables

Copy `.env.local.example` to `.env.local` and set values:

```
BACKEND_GRAPHQL_URL=http://localhost:3000/graphql
MODUS_API_KEY=replace-with-your-api-key
```

These are server-only and used by `src/lib/actions.ts` for Modus GraphQL calls.

### Local API routes

The app exposes typed API routes that proxy to the backend or serve stubs:

- POST `/api/auth/send-otp` → send OTP to email (CharonOTP)
- POST `/api/auth/verify-otp` → verify OTP and branch to signin/register (CharonOTP)
- POST `/api/auth/register` → register new user (HecateRegister)

Stubbed placeholders (UI wired, backend integration pending):

- POST `/api/auth/webauthn/login` → Passkey sign-in stub
- POST `/api/auth/webauthn/register` → Passkey registration stub
- POST `/api/auth/passwordless/send-magic-link` → Magic link stub

### Sign-in flow

Navigate to `/signin`:

1. Enter email → send OTP
2. Enter OTP → verify
3. If existing user → WebAuthn or magic link (stubs)
4. If new user → complete registration → success
