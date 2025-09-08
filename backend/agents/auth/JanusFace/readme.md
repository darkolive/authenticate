JanusFace

Origin: Roman Mythology
Inspired by: Janus, the god of gates, beginnings, transitions, and duality — often depicted with two faces, one looking to the past, the other to the future.

⸻

Purpose

JanusFace is the gatekeeping agent responsible for janusface authentication, enabling passwordless, biometric, or device-based login in a secure and user-friendly way.

It stands at the threshold of the system, verifying identity via trusted presence rather than shared secrets.

⸻

Responsibilities
• Register new janusface credentials (biometric or hardware-based)
• Validate challenge–response janusface login requests
• Associate device credentials with user profiles (PersonaProfile)
• Support credential rotation, revocation, and multi-device linkage
• Coordinate with:
• ChronosSession for issuing session tokens
• ThemisLog for audit trails
• PII handler for secure key storage

⸻

janusface Workflow

1. Credential Registration
   • Frontend calls JanusFace.register()
   • JanusFace issues a challenge
   • User device/browser generates a public key credential (via biometric or hardware key)
   • Credential is stored and linked to user’s UID

2. Login Verification
   • Frontend calls JanusFace.verify() with signed challenge response
   • JanusFace checks authenticity of signature
   • On success, issues session via ChronosSession

Security Considerations
• janusface keys are never stored in plaintext
• Each registration is validated and signed using platform-specific hardware
• Supports passkeys, Face ID, Windows Hello, Touch ID, and YubiKeys

⸻

Philosophy

Just as Janus watches both inward and outward, JanusFace ensures that only those truly present — in flesh or trusted device — may pass.

⸻
