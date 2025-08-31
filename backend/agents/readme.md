1. Janus (Roman Mythology)
   • Role: God of gates, transitions, doorways, and beginnings.
   • Why it’s great: Dual-faced — looks to the past and the future. Perfect for an auth agent that checks user history and current session validity.
   • Agent name: JanusAuth or AgentJanus

2. Heimdall (Norse Mythology)
   • Role: Guardian of the Bifrost, the rainbow bridge to Asgard.
   • Traits: Super-hearing and vision; never sleeps.
   • Why it’s great: Ideal for a watchful, security-intensive gatekeeper agent.
   • Agent name: HeimdallGuard, HeimdallKey

3. Anubis (Egyptian Mythology)
   • Role: Overseer of the afterlife and guide of souls through the Duat (underworld).
   • Why it’s great: Has a “weighing of the heart” function — great metaphor for access verification.
   • Agent name: AnubisCheck, DuatPass

4. Charon (Greek Mythology)
   • Role: Ferryman who guides souls across the river Styx to the underworld.
   • Why it’s great: Symbolic of passing a threshold — works well for an agent handling one-time-passcodes or transitions between auth stages.
   • Agent name: CharonOTP, CharonBridge

5. Cerberus (Greek Mythology)
   • Role: Three-headed dog guarding the gates of the underworld.
   • Why it’s great: Multi-layered defense metaphor — great for multi-factor authentication.
   • Agent name: CerberusMFA, CerberusGate

6. Tian Guan (Taoist/Chinese Mythology)
   • Role: One of the Three Officials, specifically the Heavenly Official who grants blessings, but also seen as a regulator of access to the heavens.
   • Why it’s great: Suitable for a more subtle or benevolent form of access control.
   • Agent name: TianGate, SkyGuardian

7. Yama (Hindu/Buddhist Mythology)
   • Role: God of death and ruler of the underworld; judges the dead.
   • Why it’s great: Adds gravitas — could be used for access denial logging or security audit trail agents.
   • Agent name: YamaJudge, YamaAuthLog

{
"name": "CharonOTP",
"description": "Handles one-time-passcode verification, guiding users safely across the authentication threshold.",
"myth_origin": "Greek",
"inspiration": "Charon – the ferryman of the underworld",
"auth_stage": "OTP Verification",
"icon": "🛶"
},
{
"name": "JanusFace",
"description": "Manages biometric verification, representing dual awareness — past sessions and current identity.",
"myth_origin": "Roman",
"inspiration": "Janus – god of gates and transitions",
"auth_stage": "Biometric Check",
"icon": "🗝️"
},
{
"name": "HeimdallGuard",
"description": "Watches for unusual login activity, monitors session activity, and protects entry paths.",
"myth_origin": "Norse",
"inspiration": "Heimdall – guardian of the Bifrost",
"auth_stage": "Access Surveillance",
"icon": "🌈"
},
{
"name": "YamaAudit",
"description": "Maintains an immutable log of authentication attempts, decisions, and session judgments.",
"myth_origin": "Hindu/Buddhist",
"inspiration": "Yama – god of death and judgment",
"auth_stage": "Audit Logging",
"icon": "📜"
},
{
"name": "CerberusMFA",
"description": "Oversees multi-factor authentication, guarding the system with a three-headed defense.",
"myth_origin": "Greek",
"inspiration": "Cerberus – three-headed guard dog of the underworld",
"auth_stage": "Multi-Factor Authentication",
"icon": "🐾"
},
{
"name": "AnubisSession",
"description": "Preserves active sessions, guiding them safely through expiration, renewal, or termination.",
"myth_origin": "Egyptian",
"inspiration": "Anubis – guardian of the afterlife",
"auth_stage": "Session Management",
"icon": "⚖️"
}
