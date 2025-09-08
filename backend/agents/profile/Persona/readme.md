# Persona

**Origin:** Latin – _persona_, meaning “mask,” “character,” or “public identity.”

## Purpose

`Persona` manages the user's **personal identity** across the system, including their name, avatar, pronouns, preferences, and verified identifiers.

It honors the principle that identity is **contextual, self-defined, and evolving** — especially in neurodiverse, trauma-informed, or privacy-sensitive environments.

## Responsibilities

- Create and manage user personas
- Store public-facing attributes: name, avatar, pronouns, preferences
- Maintain multiple contextual personas (e.g. admin, learner, mentor)
- Coordinate with:
  - `HecateRegister` for user registration
  - `ChronosSession` for session management
  - `JanusFace` for biometric identity
  - `ThemisLog` for audit compliance

## Example Fields

```json
{
  "uid": "0x123",
  "name": "Rae",
  "pronouns": "they/them",
  "avatar": "ipfs://...",
  "preferences": {
    "theme": "dark",
    "language": "en",
    "notifications": true
  }
}
```
