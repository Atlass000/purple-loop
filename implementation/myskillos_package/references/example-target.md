# Target Architecture — "NovaPay" (fictional)

> This is a **fictional** system description used as input to the PURPLE-LOOP tabletop
> exercise. It does not describe any real product or organization.

## Business
NovaPay is a consumer fintech offering a mobile wallet, peer-to-peer transfers, and a
prepaid card. It operates in three markets and has ~400k users.

## Components
- **Mobile app** (iOS/Android) talking to a single public **API gateway**.
- **API gateway** — REST, behind a WAF and per-IP rate limiting. Routes are protected by
  a bearer-token check at the route level.
- **Identity provider (IdP)** — email/password plus SMS OTP. Handles login, password
  reset, and session issuance. Password reset sends a link to the registered email.
- **Core ledger service** — holds balances and transaction history.
- **Customer data store** — PII: name, national ID number, address, KYC documents.
- **KYC vendor integration** — a third-party provider performs identity verification and
  posts the result back to an onboarding endpoint. The endpoint accepts callbacks from
  the vendor's published IP range.
- **Admin console** — internal tool for support and operations staff; can view accounts,
  reset credentials, and reverse transactions.
- **Support desk** — outsourced to a BPO partner. Agents verify callers using name, date
  of birth, and the last four digits of the registered phone number, then may trigger a
  password reset or unlock an account from the admin console.
- **Observability** — application logs and nightly database backups shipped to a central
  bucket shared across environments.
- **CI/CD** — GitHub-based pipeline with branch protection; deploy credentials are stored
  as long-lived repository secrets.

## Data flows
1. App → API gateway → IdP (auth) → ledger / customer store.
2. KYC vendor → onboarding endpoint (callback) → customer store (sets `kyc_verified`).
3. Support agent → admin console → IdP (credential reset) and ledger (reversal).
4. All services → log pipeline → shared observability bucket → nightly backup.

## Stated controls
- WAF and rate limiting at the edge.
- TLS everywhere; database encryption at rest.
- MFA (SMS OTP) for end users at login.
- Branch protection on the main repository.
- Annual security awareness training for internal staff.

## Known constraints
- The support desk BPO contract does not currently allow biometric or hardware-token
  verification of callers.
- The KYC vendor does not support signed callbacks on the current contract tier.
- A legacy account-recovery path from the 2021 platform is still enabled for a subset of
  users who have not migrated.
