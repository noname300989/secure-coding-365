# SaaS-to-SaaS Security — Architect + Pentester Perspective

## 🏗️ Security Architect Perspective — What Must Be In Place

### 1. Mutual Authentication (mTLS)

Both SaaS apps must prove identity to each other — not just one-way.

```
SaaS A ──── TLS + Client Cert ────▶ SaaS B
SaaS A ◀─── TLS + Client Cert ────── SaaS B
Both sides verify each other's X.509 certificate
```

- Each service has its own TLS certificate signed by a trusted CA
- Certificate pinning prevents MITM even if CA is compromised
- Auto-rotate certificates before expiry

---

### 2. OAuth 2.0 Client Credentials Flow

The standard for machine-to-machine (M2M) auth between SaaS apps:

```
SaaS A ──▶ Authorization Server: "Here's my client_id + client_secret"
Auth Server ──▶ SaaS A: "Here's a short-lived access token (JWT)"
SaaS A ──▶ SaaS B: "Bearer <JWT>" + API request
SaaS B ──▶ Auth Server: Validates token (or validates locally via JWKS)
```

- **Never** use user-facing OAuth flows (auth code) for service-to-service
- Tokens should be short-lived (5-15 min)
- Use scopes to limit what each service can access

---

### 3. API Gateway & Zero Trust Architecture

```
┌─────────┐    ┌──────────────┐    ┌──────────────┐    ┌─────────┐
│ SaaS A  │───▶│  API Gateway │───▶│  API Gateway │───▶│ SaaS B  │
│         │    │  (Egress)    │    │  (Ingress)   │    │         │
└─────────┘    │• Auth        │    │• Auth verify │    └─────────┘
               │• Rate limit  │    │• IP allowlist│
               │• Logging     │    │• WAF rules   │
               └──────────────┘    └──────────────┘
```

- **Never trust, always verify** — even between internal services
- Every request is authenticated + authorized, no exceptions
- Network-level controls: IP allowlisting, VPN/PrivateLink

---

### 4. Request Signing (HMAC / Digital Signatures)

Prevent tampering of API requests in transit:

```
SaaS A computes:
signature = HMAC-SHA256(shared_secret, 
    method + path + timestamp + body_hash)

Headers sent:
X-Signature: <computed_signature>
X-Timestamp: 1713290400
X-Nonce: abc123xyz

SaaS B recomputes signature and compares.
```

- Timestamp validation (reject requests >5 min old) prevents replay attacks
- Nonce tracking prevents duplicate request replay
- Body hashing ensures payload integrity

---

### 5. Data Protection

- **Encryption in transit:** TLS 1.3 mandatory (no TLS 1.0/1.1)
- **Encryption at rest:** AES-256 for any stored shared data
- **Field-level encryption:** PII/sensitive fields encrypted even within JSON payloads
- **Data minimization:** Only share the minimum data needed
- **Tokenization:** Replace sensitive data with tokens (e.g., payment card → token)

---

### 6. Webhook Security

When SaaS B sends events to SaaS A:

- Webhook signature verification (HMAC of payload)
- Shared secret rotation
- Verify source IP
- Idempotency keys to handle duplicate deliveries
- Respond with 200 before processing (prevent timeout-based info leak)

---

### 7. Secrets Management

- Store API keys, client secrets, certs in a vault (HashiCorp Vault, AWS Secrets Manager)
- **Never** hardcode secrets in code or config files
- Automatic rotation on a schedule
- Separate secrets per environment (dev ≠ staging ≠ prod)

---

### 8. Rate Limiting & Circuit Breakers

- Per-partner rate limits (not just global)
- Circuit breaker pattern: if SaaS B is failing, stop sending requests
- Backoff + retry with jitter
- Quota management per integration partner

---

### 9. Logging, Monitoring & Audit Trail

- Log every inter-service API call (who, what, when, from where)
- Immutable audit logs for compliance (SOC 2, ISO 27001)
- Anomaly detection: unusual volume, new IPs, off-hours access
- Alert on auth failures, signature mismatches, rate limit hits

---

### 10. Contract & Compliance

- Data Processing Agreement (DPA) between SaaS providers
- Define data retention & deletion policies
- SOC 2 Type II / ISO 27001 certification requirements
- Incident response SLA between partners

---

## 🔴 Pentester Perspective — What to Attack & Test

### 1. Authentication Testing

```
☐ Is mTLS enforced or optional? Try connecting without client cert
☐ Steal/reuse OAuth tokens — are they short-lived?
☐ Test token scope: can SaaS A's token access SaaS C's resources?
☐ Try expired/revoked tokens — are they still accepted?
☐ Brute-force client_secret if no lockout
☐ Check if API keys are in URLs (logged in server logs)
☐ Test if auth can be bypassed via HTTP method change
```

---

### 2. HMAC/Signature Bypass

```
☐ Remove X-Signature header entirely — does request still work?
☐ Send empty signature — accepted?
☐ Replay old signed request (same nonce + timestamp)
☐ Modify body after signing — is signature actually verified?
☐ Tamper with timestamp (set to future) — is clock skew too generous?
☐ Try signature with different algorithms (SHA1 vs SHA256)
☐ Length extension attacks on HMAC if using MD5/SHA1
```

---

### 3. Authorization & Data Leakage

```
☐ Can SaaS A access SaaS B's OTHER customers' data? (tenant isolation)
☐ Horizontal escalation: change tenant_id in requests
☐ Can you access admin/internal endpoints of the partner API?
☐ Check if excessive data is returned in responses
☐ Test webhook endpoints — can you spoof events from SaaS B?
☐ Send webhook with forged signature — is it verified?
```

---

### 4. Network & Infrastructure

```
☐ Is communication over TLS 1.3? Test for TLS 1.0/1.1 downgrade
☐ Test weak cipher suites (testssl.sh, sslyze)
☐ Is IP allowlisting enforced? Try from different IP
☐ Can you bypass API gateway and hit backend directly?
☐ SSRF: Can you make SaaS A call internal endpoints of SaaS B?
☐ DNS rebinding to bypass IP restrictions
```

---

### 5. Injection & Business Logic

```
☐ SQL/NoSQL injection in shared API parameters
☐ XML/JSON injection in data exchange payloads
☐ Race conditions in webhook processing
☐ Can you trigger excessive API calls (billing abuse)?
☐ Parameter pollution between services
☐ SSRF via webhook callback URLs
☐ Deserialization attacks if using binary formats
```

---

### 6. Secret & Key Management Testing

```
☐ Search GitHub/GitLab for leaked API keys or secrets
☐ Check client-side code for hardcoded credentials
☐ Are secrets rotated? Try old keys — still work?
☐ Can you extract secrets from error messages?
☐ Is the same API key used across all environments?
☐ Check .env files, config endpoints, debug pages
```

---

## ⚡ Quick Reference — Security Layers Summary

| Layer | Architect (Build) | Pentester (Break) |
|---|---|---|
| **Network** | mTLS, IP allowlist, VPN | TLS downgrade, bypass gateway |
| **Authentication** | OAuth 2.0 CC, mTLS, API keys | Token theft, replay, brute force |
| **Authorization** | Scopes, RBAC, tenant isolation | Tenant escape, scope escalation |
| **Integrity** | HMAC signing, nonce, timestamp | Remove/forge signature, replay |
| **Encryption** | TLS 1.3, field-level encryption | Weak ciphers, missing encryption |
| **Rate Limiting** | Per-partner quotas, circuit breaker | Bypass via headers, billing abuse |
| **Monitoring** | Audit logs, anomaly detection | Blind spots, log injection |
| **Secrets** | Vault, auto-rotation | Leaked keys, old keys, env files |

> **FAANG Interview Tip:** They want to hear you cover auth, encryption, authorization, integrity, and monitoring as distinct layers.
