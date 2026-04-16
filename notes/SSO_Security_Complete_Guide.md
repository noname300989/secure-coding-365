# 🛡️ SSO Security — Complete Deep Dive

> **Author:** Gayatri Rachakonda  
> **Date:** April 16, 2026  
> **Part of:** [Secure Coding 365 — Zero to Hero Program](../README.md)

---

## Table of Contents
- [1. What is SSO & How It Works](#1-what-is-sso--how-it-works)
- [2. Types of SSO Protocols](#2-types-of-sso-protocols)
  - [2.1 SAML 2.0](#21-saml-20-security-assertion-markup-language)
  - [2.2 OAuth 2.0 + OpenID Connect](#22-oauth-20--openid-connect-oidc)
  - [2.3 Kerberos](#23-kerberos)
  - [2.4 CAS](#24-cas-central-authentication-service)
  - [2.5 LDAP-Based SSO](#25-ldap-based-sso)
  - [2.6 Token-Based SSO](#26-token-based-sso-custom-jwt--cookie-based)
- [3. SSO Types Comparison](#3-sso-types-comparison)
- [4. SSO Vulnerabilities & Attacks](#4-sso-vulnerabilities--attacks)
  - [4.1 XML Signature Wrapping (XSW)](#41-xml-signature-wrapping-xsw-attack)
  - [4.2 SAML Assertion Replay](#42-saml-assertion-replay-attack)
  - [4.3 XXE in SAML Parsing](#43-xxe-in-saml-parsing)
  - [4.4 Open Redirect / Auth Code Interception](#44-open-redirect--authorization-code-interception)
  - [4.5 JWT Token Vulnerabilities](#45-jwt-token-vulnerabilities-in-oidc)
  - [4.6 Insecure Token Storage](#46-insecure-token-storage)
  - [4.7 Kerberoasting](#47-kerberoasting)
  - [4.8 Golden Ticket Attack](#48-golden-ticket-attack)
  - [4.9 Pass-the-Ticket](#49-pass-the-ticket-ptt)
  - [4.10 Session Fixation](#410-sso-session-fixation)
  - [4.11 Insufficient Logout](#411-insufficient-logout-single-logout-failure)
  - [4.12 Account Linking Attacks](#412-account-linking--email-confusion-attacks)
- [5. Security Best Practices Checklist](#5-sso-security-best-practices-checklist)
- [6. Vulnerability Summary Matrix](#6-vulnerability-summary-matrix)

---

## 1. What is SSO & How It Works

**Single Sign-On (SSO)** lets a user authenticate **once** and gain access to multiple applications without re-entering credentials.

### The Core Concept

- User logs in to an **Identity Provider (IdP)** — the central auth server
- IdP issues a **token/assertion** proving identity
- User presents that token to **Service Providers (SPs)** — the apps
- SPs trust the IdP and grant access **without asking for a password again**

> 💡 Think of it like an airport boarding pass — you verify your identity once at check-in (IdP), then use your boarding pass (token) to access the lounge, the gate, and the plane (SPs) without showing your passport every time.

### Why SSO Matters for Security

**Advantages:**
- ✅ **Fewer passwords** → users don't reuse weak passwords across apps
- ✅ **Centralized auth** → one place to enforce MFA, lockout, password policies
- ✅ **Faster deprovisioning** → disable one account, access revoked everywhere
- ✅ **Audit trail** → single log of all authentication events

**Risks:**
- ⚠️ **Single point of failure** → compromise the IdP = compromise everything
- ⚠️ **Token theft** → one stolen token grants access to ALL connected apps
- ⚠️ **Complex implementation** → misconfigurations = major vulnerabilities

---

## 2. Types of SSO Protocols

There are **6 major SSO protocols/approaches**. Each works differently and has unique security trade-offs.

---

### 2.1 SAML 2.0 (Security Assertion Markup Language)

| Property | Value |
|----------|-------|
| **Format** | XML-based assertions |
| **Transport** | HTTP POST/Redirect (browser-based) |
| **Best for** | Enterprise web apps, legacy systems |
| **Used by** | Okta, Azure AD, OneLogin, ADFS |

#### How it works:

```
1. User visits SP (e.g., Salesforce)
2. SP redirects to IdP (e.g., Okta) with SAML AuthnRequest
3. User authenticates at IdP
4. IdP sends SAML Response (XML assertion) back to SP via browser POST
5. SP validates the XML signature and grants access
```

#### Key Security Features:
- XML Digital Signatures (XMLDsig) for integrity
- Optional XML Encryption for confidentiality
- Assertion expiration timestamps
- Audience restriction (assertion is locked to specific SP)

---

### 2.2 OAuth 2.0 + OpenID Connect (OIDC)

| Property | Value |
|----------|-------|
| **Format** | JSON (JWT tokens) |
| **Transport** | HTTPS REST APIs |
| **Best for** | Modern web/mobile apps, APIs, SPAs |
| **Used by** | Google, GitHub, Auth0, Cognito |

#### How it works:

```
1. User clicks "Login with Google"
2. App redirects to Google's auth server with client_id + redirect_uri
3. User authenticates & consents
4. Google redirects back with authorization code
5. App exchanges code for access_token + id_token (JWT)
6. App reads user identity from id_token
```

#### Key Difference:
- **OAuth 2.0** = Authorization only ("what can you access?")
- **OIDC** = OAuth 2.0 + **Authentication layer** ("who are you?")
- OIDC adds the `id_token` (JWT) with user identity claims

---

### 2.3 Kerberos

| Property | Value |
|----------|-------|
| **Format** | Binary tickets (ASN.1 encoded) |
| **Transport** | TCP/UDP (port 88) |
| **Best for** | Internal networks, Windows AD environments |
| **Used by** | Active Directory, MIT Kerberos, Hadoop |

#### How it works:

```
1. User authenticates to KDC (Key Distribution Center)
2. KDC issues TGT (Ticket Granting Ticket)
3. User presents TGT to request Service Tickets for specific services
4. Service validates ticket and grants access
   All tickets are time-limited and encrypted
```

#### Key Security Features:
- Mutual authentication (both client and server verify each other)
- Passwords **never** traverse the network
- Time-based ticket expiry (typically 8-10 hours)
- Symmetric key cryptography

---

### 2.4 CAS (Central Authentication Service)

| Property | Value |
|----------|-------|
| **Format** | XML or JSON tickets |
| **Transport** | HTTPS redirects + back-channel ticket validation |
| **Best for** | Universities, internal web applications |
| **Used by** | Apereo CAS, academic institutions |

#### How it works:

```
1. User visits app → redirected to CAS login page
2. User authenticates → CAS issues a Service Ticket (ST)
3. User redirected back to app with ST in URL
4. App validates ST with CAS server via back-channel HTTPS call
5. CAS confirms identity → app grants access
```

#### Key Difference from SAML:
- Simpler protocol, easier to implement
- Back-channel validation (server-to-server) adds security
- No XML signatures needed

---

### 2.5 LDAP-Based SSO

| Property | Value |
|----------|-------|
| **Format** | LDAP directory entries |
| **Transport** | LDAP/LDAPS (port 389/636) |
| **Best for** | Internal enterprise apps binding to AD/LDAP directly |
| **Used by** | Legacy Java/PHP enterprise apps |

#### How it works:

```
1. Each app connects to the same LDAP/AD server
2. User enters credentials in each app (NOT true SSO)
3. Each app validates credentials against the central LDAP
4. "Same credentials everywhere" — not "sign in once"
```

> ⚠️ **Important:** This is technically *same-sign-on*, not *single-sign-on*. The user still types their password in each app. But it's a single credential store.

---

### 2.6 Token-Based SSO (Custom JWT / Cookie-Based)

| Property | Value |
|----------|-------|
| **Format** | JWT tokens or encrypted cookies |
| **Transport** | Shared cookies or API tokens |
| **Best for** | Microservices under the same domain, internal tools |
| **Used by** | Custom internal SSO systems |

#### How it works:

```
1. User logs in to auth service at auth.company.com
2. Auth service sets a signed JWT in a cookie for *.company.com
3. All apps on *.company.com read the shared cookie
4. Each app validates the JWT signature and reads user claims
```

> ⚠️ **Limitation:** Only works within the same top-level domain. Cross-domain needs token-passing via redirects.

---

## 3. SSO Types Comparison

| Feature | SAML 2.0 | OIDC/OAuth | Kerberos | CAS |
|---------|----------|------------|----------|-----|
| **Token Format** | XML | JSON (JWT) | Binary Tickets | XML/JSON |
| **Best For** | Enterprise | Web/Mobile | Internal Net | Universities |
| **Mobile Support** | Poor | Excellent | None | Limited |
| **API Support** | Limited | Excellent | None | Limited |
| **Complexity** | High | Medium | Very High | Low |
| **Cross-Domain** | Yes | Yes | No (same net) | Yes |
| **Industry** | Enterprise | Consumer | Corporate LAN | Education |
| **Auth+Authz** | Auth only | Both | Auth only | Auth only |
| **Logout** | Complex | Moderate | Ticket expiry | Simple |

### When to use which:

- **Enterprise B2B app?** → SAML 2.0 (it's what Okta/Azure AD clients expect)
- **Modern web/mobile app?** → OIDC (lighter, JSON, great for SPAs)
- **Windows-only internal network?** → Kerberos via Active Directory
- **Internal web portal?** → CAS (simple, effective)
- **Same-domain microservices?** → Token-based/JWT cookies

---

## 4. SSO Vulnerabilities & Attacks

### SAML-Specific Vulnerabilities

---

### 4.1 XML Signature Wrapping (XSW) Attack

The **#1 most critical SAML vulnerability**. The attacker *moves* the legitimate signed XML block and *injects* a malicious assertion that the SP processes instead.

#### How it works:

```xml
<!-- LEGITIMATE SAML Response (simplified) -->
<Response>
  <Assertion ID="_abc123">  <!-- This part is signed -->
    <Subject>victim@company.com</Subject>
  </Assertion>
  <Signature>
    <Reference URI="#_abc123"/>  <!-- Signature covers _abc123 -->
  </Signature>
</Response>

<!-- ATTACKED SAML Response -->
<Response>
  <Assertion>  <!-- INJECTED - unsigned, but SP processes THIS -->
    <Subject>attacker@evil.com</Subject>
  </Assertion>
  <Assertion ID="_abc123">  <!-- Original signed assertion, moved here -->
    <Subject>victim@company.com</Subject>
  </Assertion>
  <Signature>
    <Reference URI="#_abc123"/>  <!-- Signature still valid! -->
  </Signature>
</Response>
```

**Why it works:** The XML signature is valid (it references the original assertion by ID), but the SP reads the *first* assertion it finds — which is the attacker's unsigned one.

#### ✅ Fix:
- Validate that the signed element is the **same** element you're reading claims from
- Use well-tested SAML libraries (don't roll your own XML parsing)
- Reject responses with multiple assertions

---

### 4.2 SAML Assertion Replay Attack

Attacker intercepts a valid SAML assertion and **replays** it later to impersonate the user.

```
Timeline:
10:00 AM - User legitimately logs in, SAML assertion sent
10:01 AM - Attacker intercepts the assertion (via network sniffing/logs)
10:15 AM - Attacker replays the same assertion to the SP
         - SP accepts it because it's still "valid"
```

#### ✅ Fix:

```python
# Python - Check assertion conditions
def validate_saml_assertion(assertion):
    now = datetime.utcnow()
    
    # 1. Check NotBefore and NotOnOrAfter timestamps
    not_before = parse_datetime(assertion.conditions.not_before)
    not_after = parse_datetime(assertion.conditions.not_on_or_after)
    
    if now < not_before or now >= not_after:
        raise SecurityError("Assertion expired or not yet valid")
    
    # 2. Check InResponseTo matches our original request ID
    if assertion.in_response_to != stored_request_id:
        raise SecurityError("Assertion doesn't match our request")
    
    # 3. One-time use: Track used assertion IDs
    if redis_client.exists(f"used_assertion:{assertion.id}"):
        raise SecurityError("Assertion already used (replay detected!)")
    
    redis_client.setex(
        f"used_assertion:{assertion.id}",
        timedelta(hours=1),  # Keep for assertion lifetime
        "used"
    )
```

---

### 4.3 XXE in SAML Parsing

SAML uses XML, which means **XML External Entity injection** is possible if the parser isn't hardened.

```xml
<!-- Malicious SAML Response with XXE -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<Response>
  <Assertion>
    <Subject>&xxe;</Subject>  <!-- Reads server files! -->
  </Assertion>
</Response>
```

#### ✅ Fix in each language:

**Java:**
```java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

**PHP:**
```php
libxml_disable_entity_loader(true);  // PHP < 8.0
// PHP 8.0+ has it disabled by default
```

**Python:**
```python
from defusedxml.ElementTree import parse  # Safe!
# NEVER use: from xml.etree.ElementTree import parse
```

---

### OAuth 2.0 / OIDC Vulnerabilities

---

### 4.4 Open Redirect / Authorization Code Interception

If the SP doesn't strictly validate `redirect_uri`, an attacker can steal the authorization code.

```
// VULNERABLE - Loose redirect_uri validation
https://idp.com/authorize?
  client_id=legit_app&
  redirect_uri=https://legit-app.com.evil.com/callback  ← ATTACKER DOMAIN!
  &response_type=code
  &scope=openid profile

// The IdP redirects the auth code to the attacker's server!
https://legit-app.com.evil.com/callback?code=STOLEN_AUTH_CODE
```

#### ✅ Fix:

```javascript
// Node.js - Strict redirect_uri validation
const ALLOWED_REDIRECTS = [
  'https://myapp.com/callback',
  'https://myapp.com/auth/callback'
];

app.get('/authorize', (req, res) => {
  const redirectUri = req.query.redirect_uri;
  
  // EXACT match only - no regex, no substring, no wildcards
  if (!ALLOWED_REDIRECTS.includes(redirectUri)) {
    return res.status(400).json({ error: 'Invalid redirect_uri' });
  }
  // ... proceed with auth
});
```

> Also use **PKCE** (Proof Key for Code Exchange) to prevent code interception even if redirect is compromised.

---

### 4.5 JWT Token Vulnerabilities in OIDC

#### Attack A: Algorithm "none" bypass

```javascript
// VULNERABLE - Attacker changes JWT header to alg:"none"
// Original token header: {"alg": "RS256", "typ": "JWT"}
// Attacker changes to:  {"alg": "none", "typ": "JWT"}

// Weak library accepts it without signature verification!
const decoded = jwt.verify(token, '', { algorithms: ['none', 'RS256'] });
// ❌ This accepts unsigned tokens!

// ✅ FIX: Explicitly specify allowed algorithms
const decoded = jwt.verify(token, publicKey, {
  algorithms: ['RS256'],  // ONLY RS256, never 'none'
  issuer: 'https://your-idp.com',
  audience: 'your-client-id'
});
```

#### Attack B: RS256 → HS256 Algorithm Confusion

```
Exploit:
1. IdP signs tokens with RS256 (asymmetric: private key signs, public key verifies)
2. Attacker knows the PUBLIC key (it's public!)
3. Attacker creates a new JWT, sets alg to HS256 (symmetric)
4. Attacker signs the JWT using the PUBLIC key as the HMAC secret
5. If the SP accepts HS256, it uses the same PUBLIC key to verify
6. Signature matches! Attacker forged a valid token.
```

**✅ Fix:** Always enforce the expected algorithm on the *verifier* side. Never let the token dictate which algorithm to use.

---

### 4.6 Insecure Token Storage

Where you store the SSO token matters **hugely**:

```
❌ localStorage  → Accessible by ANY JavaScript on the page (XSS = game over)
❌ sessionStorage → Same problem, just cleared on tab close  
❌ URL parameters → Leaked in referrer headers, browser history, logs
⚠️ Regular cookie → Sent automatically (CSRF risk) but ok if configured right
✅ HttpOnly + Secure + SameSite=Strict cookie → BEST for web apps
```

```javascript
// ✅ Node.js - Secure token cookie
res.cookie('sso_token', token, {
  httpOnly: true,    // JavaScript can't read it (XSS protection)
  secure: true,      // Only sent over HTTPS
  sameSite: 'Strict', // Not sent in cross-site requests (CSRF protection)
  maxAge: 3600000,   // 1 hour expiry
  domain: '.company.com',
  path: '/'
});
```

---

### Kerberos Vulnerabilities

---

### 4.7 Kerberoasting

Attacker requests service tickets for service accounts, then cracks them **offline** — because service tickets are encrypted with the service account's password hash.

```
Attack Flow:
1. Attacker has ANY valid domain user account (even low-privilege)
2. Requests TGS tickets for service accounts (SPN enumeration)
3. Extracts the encrypted ticket data
4. Cracks offline with hashcat/John — no lockout, no detection
5. If the service account has a weak password → cracked in minutes
6. Many service accounts have admin privileges → domain compromise
```

#### ✅ Fix:
- Use **Group Managed Service Accounts (gMSA)** — auto-rotating 240-char passwords
- Set service account passwords to 25+ random characters
- Monitor for mass TGS requests from a single user
- Apply AES256 encryption (harder to crack than RC4)

---

### 4.8 Golden Ticket Attack

If an attacker compromises the **KRBTGT** account (the KDC's master key), they can forge **any** Kerberos ticket for **any** user — including Domain Admin.

```
Attack Flow:
1. Attacker gains access to a domain controller
2. Extracts the KRBTGT password hash (e.g., via DCSync or ntds.dit)
3. Uses Mimikatz to forge a TGT for any user:
   mimikatz # kerberos::golden /user:Administrator 
     /domain:corp.com /krbtgt:<HASH> /sid:<DOMAIN_SID>
4. This forged TGT is valid for 10 YEARS by default
5. Attacker has persistent, undetectable domain admin access
```

#### ✅ Fix:
- Reset the KRBTGT password **twice** (it keeps history of 1)
- Minimize who can access domain controllers
- Monitor for TGTs with abnormally long lifetimes
- Use **Privileged Access Workstations** for DC administration

---

### 4.9 Pass-the-Ticket (PtT)

Attacker steals a Kerberos ticket from memory on a compromised machine and uses it on another machine — no password needed.

```
1. Attacker compromises workstation where admin is logged in
2. Extracts Kerberos tickets from memory (Mimikatz sekurlsa::tickets)
3. Injects the stolen ticket into their own session
4. Now has the admin's Kerberos identity on the network
```

#### ✅ Fix:
- Enable **Credential Guard** on Windows 10/11
- Limit admin logins to only designated admin workstations
- Set short TGT lifetimes (4 hours instead of 10)
- Monitor for ticket re-use from different IPs

---

### Cross-Protocol SSO Vulnerabilities

---

### 4.10 SSO Session Fixation

Attacker pre-creates a session on the IdP and tricks the victim into authenticating with that session.

```
1. Attacker starts SSO login flow → gets a session ID from IdP
2. Attacker sends victim a crafted link with that session ID
3. Victim authenticates (enters password) on the IdP
4. The IdP associates the victim's identity with attacker's session
5. Attacker now has an authenticated session as the victim!
```

#### ✅ Fix:

**Java (Spring):**
```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.sessionManagement()
        .sessionFixation().newSession()  // Create entirely new session
        // OR .migrateSession()  // Copy attributes to new session
}
```

**PHP:**
```php
session_start();
// ... authenticate user ...
session_regenerate_id(true);  // true = delete old session
```

---

### 4.11 Insufficient Logout (Single Logout Failure)

User logs out of one app but remains logged in to all other SSO-connected apps.

```
Scenario:
1. User is logged into Gmail, Google Drive, YouTube (via Google SSO)
2. User clicks "Logout" on Gmail
3. Gmail clears its local session ✔️
4. But Google Drive and YouTube still have valid sessions ❌
5. If someone accesses the computer, they're still logged into Drive + YouTube
```

#### Types of SSO Logout:
- **SAML SLO (Single Logout):** IdP sends LogoutRequest to ALL SPs — complex, often broken
- **OIDC Back-Channel Logout:** IdP sends logout tokens to SP backend endpoints
- **OIDC Front-Channel Logout:** IdP loads hidden iframes to each SP's logout URL

#### ✅ Secure Logout Implementation:

```javascript
// Node.js - Proper SSO logout
app.post('/logout', async (req, res) => {
  // 1. Clear LOCAL session
  req.session.destroy();
  
  // 2. Clear SSO cookies
  res.clearCookie('sso_token', { domain: '.company.com' });
  
  // 3. Revoke tokens at IdP (OIDC)
  await fetch('https://idp.com/oauth/revoke', {
    method: 'POST',
    body: new URLSearchParams({
      token: req.session.access_token,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET
    })
  });
  
  // 4. Redirect to IdP's logout endpoint
  res.redirect('https://idp.com/logout?post_logout_redirect_uri=https://myapp.com');
});
```

---

### 4.12 Account Linking / Email Confusion Attacks

When multiple SSO providers are supported, attackers exploit how accounts are linked.

```
Attack Flow:
1. App supports "Login with Google" AND "Login with GitHub"
2. Attacker creates a GitHub account with victim's email address
   (GitHub doesn't always verify email!)
3. Attacker clicks "Login with GitHub" on the target app
4. App sees the email, links it to the victim's existing account
5. Attacker now has access to victim's account!
```

#### ✅ Fix:
- NEVER auto-link accounts based solely on email
- Require email **verification** from the IdP (check `email_verified` claim in OIDC)
- If linking SSO to existing account, require current password or MFA confirmation
- Show users which SSO providers are linked to their account

---

## 5. SSO Security Best Practices Checklist

### Identity Provider (IdP) Security
- [ ] Enforce MFA on the IdP (this is the crown jewel!)
- [ ] Implement account lockout after failed attempts
- [ ] Monitor for anomalous login patterns (geo, time, device)
- [ ] Use strong session timeouts (idle + absolute)
- [ ] Log ALL authentication events for audit

### Token/Assertion Security
- [ ] Always validate signatures (RSA-2048+ or ECDSA P-256+)
- [ ] Check `issuer`, `audience`, `expiration` on EVERY token
- [ ] Use short token lifetimes (access: 15min, refresh: 8hr)
- [ ] Implement token revocation for logout & compromise
- [ ] Track used assertion IDs to prevent replay

### Transport Security
- [ ] HTTPS everywhere — no exceptions
- [ ] HSTS headers with long max-age
- [ ] Strict `redirect_uri` validation (exact match only)
- [ ] Use `state` parameter to prevent CSRF in OAuth flows
- [ ] Implement PKCE for all OAuth flows (not just mobile!)

### Logout & Session
- [ ] Implement Single Logout (SLO) across all SPs
- [ ] Revoke tokens at IdP on logout
- [ ] Clear all session data and cookies
- [ ] Regenerate session IDs after authentication

### Monitoring
- [ ] Alert on token with abnormal lifetime
- [ ] Alert on authentication from new geo/device
- [ ] Alert on mass service ticket requests (Kerberoasting)
- [ ] Log and audit all SSO assertion failures

---

## 6. Vulnerability Summary Matrix

| Vulnerability | SAML | OIDC | Kerberos | Impact |
|---|:---:|:---:|:---:|---|
| XML Signature Wrapping | ⬤ | | | Critical |
| XXE Injection | ⬤ | | | Critical |
| Assertion Replay | ⬤ | ⬤ | | High |
| Token Alg Confusion | | ⬤ | | Critical |
| Open Redirect | | ⬤ | | High |
| Insecure Token Storage | | ⬤ | | High |
| Kerberoasting | | | ⬤ | High |
| Golden Ticket | | | ⬤ | Critical |
| Pass-the-Ticket | | | ⬤ | High |
| Session Fixation | ⬤ | ⬤ | | High |
| Logout Failure | ⬤ | ⬤ | ⬤ | Medium |
| Account Linking | | ⬤ | | Critical |

---

> **Key Takeaway:** SSO concentrates trust in the IdP — so the IdP must be your most hardened, monitored, and protected system.

---

*Part of the Secure Coding 365 program — Zero to Hero in 365 Days*
