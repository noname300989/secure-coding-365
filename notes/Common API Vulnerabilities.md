1. Missing Authentication
CVE‑2021‑22986 – F5 BIG‑IP Remote Code Execution (RCE) due to an unauthenticated API endpoint that allowed arbitrary configuration changes.

Why it matters
Any user who can reach the endpoint can read or modify configuration, inject code, or create new accounts.

Mitigation
Require a signed OAuth 2.0 Bearer token or API key on every request.
Enforce HTTPS to protect the token in transit.
Rotate secrets regularly and revoke compromised keys.
Use a Web Application Firewall (WAF) to block suspicious patterns.
2. Broken Authentication
CVE‑2020‑1472 – Netlogon Remote Protocol (MS‑RPC) authentication bypass that allowed attackers to create a computer account on a domain controller.

Why it matters
An attacker can impersonate a domain controller, gain domain‑wide privileges, and pivot laterally.

Mitigation
Use strong, rotating secrets for token issuance.
Store passwords with Argon2id (≥ 16 bytes salt, 2 million iterations).
Issue short‑lived access tokens (15 min) and long‑lived refresh tokens (7 days).
Implement MFA for all privileged endpoints.
3. Excessive Data Exposure
CVE‑2021‑44228 – Log4j Remote Code Execution via JNDI lookup. The vulnerability was triggered when an attacker could inject a malicious string into a log message that was later parsed by Log4j.

Why it matters
If an API logs user‑supplied data without sanitization, the attacker can execute arbitrary code on the server.

Mitigation
Return only the fields required by the consumer (DTO projection).
Mask or remove sensitive fields (credit_card_number, cvv).
Use a strict schema validation library (e.g., pydantic, Joi).
Audit all logs for unexpected JNDI lookups.
4. Lack of Resources and Rate Limiting
Why it matters
Unlimited login attempts or API calls enable credential stuffing, brute‑force, and DoS attacks.

Mitigation
Apply per‑IP and per‑API‑key rate limits (e.g., 100 req/min).
Use a token‑bucket algorithm for burst protection.
Lock accounts after 5 consecutive failures for 15 minutes.
Monitor traffic patterns and trigger alerts on anomalies.
5. Broken Object Level Authorization
Why it matters
An attacker can access or modify resources that belong to other users (IDOR).

Mitigation
Verify ownership on every request (resource.owner_id == user.id).
Use policy‑based access control libraries (Casbin, OPA).
Enforce row‑level security in the database (PostgreSQL policies).
Log all access attempts and review for violations.
6. Injection (SQL, NoSQL, OS)
Why it matters
Untrusted input can alter query logic, leak data, or execute system commands.

Mitigation
Use parameterized queries or prepared statements.
Avoid string concatenation for SQL.
Validate and sanitize all user input.
Working Code Examples
Python (SQLAlchemy)
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

engine = create_engine("postgresql://user:pass@localhost/db")
Session = sessionmaker(bind=engine)

def get_user_by_email(email: str):
    # Parameterized query – no risk of injection
    sql = text("SELECT id, name, email FROM users WHERE email = :email")
    with Session() as session:
        result = session.execute(sql, {"email": email}).fetchone()
    return result

# Usage
user = get_user_by_email("alice@example.com")
print(user)
Node.js (pg-promise)
const pgp = require('pg-promise')();
const db = pgp('postgres://user:pass@localhost:5432/db');

async function getUserByEmail(email) {
    // Parameterized query – safe from injection
    const sql = 'SELECT id, name, email FROM users WHERE email = $1';
    const user = await db.oneOrNone(sql, [email]);
    return user;
}

// Usage
getUserByEmail('bob@example.com')
    .then(user => console.log(user))
    .catch(err => console.error(err));
7. Cross‑Site Scripting (XSS) – Full Description & Mitigation
What It Is
XSS occurs when an attacker injects malicious scripts into content that is later rendered in a victim’s browser. In APIs, XSS can happen when user‑supplied data is returned in JSON, HTML, or other formats without proper escaping, and the client renders it directly.

Types
Type	Description	Typical Trigger
Reflected XSS	Payload is part of the request (e.g., query string) and immediately reflected in the response.	/search?q=<script>alert(1)</script>
Stored XSS	Payload is persisted (database, file) and served to any user who requests the resource.	Comment section storing <script>…</script>
DOM‑based XSS	Client‑side JavaScript manipulates the DOM using untrusted data.	location.hash used without sanitization
Why It Matters
Steals session cookies or tokens.
Executes malicious actions on behalf of the user.
Can lead to full account takeover.
Real‑world Example
CVE‑2021‑44228 (Log4j) was triggered by an attacker inserting a JNDI lookup string into a log message that was later parsed and executed. The payload effectively performed a reflected XSS‑style injection on the server side, allowing remote code execution.

Mitigation Steps (API‑Level)
Never Trust Input
Treat all incoming data as untrusted.
Validate against a whitelist (e.g., allow only alphanumeric usernames).
Escape Output
For JSON responses, use a JSON serializer that escapes control characters (\u2028, \u2029).
For HTML responses, use a templating engine that auto‑escapes (Jinja2, Handlebars).
Content Security Policy (CSP)
Add Content-Security-Policy: default-src 'self'; script-src 'self' to responses.
Disallow inline scripts (script-src 'self' 'nonce-<random>').
HTTPOnly & Secure Cookies
Set HttpOnly flag to prevent JavaScript access.
Set Secure flag to restrict cookies to HTTPS.
Use a WAF
Deploy a WAF rule set that blocks common XSS payloads (e.g., OWASP ModSecurity Core Rule Set).
Regular Audits
Run automated security scanners (OWASP ZAP, Burp Suite).
Perform manual code reviews for any dynamic content rendering.
Example: Escaping JSON in Python
import json

def safe_json_response(data):
    # json.dumps automatically escapes control characters
    return json.dumps(data, ensure_ascii=False)

payload = {"message": "<script>alert('XSS')</script>"}
print(safe_json_response(payload))
# {"message":"<script>alert('XSS')</script>"}
Example: CSP Header in Express (Node.js)
app.use((req, res, next) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self'; object-src 'none';"
    );
    next();
});
8. Insecure Cryptographic Storage
Why it matters
Storing secrets in plaintext or using weak algorithms (MD5, SHA‑1) allows attackers to recover passwords or tokens.

Mitigation
Use AES‑256 in GCM mode for symmetric data.
Store keys in a Hardware Security Module (HSM) or cloud KMS.
Rotate keys quarterly and re‑encrypt data.
9. Unvalidated Redirects
Why it matters
An attacker can redirect users to phishing sites by manipulating the redirect_uri parameter.

Mitigation
Whitelist allowed redirect URIs.
Validate against a stored list before redirecting.
Use state parameter to prevent CSRF.
10. Summary Checklist
Area	Key Controls	Tools / Libraries
Authentication	OAuth 2.0 / JWT, HTTPS, MFA	Auth0, Keycloak
Authorization	RBAC/ABAC, ownership checks, OPA	Casbin, OPA
Input Validation	Whitelisting, pydantic, Joi	pydantic, Joi
Output Escaping	JSON serializer, CSP, HttpOnly cookies	Express, Flask
Rate Limiting	Token bucket, per‑IP limits	NGINX, Kong
Logging	Sanitized logs, audit trails	ELK, Loki
Cryptography	AES‑256 GCM, HSM	AWS KMS, Azure Key Vault
Redirects	Whitelist, state	OAuth libraries
Implementing the controls above, coupled with continuous scanning and code reviews, will harden your API against the most common and high‑impact vulnerabilities identified in the CVE list and industry best practices.
