# Day 12: PHP Strings & Output Encoding — Defeating XSS at the Source

**Phase:** Programming Foundations & Setup  
**Module:** PHP Foundations  
**Language:** PHP  
**CWE:** CWE-79 (Cross-site Scripting)  
**CVE Context:** Samy Worm (2005), British Airways breach (2018), Yahoo Mail XSS (CVE-2019-14061 range)

---

## What You'll Learn

- How PHP handles strings and why output encoding is the first line of defense
- The difference between `htmlspecialchars()` and `htmlentities()` — and when to use each
- Context-aware encoding: HTML, HTML attributes, JavaScript, URLs, and CSS all need *different* escaping
- How XSS attacks work in practice (and how attackers chain them into account takeovers)
- Secure patterns you can adopt on Day 1 of any PHP project

---

## Real-World Context

Cross-Site Scripting (XSS) has been in the OWASP Top 10 for over 20 years. It's not because developers are careless — it's because raw string concatenation feels natural, and the danger is invisible until an attacker exploits it.

**Famous XSS incidents:**
- **Samy Worm (2005)** — A MySpace XSS propagated to 1 million profiles in under 24 hours. It self-replicated by injecting JavaScript that added Samy Kamkar as a friend and cloned the payload to every visitor's profile.
- **British Airways (2018)** — Attackers injected a 22-line JavaScript skimmer onto the payment page via a compromised third-party script. 500,000 customers had card details stolen. £183M GDPR fine.
- **Yahoo Mail XSS (CVE-2019 range)** — Persistent XSS in Yahoo Mail allowed attackers to read email content, forward emails, and install persistent backdoors simply by sending a crafted email.

---

## The Encoding Context Map

| Context | Function to use |
|---------|----------------|
| HTML body text | `htmlspecialchars($v, ENT_QUOTES\|ENT_SUBSTITUTE, 'UTF-8')` |
| HTML attributes | `htmlspecialchars($v, ENT_QUOTES\|ENT_SUBSTITUTE, 'UTF-8')` |
| URL query param | `urlencode($v)` |
| Full URL value | Validate against allowlist; use `parse_url()` to inspect |
| JS string | `json_encode($v, JSON_HEX_TAG\|JSON_HEX_APOS\|JSON_HEX_AMP)` |
| CSS value | Reject non-alphanumeric chars; use a safe CSS library |
| SQL | Prepared statements (PDO/MySQLi) — never string concat |

---

## Code Examples

See:
- `vulnerable_profile.php` — all the ways XSS slips in
- `secure_profile.php` — context-aware encoding done right
- `htmlspecialchars_vs_htmlentities.php` — function comparison deep dive
- `search_results_challenge.php` — mini challenge (fix all 7 XSS issues)

---

## Key Takeaways

1. **Never echo raw user input** — always encode before output. Trust no source.
2. **Context matters more than anything** — HTML-encoding inside a `<script>` tag is useless. Use `json_encode()` with hex flags for JavaScript context.
3. **`ENT_QUOTES | ENT_SUBSTITUTE` is your default** — always include both flags in `htmlspecialchars()`.
4. **Encode on OUTPUT, not on INPUT** — store raw data, encode when displaying. Same data may go to HTML, JSON APIs, PDFs — each needs different encoding.
5. **Allowlist redirect URLs, never blocklist** — `javascript:` protocol XSS bypasses all HTML encoding.

---

## Quick Quiz Answers

1. **B** — `htmlspecialchars($name, ENT_QUOTES, 'UTF-8')` for HTML title context
2. **B** — `json_encode()` with `JSON_HEX_*` flags for JavaScript string context
3. **B** — `javascript:` protocol isn't blocked by htmlspecialchars; validate URL scheme

---

## Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [PortSwigger XSS Labs](https://portswigger.net/web-security/cross-site-scripting)
- [PHP Manual — htmlspecialchars()](https://www.php.net/htmlspecialchars)
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html)
