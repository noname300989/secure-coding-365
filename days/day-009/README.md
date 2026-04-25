# Day 9: PHP Setup & Security Configuration

**Phase:** Programming Foundations & Setup  
**Module:** PHP Foundations  
**Language:** PHP  
**Date:** 2026-04-25  

---

## 🎯 What You'll Learn

- Why `php.ini` is your first and most critical security boundary
- Which PHP default settings are dangerously permissive
- How to configure `error_reporting`, `display_errors`, `disable_functions`, `expose_php`, and session security
- The difference between development and production PHP configs
- Real-world CVEs caused by misconfigured PHP installations

---

## 🌍 Real-World Context

PHP runs ~77% of the web: WordPress, Drupal, Laravel, Magento. Misconfigured PHP is one of the most exploited attack vectors.

**CVE-2019-11043** — PHP-FPM + nginx path info misconfiguration → unauthenticated RCE on Nextcloud, WordPress. CVSS 9.8.  
**CVE-2012-1823** — PHP-CGI argument injection via `cgi.force_redirect = Off` → source disclosure or RCE on millions of shared hosting servers.  
**Countless breaches** via `display_errors = On` in production, leaking DB names, file paths, and stack traces.

> **Security insight:** PHP ships with development-friendly defaults. Your job is to override them before production.

---

## ⚠️ Vulnerable Configuration (DON'T use in production)

See: [`code/dangerous-defaults.ini`](code/dangerous-defaults.ini)

**Critical vulnerabilities in default config:**
- `expose_php = On` → PHP version fingerprinting → targeted CVE exploitation
- `display_errors = On` → CWE-209: Information Exposure via error messages (DB names, file paths, credentials)
- `allow_url_include = On` → Remote File Inclusion (RFI) attacks → full RCE
- `disable_functions =` (empty) → Attackers can call `exec()`, `system()`, `shell_exec()` for OS command execution
- `session.cookie_httponly = 0` → XSS can steal session cookies → account takeover
- `memory_limit = -1` → No resource limit → Denial of Service attacks

---

## ✅ Secure Configuration

See: [`code/hardened-production.ini`](code/hardened-production.ini)

**Key security improvements:**
- `expose_php = Off` — No version header leakage
- `display_errors = Off` + `log_errors = On` — Errors go to protected log, not browser
- `disable_functions = exec,passthru,shell_exec,system,...` — Post-exploitation firewall
- `allow_url_fopen = Off`, `allow_url_include = Off` — Blocks SSRF and RFI
- Full session hardening: httponly, secure, strict_mode, samesite
- `open_basedir` — PHP restricted to specific directories

---

## Runtime Verification

See: [`code/SecurityConfigCheck.php`](code/SecurityConfigCheck.php)

Always verify settings at runtime — `php.ini` can be overridden by `.htaccess` or `ini_set()` calls in code.

---

## 💡 Key Takeaways

1. **PHP's defaults are for development, not production.** You must explicitly harden php.ini.
2. **`display_errors = Off` is non-negotiable.** Use `log_errors = On` with a protected log file instead (CWE-209).
3. **`disable_functions` is your post-exploitation firewall.** Disabling OS command functions limits attacker capability even after RCE.
4. **Session security settings prevent XSS cookie theft and session fixation.** `httponly`, `secure`, `use_strict_mode`, `samesite` — all must be On.
5. **Maintain separate dev/prod configs.** Never promote development settings to production.

---

## 🏋️ Mini Challenge

You've inherited a legacy PHP app on shared hosting (no root). You can only use `.htaccess` and `ini_set()`.

1. Write a `.htaccess` that sets `display_errors Off`, `expose_php Off`, and `session.cookie_httponly 1`
2. Write `bootstrap.php` that enforces security settings via `ini_set()`, sets secure session cookie params, and installs a safe exception handler
3. **Bonus:** When does `ini_set()` NOT work? Research `PHP_INI_SYSTEM` vs `PHP_INI_ALL` changeable modes

See: [`code/ChallengeBootstrap.php`](code/ChallengeBootstrap.php)

---

## ❓ Quick Quiz

**Q1.** An attacker sees `X-Powered-By: PHP/8.1.2` in response headers. Which setting caused this?
- ✅ **a) `expose_php = On`** — enables fingerprinting; attacker targets known CVEs
- b) `display_errors = On`
- c) `phpinfo()` on every page
- d) `error_reporting = E_ALL`

**Q2.** Which setting directly enables Remote File Inclusion (RFI) attacks?
- a) `allow_url_fopen = On`
- ✅ **b) `allow_url_include = On`** — allows including remote URLs as executable code
- c) `file_uploads = On`
- d) `open_basedir` not set

**Q3.** Sessions are being stolen via XSS despite using HTTPS. Which setting is most likely missing?
- a) `session.use_strict_mode = 1`
- b) `session.cookie_secure = 1`
- ✅ **c) `session.cookie_httponly = 1`** — prevents JS from accessing session cookies
- d) `session.cookie_samesite = Strict`

---

## 📚 References

- [PHP ini directives reference](https://www.php.net/manual/en/ini.list.php)
- [OWASP PHP Configuration Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/PHP_Configuration_Cheat_Sheet.html)
- [CIS PHP Benchmark](https://benchmarks.cisecurity.org/)
- [PHP ini changeable modes](https://www.php.net/manual/en/configuration.changes.modes.php)
- CWE-209: Information Exposure Through an Error Message
- CVE-2019-11043: PHP-FPM RCE via path info
- CVE-2012-1823: PHP-CGI argument injection
