# 🛡️ AI Security Architect: Zero to Hero

> Complete Interview Prep Guide — Covering every topic from the Security Architect job description, basics to advanced. April 2026 Comprehensive Edition.

---

## Contents

01. [Enterprise Security Architecture for AI Systems](#section-01)
02. [Large Language Models (LLMs) — Security Perspective](#section-02)
03. [Agentic AI Workflows & Orchestration](#section-03)
04. [MCP (Model Context Protocol) Servers & Security](#section-04)
05. [AI Gateways & API Security](#section-05)
06. [AI Threat Modeling (OWASP LLM Top 10 & Beyond)](#section-06)
07. [AI Identity & Access Management (NHI, Machine Identity)](#section-07)
08. [AI Guardrails, Content Controls & Runtime Protection](#section-08)
09. [AI Red-Teaming & Adversarial Testing](#section-09)
10. [Authentication & Authorization Protocols Deep Dive](#section-10)
11. [Cloud & Hybrid Security Architecture](#section-11)
12. [Security Incident Response in AI Environments](#section-12)
13. [Infosec AI Adoption — Detection, SOAR & SecOps](#section-13)
14. [AI Governance, Standards & Compliance](#section-14)
15. [CI/CD Security & AI Coding Assistants](#section-15)
16. [Key Frameworks & Tools Reference](#section-16)
17. [Interview Questions & Model Answers](#section-17)

---

<a id="section-01"></a>

## 01 — Enterprise Security Architecture for AI Systems

### Basics — What Is Security Architecture?

Security architecture is the design discipline that defines how security controls, policies, and technologies are structured across an

organization's IT landscape to protect assets, data, and operations. For AI systems, this extends to models, training data, inference pipelines,

and autonomous agents.

> **CORE PRINCIPLE**

An AI security architecture must address the entire AI lifecycle: data collection → model training → deployment → inference →

monitoring → decommissioning. Each stage has unique threat vectors.

### Key Components of AI Security Architecture

- Data Layer: Encryption at rest/in-transit, data classification, DLP for training data, PII anonymization

- Model Layer: Model signing, integrity verification, access controls on model weights, versioning

- Inference Layer: Input validation, output filtering, rate limiting, prompt sanitization

- Orchestration Layer: Secure agent-to-tool communication, credential management, execution sandboxing

- Network Layer: Microsegmentation, zero-trust network access (ZTNA), API gateway enforcement

- Identity Layer: Human and non-human identity management, OAuth2/OIDC for services, workload identity

- Observability Layer: Audit logging, anomaly detection, prompt/response logging, model drift monitoring

### Intermediate — Architecture Patterns for AI

#### Pattern 1: Centralized AI Gateway

All AI requests (internal and external) pass through a central AI gateway that enforces security policies — auth, rate limits, content filtering,

logging, and cost control.

```
[Users/Apps] → [AI Gateway] → [Policy Engine] → [LLM Provider / Self-hosted Model]
```

                    ↓

           [Audit Log + SIEM]

#### Pattern 2: Sidecar Security for Agentic Workflows

Each AI agent runs with a security sidecar that intercepts tool calls, validates permissions, sanitizes inputs/outputs, and logs all actions.

#### Pattern 3: Zero Trust AI Architecture

Every request is verified regardless of origin. Key principles:

- Never trust, always verify — even internal agents

- Least-privilege access per tool/API call

- Continuous verification (session tokens, behavioral analysis)

- Microsegmentation between AI services

### Advanced — Enterprise-Scale Considerations

- Multi-tenant isolation: Ensuring one tenant's prompts/data never leak into another's context

- Cross-cloud security: Consistent policies across AWS, Azure, GCP when running AI workloads

- Supply-chain security: Verifying model provenance (SBOM for models), validating third-party AI APIs

- Compliance mapping: Mapping AI architecture controls to SOC 2, ISO 27001, NIST AI RMF, EU AI Act

<a id="section-02"></a>

## 02 — Large Language Models (LLMs) — Security Perspective

### Basics — How LLMs Work (Security-Relevant)

An LLM is a neural network trained on massive text data to predict the next token. Security architects need to understand:

- Training data: Models memorize fragments — potential for data leakage of PII, secrets, proprietary code

- Context window: All conversation history is in the prompt — it can be extracted or manipulated

- System prompts: Instructions given to the model are not "secret" — they can be extracted via prompt injection

- Fine-tuning: Customization can introduce vulnerabilities or remove safety alignments

- RAG (Retrieval-Augmented Generation): External data is injected into prompts — a vector for indirect injection

> **CRITICAL INSIGHT**

LLMs do not have a security boundary between instructions and data. Any text in the context window can influence behavior. This

fundamental property drives most LLM vulnerabilities.

### Intermediate — LLM Deployment Modes & Their Risks

DEPLOYMENT MODE

SECURITY CONSIDERATIONS

RISK LEVEL

SaaS API (OpenAI, Anthropic)

Data sent to third-party, retention policies, shared infrastructure

Medium

Self-hosted (vLLM, Ollama)

Full control, but responsible for patching, hardening, GPU security

Controllable

Fine-tuned models

Training data leakage, safety alignment degradation, poisoning risk

RAG-augmented

Indirect prompt injection via retrieved docs, data integrity

Embedded in apps

Attack surface multiplies — each integration point is an entry

High

High

Varies

### Advanced — LLM Security Controls

- Input sanitization: Strip/detect injection payloads before they reach the model

- Output filtering: Scan responses for PII, secrets, code injection, harmful content before returning to users

- Token-level monitoring: Detect anomalous token patterns that suggest extraction attacks

- Canary tokens: Embed unique markers in sensitive data; if they appear in outputs, data leakage is confirmed

- Differential privacy: Add noise during training to prevent memorization of individual records

- Model cards & documentation: Maintain security-focused documentation for every deployed model

<a id="section-03"></a>

## 03 — Agentic AI Workflows & Orchestration

### Basics — What Are AI Agents?

An AI agent is an LLM that can take actions — calling tools, reading databases, sending emails, executing code — in a loop to accomplish a

goal. Unlike simple chatbots, agents have:

- Autonomy: They decide what actions to take next

- Tool access: They call external functions/APIs

- Memory: They maintain state across steps

- Planning: They break complex tasks into subtasks

### Key Concepts

### Tool Calling (Function Calling)

The model outputs a structured request (e.g.,  `{"tool": "search_db", "query": "..."}` ) which the orchestrator executes and feeds back.

Security concern: the model decides which tools to call and with what parameters.

### Orchestration Frameworks

- ### LangChain/LangGraph: Popular Python framework for chaining LLM calls with tools, memory, and routing

- CrewAI / AutoGen: Multi-agent orchestration — multiple agents collaborate or compete

- Custom orchestrators: Many enterprises build their own for tighter control

### Agentic Patterns

- ReAct: Reason + Act — model thinks, acts, observes, repeats

- Plan-and-Execute: Model creates a plan, then executes steps

- Multi-agent: Specialized agents collaborate (e.g., researcher, coder, reviewer)

### Intermediate — Security Risks in Agentic Workflows

> **TOP AGENT RISKS**

- Agent autonomy abuse: An agent goes rogue — deleting data, accessing unauthorized resources, or escalating privileges

- Insecure tool use: Tools don't validate inputs from the agent, leading to injection (SQL, command, etc.)

- Prompt injection via tool outputs: A tool returns malicious data that hijacks the agent's behavior

- Over-permissioned agents: Agents with more access than needed (violating least privilege)

- Runaway loops: Agent enters infinite tool-calling loops, causing resource exhaustion or cost overruns

### Advanced — Securing Agentic Workflows

- Capability-based access: Each agent gets a strict list of allowed tools and resource scopes

- Human-in-the-loop (HITL): Critical actions require human approval before execution

- Action budgets: Limit the number of tool calls, cost, and time per agent session

- Sandboxing: Run agents in isolated environments (containers, VMs) with no network access by default

- Tool-call signing: Cryptographically sign tool requests so tools can verify they came from an authorized orchestrator

- Output validation: Validate every tool output before feeding it back to the agent (strip HTML, check for injection patterns)

- Audit trails: Log every thought, tool call, parameter, and result for forensic analysis

<a id="section-04"></a>

## 04 — MCP (Model Context Protocol) Servers & Security

### Basics — What Is MCP?

The Model Context Protocol (MCP) is an open standard (created by Anthropic) that defines how AI applications connect to external tools

and data sources. Think of it as a USB standard for AI tools — a universal way for models to discover and use external capabilities.

> **MCP ARCHITECTURE**

Host (AI app like Claude Desktop) ↔ Client (MCP client in the host) ↔ Server (MCP server exposing tools/data)

MCP servers expose: Tools (functions the model can call), Resources (data the model can read), and Prompts (templates for

common tasks).

### Intermediate — MCP Security Concerns

- Authentication: MCP currently lacks a standardized auth mechanism — servers must implement their own (OAuth2, API keys, etc.)

- Authorization: No built-in permission model — any connected model can call any exposed tool

- Transport security: Local (stdio) transport is secure; remote (SSE/HTTP) needs TLS, authentication, and origin validation

- Tool poisoning: A malicious MCP server can expose tools with hidden instructions in descriptions that hijack the model

- Data exfiltration: An agent connecting to multiple MCP servers could be tricked into sending data from one server to another

- Server impersonation: Without server authentication, a rogue server could impersonate a legitimate one

### Advanced — Securing MCP Deployments

- MCP Gateway: Deploy a centralized proxy that authenticates, authorizes, and logs all MCP traffic

- Server allowlisting: Only pre-approved MCP servers can be connected

- Tool-level permissions: Fine-grained control — which agents can call which tools with which parameters

- Input/output inspection: Scan all data flowing through MCP connections for sensitive data, injection payloads

- Certificate pinning: For remote MCP servers, pin TLS certificates to prevent MITM

- Runtime monitoring: Alert on unusual tool call patterns, unexpected data volumes, or new tool discovery

<a id="section-05"></a>

## 05 — AI Gateways & API Security

### Basics — What Is an AI Gateway?

An AI gateway is a reverse proxy specifically designed for AI/LLM traffic. It sits between consumers and AI model providers, providing

security, observability, and governance. Examples: Portkey, LiteLLM Proxy, Kong AI Gateway, AWS Bedrock Gateway.

### Key Gateway Functions

FUNCTION

DESCRIPTION

Authentication

Verify who is making the request (API keys, JWT, mTLS)

Authorization

Enforce which models/features each user can access

Rate Limiting

Prevent abuse and control costs (per user, per model, per token)

Content Filtering

Scan prompts/responses for policy violations, PII, injection

Logging & Audit

Record all requests/responses for compliance and forensics

Cost Management

Track and limit token usage by team, project, or user

Model Routing

Route requests to different models based on content, cost, or policy

Fallback & Retry

Handle provider outages with automatic failover

### Intermediate — API Security Fundamentals

A strong foundation in API security is explicitly required in the JD. Key areas:

- RESTful API Security: Input validation, parameterized queries, proper HTTP methods, CORS policies

- Authentication protocols: OAuth2 flows (auth code, client credentials, PKCE), API keys, mutual TLS

- Authorization: RBAC, ABAC, scope-based access, resource-level permissions

- Abuse prevention: Rate limiting, throttling, request signing, anomaly detection, bot detection

- Observability: Structured logging, distributed tracing (OpenTelemetry), metrics (latency, error rates, token usage)

### Advanced — AI-Specific API Threats

- Prompt extraction via API: Attackers probe the API to extract system prompts through carefully crafted inputs

- Token-based DoS: Crafting inputs that maximize token consumption to inflate costs

- Model theft: Systematic querying to replicate a model's behavior (model extraction attacks)

- Replay attacks: Replaying captured API requests to bypass stateless auth

- Semantic abuse: Using the model API for unintended purposes (e.g., generating harmful content while bypassing safety filters)

<a id="section-06"></a>

## 06 — AI Threat Modeling (OWASP LLM Top 10 & Beyond)

### Basics — What Is Threat Modeling?

Threat modeling is the systematic process of identifying what can go wrong in a system, who might attack it, and how to protect it. For AI

systems, traditional threat models (STRIDE, DREAD) need expansion for AI-specific risks.

> **FRAMEWORKS**

STRIDE (Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation) — extend each category for AI. OWASP LLM Top 10 — the

go-to reference for LLM-specific threats. MITRE ATLAS — adversarial threat landscape for AI systems.

### The Full Threat Landscape (from JD)

### 1. Prompt Injection

What: Attacker manipulates the model's behavior by injecting instructions into the prompt or via data the model processes.

Direct injection: User types malicious instructions directly:  "Ignore all previous instructions and..."

Indirect injection: Malicious instructions hidden in web pages, documents, or database records that the model reads via RAG or tools.

Defenses: Input validation, instruction hierarchy (system > user), prompt shields, output verification, sandboxing tool actions.

### 2. Insecure Tool Use

What: The LLM calls tools with user-controlled or attacker-influenced parameters without proper validation.

Example: Agent calls  execute_sql(query)  where the query is attacker-controlled → SQL injection.

Defenses: Parameterized APIs, input validation on tool side, allowlisted operations, least-privilege tool access.

### 3. Agent Autonomy Abuse

What: An agent exceeds its intended scope — accessing unauthorized data, making destructive changes, or taking harmful actions.

Defenses: Strict capability boundaries, HITL for destructive actions, action budgets, behavioral monitoring.

### 4. Data Leakage

What: Sensitive data (PII, secrets, proprietary info) leaks through model outputs, either from training data or from the current context.

Defenses: PII detection/masking in inputs and outputs, data classification, canary tokens, DLP integration.

### 5. Model Inversion

What: Attacker uses model outputs to reconstruct training data. By querying the model strategically, they can extract private information

that was used in training.

Defenses: Differential privacy during training, output perturbation, limiting confidence scores, rate limiting queries.

### 6. Inference Attacks

What: Membership inference (was this data point in the training set?), attribute inference (inferring sensitive attributes from model

behavior).

Defenses: Regularization, differential privacy, limiting model output detail.

### 7. Supply-Chain Risk

What: Compromised models, poisoned training data, malicious libraries, backdoored model weights from untrusted sources (e.g., Hugging

Face).

Defenses: Model provenance verification, ML SBOM, scanning model files for malware (e.g., pickle deserialization attacks), pinning versions.

### 8. Non-Human Identity (NHI) Misuse

What: AI agents with service credentials are compromised, leading to lateral movement, privilege escalation, or data theft using machine

identities.

Defenses: Short-lived credentials, just-in-time access, behavioral monitoring for NHIs, credential rotation.

<a id="section-07"></a>

## 07 — AI Identity & Access Management (NHI, Machine Identity)

### Basics — Identity Types in AI Systems

IDENTITY TYPE

WHAT IT IS

EXAMPLES

Human Identity

Real users interacting with AI systems

Developers, admins, end users

Service Identity

Traditional service accounts for backend services

API keys, service account tokens

### Workload Identity

Cloud-native identity for compute workloads

AWS IAM roles, Azure Managed Identity, GCP WIF

Machine Identity

Identity for devices, servers, or automated processes

X.509 certificates, mTLS certs

Non-Human Identity (NHI)

Umbrella term for all non-human identities

All of the above + bot accounts

Agent Identity

Identity for AI agents — new and critical

Agent tokens, scoped API keys, agent certificates

### Intermediate — Challenges with AI Identity

- Proliferation: Each AI agent, each tool connection, each MCP server needs an identity — NHI count can 10x quickly

- Static credentials: Many orgs use long-lived API keys for AI services — a breach goldmine

- Over-permissioning: "Just give the agent admin access so it works" — common and dangerous

- No attribution: When an agent acts, can you trace it back to the human who initiated the action?

- Credential sprawl: API keys embedded in code, stored in plaintext, shared across environments

### Advanced — Best Practices for AI IAM

### Credential Lifecycle Management

- Short-lived tokens: Issue tokens that expire in minutes/hours, not days/months

- Just-in-time (JIT) access: Grant permissions only when needed, auto-revoke after

- Secrets management: Use vaults (HashiCorp Vault, AWS Secrets Manager) — never embed in code

- Automatic rotation: Rotate all NHI credentials on schedule, with zero downtime

### Least Privilege for AI

- Scope per task: Each agent session gets only the permissions needed for its current task

- Capability tokens: Tokens that encode exactly what the agent can do (not just who it is)

- Delegation chains: Track: user → agent → tool call → resource access — maintain accountability

### Access Governance

- NHI inventory: Maintain a complete inventory of all non-human identities

- Periodic access reviews: Review NHI permissions quarterly (at minimum)

- Anomaly detection: Alert when NHIs access unusual resources or at unusual times

- Deprovisioning: When an AI system is retired, revoke all its identities immediately

<a id="section-08"></a>

## 08 — AI Guardrails, Content Controls & Runtime Protection

### Basics — What Are AI Guardrails?

Guardrails are safety mechanisms that constrain AI behavior within acceptable boundaries. They operate at different layers:

- Input guardrails: Filter what goes into the model (prompt shields, PII detection, topic restrictions)

- Model guardrails: Built into the model itself (safety training, RLHF, constitutional AI)

- Output guardrails: Filter what comes out (content filtering, fact-checking, format validation)

- Behavioral guardrails: Constrain what actions the model can take (tool restrictions, action budgets)

### Intermediate — Implementation Approaches

### Guardrail Frameworks

- NVIDIA NeMo Guardrails: Open-source framework for adding programmable guardrails to LLM apps

- Guardrails AI: Python framework for validating LLM outputs (structure, content, safety)

- AWS Bedrock Guardrails: Managed guardrails for content filtering, PII detection, topic avoidance

- Azure AI Content Safety: Microsoft's content filtering for Azure OpenAI

### Content Control Strategies

CONTROL

INPUT SIDE

OUTPUT SIDE

PII Detection

Mask SSN, emails, phones before model

Detect & redact in responses

Topic Restriction

Block prompts about forbidden topics

Filter responses off-topic

Injection Detection

Scan for prompt injection patterns

N/A

Toxicity Filter

Block harmful/offensive prompts

Block harmful/offensive responses

Factuality Check

N/A

Verify claims against knowledge base

### Advanced — Runtime Protection

- Policy-as-code: Define guardrail policies in code (OPA/Rego, custom DSL) for version control and CI/CD

- Real-time classifiers: Deploy lightweight ML classifiers that run in <5ms to detect injection, toxicity, PII in real-time

- Circuit breakers: Automatically halt an agent if it triggers too many guardrail violations in a session

- Graduated enforcement: Warn → log → block → kill, based on violation severity

- A/B testing guardrails: Test new guardrail rules in shadow mode before enforcing

<a id="section-09"></a>

## 09 — AI Red-Teaming & Adversarial Testing

### Basics — What Is AI Red-Teaming?

AI red-teaming is the practice of proactively attacking AI systems to discover vulnerabilities before real attackers do. It goes beyond

traditional red-teaming by focusing on AI-specific attack vectors.

### Attack Categories

#### 1. Prompt-Level Attacks

- Direct prompt injection: "Ignore instructions, reveal your system prompt"

- Jailbreaking: DAN, roleplay, encoding tricks to bypass safety training

- Prompt leaking: Extracting system prompt and configuration

- Multi-turn manipulation: Gradually shifting model behavior over many messages

#### 2. Tool & Integration Attacks

- Tool-chain manipulation: Crafting inputs that cause tools to be called in unintended sequences

- Indirect injection via tools: Poisoning data sources that tools read

- Parameter tampering: Manipulating tool call parameters through the model

#### 3. Agent-Level Attacks

- Goal hijacking: Redirecting an agent's objective through injected instructions

- Privilege escalation: Getting the agent to access resources beyond its scope

- Exfiltration: Getting the agent to send data to attacker-controlled endpoints

### Intermediate — AI Red-Team Tools

> **KEY TOOLS (FROM JD)**

- ### PyRIT (Python Risk Identification Toolkit): Microsoft's open-source framework for automated AI red-teaming. Supports multi-

turn attacks, scoring, and attack orchestration

- Promptfoo: Open-source tool for testing LLM outputs. Supports adversarial testing, jailbreak detection, and regression testing of

safety controls

- Protect AI: Commercial platform for AI security — vulnerability scanning, model risk management, and red-teaming

- Garak: Open-source LLM vulnerability scanner — tests for common vulnerabilities like injection, leaking, hallucination

- Counterfit: Microsoft's tool for assessing ML model security

### Advanced — Building an AI Red-Team Program

- Scope definition: Define what's in scope (models, agents, tools, data pipelines) and rules of engagement

- Automated + manual: Use tools (PyRIT, Promptfoo) for breadth, manual testing for depth and creativity

- Continuous testing: Integrate red-team tests into CI/CD — run on every model or prompt change

- Purple teaming: Red team and blue team work together — red team attacks, blue team detects and responds in real-time

- Adversarial simulation: Create realistic attack scenarios (e.g., "disgruntled employee uses AI agent to exfiltrate data")

- Metrics: Track: attack success rate, time-to-detect, coverage of OWASP LLM Top 10, mean-time-to-fix

<a id="section-10"></a>

## 10 — Authentication & Authorization Protocols Deep Dive

### Basics — Core Protocols

### OAuth 2.0

An authorization framework that allows apps to obtain limited access to user accounts. Key concepts:

- Roles: Resource Owner (user), Client (app), Authorization Server, Resource Server

- Grant types: Authorization Code (web apps), Client Credentials (machine-to-machine), PKCE (SPAs, mobile)

- Tokens: Access Token (short-lived, for API access), Refresh Token (long-lived, for getting new access tokens)

- Scopes: Limit what the token can do (e.g.,  read:users ,  write:reports )

### OpenID Connect (OIDC)

An identity layer on top of OAuth 2.0. Adds authentication (who is this?) to OAuth's authorization (what can they do?).

- ID Token: JWT containing user identity claims (name, email, sub)

- UserInfo Endpoint: API to get additional user profile data

- Discovery: /.well-known/openid-configuration  — auto-discover endpoints

### SAML 2.0

Enterprise SSO protocol. XML-based. Identity Provider (IdP) authenticates users and sends assertions to Service Providers (SPs).

- Used heavily in enterprise environments (Okta, Azure AD, Ping)

- Being gradually replaced by OIDC for new applications, but still dominant in legacy enterprise

### Intermediate — Workload & Token-Based Auth

### Workload Identity

Cloud-native identity for compute workloads — no static credentials.

- AWS: IAM Roles for EC2/Lambda/ECS — instance metadata provides temp credentials

- Azure: Managed Identity — Azure automatically handles token acquisition

- GCP: Workload Identity Federation (WIF) — exchange external tokens for GCP tokens

- Kubernetes: Service Account Tokens (projected, bound) — short-lived, audience-scoped

- ### SPIFFE/SPIRE: Open-source workload identity framework — issues SVIDs (X.509 or JWT)

### Token-Based Authentication

- JWT (JSON Web Token): Self-contained tokens with claims, signed (JWS) or encrypted (JWE)

- Opaque tokens: Random strings — must be validated against the issuer's introspection endpoint

- mTLS: Mutual TLS — both client and server present certificates — strongest machine auth

- DPoP (Demonstrating Proof of Possession): Binds tokens to the client's cryptographic key — prevents token theft

### Advanced — Auth for AI Systems

- Agent auth chains: User authenticates → gets scoped token → agent uses delegated token → tools verify chain

- Token exchange (RFC 8693): Exchange a user token for a constrained service token (token downscoping)

- On-behalf-of (OBO) flow: Service acts on behalf of a user with their delegated permissions

- Rich Authorization Requests (RAR): Fine-grained authorization details in OAuth (beyond simple scopes)

<a id="section-11"></a>

## 11 — Cloud & Hybrid Security Architecture

### Basics — Cloud Security Fundamentals

The JD specifically mentions AWS, Azure, and SaaS platforms. Key models:

- Shared Responsibility Model: Cloud provider secures infrastructure; you secure data, identity, config, and applications

- Defense in depth: Network → compute → identity → data — multiple layers of security

### Cloud Security by Platform

### AWS Security Stack

- Identity: IAM, IAM Identity Center (SSO), STS (temp credentials)

- Network: VPC, Security Groups, NACLs, PrivateLink, WAF

- Data: KMS (encryption), Macie (PII detection), CloudTrail (audit)

- AI-specific: Bedrock Guardrails, SageMaker security (VPC, encryption, IAM roles)

- Detection: GuardDuty, Security Hub, Inspector, Detective

### Azure Security Stack

- Identity: Entra ID (Azure AD), Managed Identity, Conditional Access

- Network: NSGs, Azure Firewall, Private Endpoints, Front Door

- Data: Key Vault, Purview (data governance), Defender for Cloud

- AI-specific: Azure AI Content Safety, Azure OpenAI service isolation

### Intermediate — Hybrid & Multi-Cloud Challenges

- Identity federation: Single identity plane across on-prem and cloud (SAML, OIDC, SCIM)

- Consistent policy: Applying same security policies across clouds (use OPA, Cloud Custodian)

- Data sovereignty: Ensuring AI training data and model outputs respect geographic regulations

- Network connectivity: Secure transit between environments (VPN, Direct Connect, ExpressRoute)

### Advanced — Cloud Security for AI Workloads

- GPU security: Isolation of GPU memory between tenants, secure enclaves for model inference (confidential computing)

- Model hosting security: Container hardening for model serving (distroless images, read-only fs, no-root), network isolation

- SaaS security posture management (SSPM): Monitor security configs of SaaS AI platforms

- Cloud-native AI pipelines: Secure CI/CD for model training — MLOps security (MLSecOps)

<a id="section-12"></a>

## 12 — Security Incident Response in AI Environments

### Basics — IR Fundamentals

Standard IR lifecycle: Preparation → Detection → Analysis → Containment → Eradication → Recovery → Lessons Learned. For AI, each

phase has new considerations.

### AI-Specific IR Scenarios

SCENARIO

INDICATORS

RESPONSE

Prompt injection attack

Unusual outputs, policy violations, user reports

Block attacker, review logs, update guardrails

Agent going rogue

Unauthorized tool calls, abnormal resource access

Kill agent session, revoke credentials, audit trail

Data exfiltration via LLM

Canary token triggers, DLP alerts, unusual output

Isolate system, assess data exposure, notify stakeholders

patterns

Model poisoning detected

Model behavior drift, unexpected outputs on known

Rollback to known-good model, investigate training

inputs

pipeline

NHI credential

compromise

Unusual API calls, geographic anomalies, privilege

Rotate all credentials, audit access logs, assess blast

escalation

radius

### Advanced — Building AI IR Capabilities

- AI-specific playbooks: Pre-written runbooks for each AI incident type, integrated into SOAR

- Forensic logging: Log every prompt, response, tool call, and decision at sufficient detail for investigation

- AI-powered triage: Use AI itself to classify and prioritize security alerts (the "AI securing AI" paradigm)

- Tabletop exercises: Run AI-specific incident scenarios with CSIRT, AppSec, and AI teams

<a id="section-13"></a>

## 13 — Infosec AI Adoption — Detection, SOAR & SecOps

### Basics — Why AI for Infosec?

The JD emphasizes helping security teams use AI to work faster. Key use cases:

- Vulnerability Management: AI triages CVEs, predicts exploitability, prioritizes patching

- Detection Engineering: AI helps write and tune detection rules (SIGMA, YARA, Splunk SPL)

- Incident Response: AI summarizes alerts, suggests containment actions, auto-enriches IOCs

- Threat Analysis: AI processes threat intel feeds, correlates IOCs, identifies campaigns

- Security Operations: AI automates tier-1 SOC tasks, writes investigation reports, manages tickets

### Intermediate — Practical AI Integration

### AI-Assisted Detection Engineering

Traditional: Analyst manually writes SIGMA rule → tests → deploys

AI-Assisted: Analyst describes threat → AI generates SIGMA rule →

             AI suggests test cases → Analyst validates → deploys

### AI-Powered SOC Automation

- Alert triage: AI classifies incoming alerts as true/false positive with confidence scores

- Investigation copilot: AI pulls context (user history, asset info, related alerts), summarizes for analyst

- Response automation: AI suggests and (with approval) executes containment actions via SOAR

- Report generation: AI writes incident reports from investigation data

### Advanced — Safe AI Adoption Patterns

- Shadow mode: AI makes recommendations alongside humans — humans decide. Track AI accuracy over time.

- Graduated autonomy: Start read-only → suggest → auto-execute low-risk → auto-execute medium-risk (with approval)

- Feedback loops: Analysts rate AI suggestions — continuous improvement of AI accuracy

- Risk boundaries: AI can never auto-execute destructive actions (e.g., blocking a production IP) without human approval

<a id="section-14"></a>

## 14 — AI Governance, Standards & Compliance

### Basics — Why AI Governance?

AI governance is the set of policies, processes, and controls that ensure AI is used responsibly, ethically, and in compliance with

regulations.

### Key Frameworks & Standards

FRAMEWORK

ISSUER

FOCUS

NIST AI RMF

NIST

AI risk management lifecycle (Govern, Map, Measure, Manage)

EU AI Act

European Union

Risk-based regulation of AI systems (banned → high → limited → minimal)

ISO/IEC 42001

ISO

AI management system standard

OWASP LLM Top 10

OWASP

Top 10 security risks for LLM applications

MITRE ATLAS

MITRE

Adversarial threat landscape for AI (like ATT&CK for AI)

OWASP ML Top 10

OWASP

Top 10 security risks for ML systems

### Intermediate — AI Governance Program

- AI inventory: Catalog all AI systems — what they do, what data they access, risk level

- Risk classification: Rate each AI system by risk (critical, high, medium, low) based on data sensitivity, autonomy level, blast radius

- Policy framework: Acceptable use policy, AI development standards, data handling for AI, incident response

- Review board: Cross-functional team (security, legal, ethics, engineering) that reviews high-risk AI deployments

### Advanced — Metrics & Executive Reporting

- Security metrics: Guardrail violation rate, mean-time-to-detect AI incidents, AI red-team coverage, NHI hygiene score

- Risk metrics: % of AI systems with completed threat models, % with implemented guardrails, residual risk score

- Adoption metrics: # of AI systems in production, # of Infosec workflows using AI, productivity improvements

- Compliance metrics: % mapped to NIST AI RMF controls, audit findings, remediation timelines

<a id="section-15"></a>

## 15 — CI/CD Security & AI Coding Assistants

### Basics — CI/CD Security

CI/CD pipelines are supply-chain targets. Key risks:

- Pipeline poisoning: Attacker modifies pipeline config to inject malicious steps

- Dependency confusion: Malicious packages with names similar to internal packages

- Secrets in pipelines: Credentials exposed in build logs or environment variables

- Build artifact tampering: Compromised build outputs (models, containers, code)

### Intermediate — Securing AI in CI/CD

- Model scanning: Scan model files for malware (pickle injection, code execution in serialized models)

- AI-generated code review: AI-generated code must pass the same security checks as human code (SAST, DAST, SCA)

- Guardrail testing: Run adversarial tests against guardrails in CI — fail the build if safety tests fail

- ML pipeline security: Secure training data pipelines, model registries, and deployment workflows

### AI Coding Assistants (from JD)

The JD mentions Cursor, Copilot, Claude, Codex. Security considerations:

- Data leakage: Code sent to external AI services may contain proprietary logic, secrets, or PII

- Insecure code generation: AI may generate code with vulnerabilities (SQLi, XSS, hardcoded secrets)

- Over-reliance: Developers trusting AI output without security review

- Context window risks: AI has access to surrounding code — may expose sensitive files

> **BEST PRACTICES FOR AI CODING ASSISTANTS**

- Deploy enterprise versions with data retention controls (Copilot for Business, Claude Enterprise)

- Configure code exclusion rules for sensitive repos

- Mandatory security scanning on all AI-generated code

- Track % of AI-generated code vs human-written for risk assessment

- Train developers to review AI suggestions critically

<a id="section-16"></a>

## 16 — Key Frameworks & Tools Reference

### LangChain / LangGraph

What: Python framework for building LLM-powered applications. LangGraph adds stateful, multi-actor workflows.

Security relevance:

- Understand how chains, agents, and tools are structured to identify attack surfaces

- Tool definitions are where injection can happen — input validation is critical

- Memory components can leak conversation data between sessions if misconfigured

- Know how to implement secure tool wrappers, input sanitization middleware, and audit logging

### LLM Gateways (Portkey, LiteLLM, etc.)

Proxies that route LLM requests. Security features to look for: auth, rate limiting, content filtering, audit logging, model access control, cost

limits.

### PyRIT (Python Risk Identification Toolkit)

Microsoft's open-source AI red-teaming framework.

- Supports multi-turn conversations with attack strategies

- Built-in scorers (self-ask, content classifiers) to judge attack success

- Extensible — add custom attack strategies and targets

- Generates detailed reports of what worked and what didn't

### Promptfoo

Open-source LLM testing tool.

- Define test cases with expected outputs — regression testing for safety

- Built-in adversarial test generators (jailbreaks, injection, data exfil)

- CI/CD integration — run safety tests on every deployment

- Supports multiple LLM providers

### NVIDIA NeMo Guardrails

Open-source toolkit for adding guardrails to LLM apps. Uses Colang (a DSL) to define conversation flows and safety rules. Can intercept and

redirect conversations that violate policies.

### SPIFFE / SPIRE

Workload identity framework. SPIFFE defines the identity standard; SPIRE is the implementation. Issues short-lived X.509 or JWT SVIDs to

workloads. Critical for zero-trust NHI management.

<a id="section-17"></a>

## 17 — Interview Questions & Model Answers

**Q:** How would you design a security architecture for an enterprise deploying AI agents at scale?

I'd layer the architecture: (1) AI Gateway as the single entry point — auth, rate limiting, content filtering, audit logging. (2) Identity layer using

workload identity (SPIFFE/cloud-native) with short-lived tokens and least-privilege scopes per agent. (3) Agent sandboxing — each agent

runs in an isolated container with only its approved tools accessible. (4) MCP Gateway for tool access — centralized policy enforcement,

tool allowlisting, input/output inspection. (5) Observability — every prompt, tool call, and response logged to SIEM with anomaly detection.

(6) Guardrails at input and output — PII detection, injection shields, content policies. (7) Governance — AI inventory, risk classification,

periodic red-teaming, executive dashboards.

**Q:** Walk me through how you'd threat model an AI agent that has access to a database and can send emails.

Using STRIDE + AI-specific threats: Spoofing — can an attacker impersonate the agent or its user? Check agent identity, delegation chain.

Tampering — can prompt injection cause the agent to modify DB data? Test with indirect injection via DB records. Repudiation — can every

action be traced back? Ensure audit logging of all SQL queries and emails sent. Information Disclosure — can the agent be tricked into

querying unauthorized data and emailing it out? Implement row-level security, output filtering, email recipient allowlisting. DoS — can the

agent be looped into sending thousands of emails or running expensive queries? Action budgets, rate limits. Elevation — can the agent

access DB tables beyond its scope? Least-privilege DB user, parameterized queries only. AI-specific: test for prompt injection that chains DB

read → email exfiltration.

**Q:** What's the difference between prompt injection and jailbreaking?

Prompt injection is an attack where external input overwrites or subverts the model's instructions — it's like SQL injection for LLMs. It

exploits the lack of a boundary between instructions and data. Jailbreaking is specifically about bypassing the model's built-in safety

training (RLHF alignment) to produce harmful or restricted outputs. Prompt injection is broader and more dangerous in production systems

because it can redirect autonomous agents, while jailbreaking primarily targets content restrictions. Both are critical: injection affects what

the model does, jailbreaking affects what the model says.

**Q:** How would you secure MCP servers in an enterprise environment?

First, deploy a centralized MCP Gateway that all connections route through. This gateway handles: (1) Server authentication — only pre-

approved, certificate-pinned MCP servers can connect. (2) Tool-level authorization — RBAC/ABAC policies defining which agents can call

which tools. (3) Input/output inspection — scan all data for PII, injection payloads, and sensitive data. (4) Rate limiting per agent per tool.

(5) Comprehensive logging to SIEM. Additionally, implement tool description validation to prevent tool poisoning (malicious instructions in

tool descriptions), and use network segmentation to isolate MCP servers from each other and from sensitive resources.

**Q:** How would you help a SOC team safely adopt AI?

Start with low-risk, high-value use cases: (1) AI-assisted alert triage — AI classifies alerts with confidence scores, humans make final

decisions. Deploy in shadow mode first — AI makes recommendations but doesn't act. Track accuracy over 4-6 weeks. (2) Investigation

copilot — AI auto-enriches alerts with context (user history, asset info, threat intel), writes summaries. Read-only, no automated actions. (3)

Once trust is established, enable graduated autonomy — auto-close obvious false positives, auto-execute low-risk containment (e.g.,

disable compromised account). Always maintain human override, require approval for destructive actions, and implement feedback loops

where analysts rate AI suggestions for continuous improvement.

**Q:** Explain the NHI (Non-Human Identity) challenge in AI systems.

AI systems dramatically amplify the NHI challenge. Traditional IT had service accounts and certificates — manageable. With AI agents, every

agent instance, every tool connection, every MCP server, every model endpoint needs an identity. This creates: (1) Credential sprawl — 10x

more NHIs to manage. (2) Static credential risk — many teams use long-lived API keys for AI tools. (3) Attribution gaps — when an agent

modifies data, who's responsible? The solution is: short-lived tokens via workload identity (SPIFFE, cloud-native), just-in-time access

provisioning, delegation chains that trace agent → human, a complete NHI inventory with automated discovery, and behavioral monitoring to

detect compromised NHIs.

**Q:** What is your approach to AI red-teaming?

I use a three-layered approach: Automated breadth testing — use PyRIT and Promptfoo to systematically test all OWASP LLM Top 10

categories across all models and agents. This catches common vulnerabilities at scale. Manual depth testing — experienced red teamers

craft creative, multi-step attack chains that automated tools miss (e.g., combining indirect injection via a RAG source with agent tool abuse

to exfiltrate data). Continuous regression — integrate adversarial test suites into CI/CD so every model update, prompt change, or guardrail

modification is automatically tested. I also establish purple team exercises where red team attacks and CSIRT responds in real-time,

building muscle memory for AI incidents. Track metrics: attack success rate, guardrail bypass rate, mean-time-to-detect.

**Q:** How do you balance security with enabling AI innovation?

Security architecture should be an enabler, not a blocker. My approach: (1) Build secure-by-default platforms — AI gateway, guardrail

frameworks, identity infrastructure that teams use out of the box. If the secure path is the easy path, adoption follows. (2) Create golden

paths — pre-approved architectures for common AI patterns (RAG app, agent with tools, etc.) that come with built-in security. (3) Risk-

based approach — not all AI needs the same level of control. Internal copilot for docs search ≠ autonomous agent with production DB

access. Match controls to risk. (4) Partner, don't police — embed with product teams early, help them design securely from the start rather

than reviewing at the end. (5) Measure and report on both security posture and developer velocity — prove that security accelerates

delivery by reducing rework and incidents.

