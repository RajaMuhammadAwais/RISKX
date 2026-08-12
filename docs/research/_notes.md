# RISKX Research Notes (working file — verified claims with sources)

Accessed: 2026-08-12. All claims below were verified against the cited primary source.

## Vulnerability Intelligence (verified via live API calls + docs)

### CISA KEV
- Feed URL (verified live): https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
- Schema (verified from live CSV, 1666 rows at time of access):
  cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription,
  requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes
- Notes field contains semicolon-separated references incl. vendor advisory URL,
  BOD 26-04 references, nvd.nist.gov detail URL.
- KEV catalog now references CISA's **BOD 26-04 Prioritizing Security Updates Based on Risk**
  (verified in live KEV notes field: "https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk").
- KEV page: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Tier 1 (government primary source). Confidence: HIGH.

### NVD API 2.0 (verified live)
- Base: https://services.nvd.nist.gov/rest/json/cves/2.0 — live, no-auth worked
  (tested 2026-08-12). Response keys: resultsPerPage, startIndex, totalResults,
  format, version, timestamp, vulnerabilities[].cve{ id, sourceIdentifier,
  published, lastModified, vulnStatus, cveTags, descriptions[], metrics{},
  weaknesses{}, references{} }.
- Doc: https://nvd.nist.gov/developers/vulnerabilities (Created 2022-09-20,
  Updated 2025-02-25). CVE API + CVE Change History API.
- Pagination: offset-based startIndex/resultsPerPage. NVD ~376,178 CVE records.
- API key: optional without key = public rate limit; with key (apikey header) higher
  limit. Request: https://nvd.nist.gov/developers/request-an-api-key
  - Terms require attribution: "This product uses the NVD API but is not endorsed
    or certified by the NVD." — MUST include in RISKX output/docs.
  - Rate-limit check page: nvd.nist.gov/developers (to verify exact numbers pre-impl).
- Tier 1 (NIST). Confidence: HIGH.

### EPSS (verified live)
- API: https://api.first.org/data/v1/epss?cve=CVE-2021-44228
- Response: {"status":"OK","status-code":200,...,"data":[{"cve","epss","percentile","date"}]}
- epss=CVE-2021-44228 → 0.999990000, percentile 1.000000000, date 2026-08-11.
- No auth required for public tier. Tier 1 (FIRST). Confidence: HIGH.

### OSV (verified live)
- API: https://api.osv.dev/v1/vulns/CVE-2021-44228 — live, returns OSV schema
  (id, details, aliases[], modified, published, related[], schema_version).
- Tier 1 (Google-backed open-source vulnerability format). Confidence: HIGH.

## TODO verify next
- EPSS bulk download, KEV download (verified), NVD bulk data (json zip),
- MITRE ATT&CK, CWE list, CVSS 3.1/4.0 spec, CPE 2.3 spec
- OWASP Top 10, OWASP Agentic AI security (LLM top 10?), OWASP MCP
- NIST AI-111, NIST AI 600 series, SP 800-53/CSF 2.0
- MCP spec official (modelcontextprotocol.io)

## MITRE ATT&CK (verified)
- STIX data repo: https://github.com/mitre-attack/attack-stix-data (official,
  STIX 2.1 collections; enterprise-attack, mobile-attack, ics-attack).
- Latest release zip works: https://github.com/mitre-attack/attack-stix-data/releases/latest/download/enterprise-attack.zip (v19.2 at access time).
- License: ATT&CK Terms of Use apply (https://attack.mitre.org/resources/terms-of-use/).
- Tier 1 (MITRE official GitHub). Confidence: HIGH.
- NOTE: https://attack.mitre.org/stix/enterprise-attack.json returns 404 — use
  the GitHub release instead.

## CWE (verified)
- CWE API: https://cwe-api.mitre.org/api/v1/cwe/{id}?format=json — works for
  individual IDs (tested CWE-19).
- /api/v1/cwe/top-25 returned error "at least one CWE not found" — API shape
  differs; verify /top25 or /cwe/top25 before use. UNVERIFIED path → treat as
  research gap.

## OWASP MCP Top 10 (verified, Tier 1 — official OWASP project page)
- Page: https://owasp.org/www-project-mcp-top-10/ (project lead vandana.verma@owasp.org)
- Version v0.1, "beta" phase; next release Oct 2026 (so model is evolving — version assumptions needed).
- License: CC BY-NC-SA 4.0.
- Risks: MCP01 Token Mismanagement & Secret Exposure; MCP02 Privilege Escalation
  via Scope Creep; MCP03 Tool Poisoning (rug pulls, schema poisoning, tool shadowing);
  MCP04 Software Supply Chain Attacks & Dependency Tampering; MCP05 Command Injection & Execution;
  MCP06 Intent Flow Subversion (Prompt Injection via Contextual Payloads); MCP07 Insufficient
  Authentication & Authorization; MCP08 Lack of Audit and Telemetry; MCP09 Shadow MCP Servers;
  MCP10 Context Injection & Over-Sharing.

## MCP official spec security (verified, Tier 1 — official modelcontextprotocol.io)
- Security best practices page: https://modelcontextprotocol.io/specification/draft/basic/security_best_practices
  Documents: Confused Deputy Problem (MCP proxy + static client_id + dynamic client
  registration + consent cookies), per-client consent requirements, token passthrough
  anti-pattern (audience validation per RFC9068), references OAuth 2.0 best practices RFC9700.
- Spec versioning: URLs are versioned (2025-06-18, draft). Protocol behavior MUST be
  versioned in implementation (spec §4).
- Architecture page 2025-06-18/basic/architecture failed extraction — retry in next research pass.

## Other verified
- NVD bulk feeds JSON 1.1 return 403 behind Cloudflare when accessed via curl (both
  custom UA and browser UA failed). NVD now pushes users to API 2.0. Verified by live test.
- MITRE STIX repo README states enterprise-attack.zip latest = v19.2.

## AI-Agent Security Standards (verified, mostly Tier 1)

### NIST COSAiS (Tier 1 — verified on csrc.nist.gov/projects/cosais, updated 2026-01-08)
- Project: SP 800-53 Control Overlays for Securing AI Systems (COSAiS), created 2025-07-10.
- Five proposed use cases: (1) Adapting/Using GenAI Assistant/LLM, (2) Using & Fine-Tuning
  Predictive AI, (3) AI Agent Systems — Single Agent, (4) AI Agent Systems — Multi-Agent,
  (5) Security Controls for AI Developers.
- Leverages SP 800-53 controls, SP 800-218A, draft NIST AI 800-1 (ipd2), NIST AI 100-2e2025.
- Predictive-AI annotated outline published 2026-01-08 (discussion draft).
- **Agent overlays NOT yet published as of 2026-08-12** — RISKX must not claim compliance
  with agent-specific overlays that don't exist yet; reference CSF/COSAIS concept paper only.

### NIST AI Agent Standards Initiative (Tier 2 — CSA research note; cross-check against
  nist.gov/CAISI)
- CAISI launched AI Agent Standards Initiative 2026-02-17 — first US govt program for
  agentic AI interoperability/security standards.
- NIST empirical research (Jan 2025, w/ UK AI Security Institute, AgentDojo framework):
  agent hijacking attacks 81% success vs 11% baseline; ~7x improvement from optimized
  prompts. Repo: github.com/usnistgov/agentdojo-inspect.
- NCCoE concept paper "Accelerating the Adoption of Software and AI Agent Identity and
  Authorization" published 2026-02-05 — focuses on agent identification, OAuth 2.0
  extension authorization, delegation accountability, logging/transparency.
- RFI: Federal Register 2026-01-08, doc 2026-00206 (91 FR 698), docket NIST-2025-0035,
  937 comments, closed 2026-03-09.
- Gaps: no standalone federal agentic AI security standard yet; ATT&CK/ATLAS doesn't cover
  multi-agent lateral movement or reasoning-layer attacks.

### Implication for RISKX (§3 of spec): use NIST AI RMF, COSAiS concept paper, NIST
  AI 800-1 draft, NIST AI-111 (Securing Generative AI) as primary controls vocabulary;
  version assumptions explicitly (no final agent overlays exist yet).

## NIST AI publications — verified states (accessed 2026-08-12)
- NIST AI RMF (AI 100-1): https://www.nist.gov/itl/ai-risk-management-framework (Tier 1)
- NIST AI 600-1 "AI RMF: Generative AI Profile" FINAL, published 2024-07-26, PDF:
  https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf — verified reachable. (Tier 1)
- NIST AI 800-1 2pd "Managing Misuse Risk for Dual-Use Foundation Models", Jan 2025,
  PDF: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.800-1.ipd2.pdf — verified reachable. (Tier 1)
- NIST SP 800-218A "Secure Software Development Practices for GenAI and Dual-Use FM:
  An SSDF Community Profile" FINAL 2024-07-26: https://csrc.nist.gov/pubs/sp/800/218/a/final — verified.
- NIST SP 800-218 SSDF v1.1 final 2022-02: https://csrc.nist.gov/pubs/sp/800/218/final — verified.
- "AI-111" numbering (AI 111-1 Securing Generative AI Applications and Systems; AI 112-1;
  AI 113-1 Adversarial ML taxonomy) — the csrc.nist.gov/pubs/ai/111 path and
  nvlpubs AI.11x paths all returned 404 at access time. Do NOT cite AI-111 URLs until
  re-verified; use AI 100-1/600-1 and COSAiS as primary sources instead. Marked UNVERIFIED.
- COSAiS project page https://csrc.nist.gov/projects/cosais verified (see above).
- Cyber AI Profile (Community Profile) NISTIR 8596 preliminary draft:
  https://csrc.nist.gov/pubs/ir/8596/iprd
- NISTIR 8607 Cyber AI Profile workshop #2 summary final: https://csrc.nist.gov/pubs/ir/8607/final

## OWASP Top 10:2025 (verified Tier 1 — owasp.org/Top10/2025, released Nov 2025)
A01 Broken Access Control (#1, 3.73% apps, SSRF rolled in, 40 CWEs), A02 Security
Misconfiguration (#2, 3.00%), A03 Software Supply Chain Failures (new category,
fewest occurrences but highest average CVE exploit/impact scores), A04 Cryptographic
Failures, A05 Injection (most CVEs), A06 Insecure Design, A07 Authentication Failures,
A08 Software or Data Integrity Failures, A09 Security Logging & Alerting Failures,
A10 Mishandling of Exceptional Conditions (new). 248 CWEs across 10 categories;
589 CWEs analyzed; 968 CWEs in MITRE dictionary at release. Methodology is data-
informed, not blindly data-driven; CVSS used for exploit/impact weighting.
Relevance to RISKX: OWASP Top 10 serves as taxonomy layer for risk findings and
for the risk-classification subsystem (§17 spec).

## Exploit telemetry & risk modeling (Tier 2/3 — industry telemetry + academic)

### Proofpoint 2026 in-the-wild exploitation (Tier 3, detailed telemetry report, 2026-05-27)
- 12 distinct 2026 CVEs exploited in network-facing attacks vs 8 in CISA KEV → KEV
  lags real exploitation by ~2-4 weeks for perimeter vulns. KEV-only prioritization is incomplete.
- CVE volume: NIST Q1-2026 submissions ~1/3 higher YoY; est. 55-60k CVEs in 2026.
  AI-assisted discovery cited (Mozilla FF 61+76 patches Feb-Mar 2026; Apache +170% CVEs).
- APT28 (TA422) weaponized CVE-2026-21509 (MS Office RCE) within 24h of disclosure —
  exploit window collapsing; actors adopt same CVEs (CVE-2026-21510 chain by TA406).
- cPanel CVE-2026-41940: mass exploitation days after public PoC (scanning → ransomware,
  defacement, TA569 SocGholish web-inject).
- Cisco SD-WAN cluster: 3 auth-bypass/info-disclosure CVEs; CISA Emergency Directive ED 26-03.
- Implication for RISKX: risk engine must fuse KEV (reactive) + EPSS + PoC presence +
  exposure context; KEV alone under-represents active risk (§12 spec evidence model).

### Bayesian local-exploit-hazard model (arXiv 2607.24618, Shaffer & Voicu, 2026-07)
- Converts global ELM (EPSS-like) probabilities into per-org daily exploit HAZARD rates.
- Control effectiveness modeled as Beta distribution, seeded by SME opinion, updated via
  Beta-Binomial inference from telemetry/BAS/pentests.
- Weibull hazard shape calibrated from KEV catalog timing (exploitation risk decays with age).
- Hazards additive under independence → aggregate per-vuln → host → network → org.
- Remediation actions ranked by projected hazard reduction under fixed capacity.
- Implication for RISKX: candidate approach for the risk engine's exploitation-likelihood
  component; evidence-model should store per-asset control-effectiveness observations.

### Academic lineage
- EPSS original: Jacobs et al., ACM CCS Workshop AISec 2021 (dl.acm.org/doi/abs/10.1145/3436242)
  — Bayesian Information Criterion optimization, CVSS-based baselines comparison.
- Probabilistic attack graphs: Homer et al. "Security risk analysis of enterprise networks
  using probabilistic attack graphs" (Springer); "Quantitative security risk assessment of
  enterprise networks" (book, Springer) — attack-graph enumeration + system risk metric.
- CVE/CVSS+Bayesian vulnerability assessment: IEEE 2025/2026 works exist (11130164).

## ATT&CK v19, CIS Controls, ASM (verified 2026-08-12)
- ATT&CK v19.2 current (released 2026-04-28). Enterprise: 15 tactics, 222 techniques,
  475 sub-techniques. Major change: Defense Evasion (TA0005) SPLIT into Stealth (TA0005)
  and Defense Impairment (TA0112). ICS gets sub-techniques; new AI/social-engineering
  coverage. STIX data: github.com/mitre-attack/attack-stix-data enterprise-attack.zip
  latest = v19.2 (verified earlier).
- CIS Controls v8.1 with IG1/IG2/IG3 implementation groups; IG1 = essential cyber
  hygiene baseline.
- EASM (Gartner market category): continuous discovery/inventory/monitoring of
  internet-facing assets; CISA cross-cuts: Discover, Prioritize, Remediate, Validate.

## Cloud security & threat taxonomy (verified Tier 1)

### CISA SCuBA Project (verified on cisa.gov)
- Secure Cloud Business Applications project (est. 2022): secure configuration baselines
  (SCBs) for Microsoft 365 and Google Workspace SaaS. ScubaGear (M365, PowerShell) and
  ScubaGoggles (GWS, Python, PyPI: scubagoggles) are open-source assessment tools on
  github.com/cisagov. BOD 25-01 enforces required cloud configurations for FCEB.
- Relevance: SaaS misconfiguration is a core CTEM asset class for RISKX (SaaS exposure
  assessment via config baseline checks).

### CISA nation-state actors page (verified)
- Four tracked nation states: PRC, Iran, DPRK, Russia. CISA uses community APT names;
  references MITRE ATT&CK Groups, Mandiant APT list, Microsoft naming taxonomy.
- CISA recommends KEV catalog as input to vuln-management prioritization; joint advisories
  on top common vulns/KEV exposures; top-10 misconfigurations advisory (AA23-278A);
  Cybersecurity Performance Goals (CPGs); no-cost Vulnerability Scanning service for
  internet-facing KEV alerts.
- CPGs include log collection (CPG 2.T) — relevant to telemetry/evidence requirements.

### Shared responsibility model
- AWS/Azure official pages confirm provider-customer split; customer retains responsibility
  for identity, data, configuration — primary driver of SaaS/PaaS misconfiguration risk.

## Competitive landscape & open-source tooling (verified)

### Commercial ASM/EASM/CAASM (Tier 2/3 — market guides, 2025-2026)
- Market categories: EASM (external/internet-facing), CAASM (internal aggregation from
  CMDB/ITSM/cloud/endpoint), ASM umbrella. Gartner defines EASM market.
- Commercial leaders 2026: Bitsight (EASM+CTI+TPRM, custom pricing only — no self-serve
  tier, 45% breach reduction per Forrester TEI), Rapid7 (VM+external visibility),
  Mandiant ASM (Google TI integration), JupiterOne (CAASM graph), Falcon Surface
  (CrowdStrike), CyberInt, Detectify, Intruder, CyberTotal, RunZero.
- Common commercial gaps RISKX can target: custom enterprise pricing only (no self-serve/
  CLI-first tier), opaque risk scoring without evidence provenance, limited AI-agent
  exposure coverage (new category), KEV-only prioritization without local hazard models.

### Open-source asset discovery ecosystem (verified — redhuntlabs/Awesome-Asset-Discovery,
  2.8k stars, CC0)
- Subdomain: SubFinder (ProjectDiscovery), Amass (OWASP), Sublist3r, massdns,
  crt.sh/certificate transparency log mining, NSEC3 walking (nsec3map).
- IP/port: nmap, zmap, masscan, bgp.he.net ASN tools, whois/nslookup.
- Cloud storage exposure: CloudScraper, GCPBucketBrute, CloudStorageFinder,
  grayhatwarfare. SaaS enumeration via DNS: Enumeration-as-a-Service.
- Internet survey data: Project Sonar (opendata.rapid7.com), scans.io, Resonance
  (RedHunt). Archive: Wayback Machine.
- NOTE licenses: subfinder (MIT), Amass (MIT w/ 3rd-party clauses), zmap/masscan GPL-2.0.
  RISKX must implement its own logic or depend with license compliance (spec §34).

### Implication for RISKX positioning
- Differentiators aligned with spec: evidence-first (every score traceable to cited
  data), no-guessing default, AI-agent/MCP exposure as explicit surface class,
  open-source CLI-first with self-serve usage.
