# FAIR Framework: Risk Quantification in GreyPing

**FAIR** (Factor Analysis of Information Risk) is a quantitative risk model that converts security findings into actionable risk scores. Every GreyPing scan produces a `fair_signals` object that breaks down risk into four measurable factors and an overall score (0–100).

## The Four FAIR Factors

### 1. Threat Event Frequency (TEF) — 0–100

**Question:** How often are threat actors likely to attack this asset?

Threat actors are more likely to target:
- Exposed business-critical software (CMS, webmail, VPN, remote access tools, databases, ecommerce platforms)
- Assets with exposed secrets (AWS keys, GitHub tokens, database credentials)
- Targets with suspicious indicators-of-compromise (cryptominers, credential harvesting, hidden iframes)

**GreyPing signals that raise TEF:**
- Technology fingerprint detects `cms`, `ecommerce`, `webmail`, `vpn`, `remote_access`, or `database` categories
- `secret_scanner` finds exposed credentials (AWS, GitHub, Stripe, Slack, JWTs, private keys, DB URLs)
- `ioc_scanner` detects cryptominers, hidden iframes, obfuscated JavaScript, or credential harvesting patterns

**Scoring:**
- **0–25 (Low):** Static marketing website with no sensitive tech stack
- **26–50 (Medium):** Blog, support portal, or basic web app
- **51–75 (High):** CMS, SaaS app, or ecommerce platform
- **76–100 (Critical):** Exposed secrets, known high-value target infrastructure, or active compromise indicators

### 2. Vulnerability (V) — 0–100

**Question:** If a threat actor engages with the asset, how likely are they to succeed?

Vulnerabilities reduce defensive posture:
- Missing or weak HTTP security headers (no HSTS, CSP, X-Frame-Options, X-Content-Type-Options)
- Expired, self-signed, or weak-cipher TLS certificates
- Weak TLS versions (anything older than TLS 1.2)
- Unpatched software (detected via technology fingerprint + CVE correlation)
- Historical breach records (indicates past compromise, weakens confidence in current controls)

**GreyPing signals that raise Vulnerability:**
- `ssl_checker` finds expired certs, self-signed certs, weak ciphers, or old TLS versions
- `security_headers` detects missing HSTS, CSP, or other recommended headers
- `cve_lookup` identifies unpatched software versions with known CVEs
- `breach_checker` finds domain/email in Have I Been Pwned
- `email_security` detects missing SPF, DKIM, or DMARC (email spoofing vector)

**Scoring:**
- **0–25 (Low):** Strong TLS (1.3), all headers present, no known CVEs, no breaches
- **26–50 (Medium):** TLS 1.2, some headers missing, one old dependency
- **51–75 (High):** Weak TLS, missing multiple headers, several CVEs or old breaches
- **76–100 (Critical):** Expired cert, no headers, actively exploitable vulnerabilities, or active breaches

### 3. Control Strength (CS) — 0–100 (Inverted)

**Question:** How effective are the defensive mechanisms?

Strong controls **reduce** Loss Event Frequency. High CS = strong defenses = lower risk.

Effective controls include:
- HSTS header (prevents downgrade attacks and SSL stripping)
- Content Security Policy (CSP) — prevents inline script injection and XSS
- X-Frame-Options — prevents clickjacking
- WAF/CDN presence (Akamai, Imperva, Sucuri, F5, Azure Front Door, Cloudflare) — absorbs attacks before reaching origin
- Email security (SPF, DKIM, DMARC) — prevents email spoofing and phishing

**GreyPing signals that raise Control Strength:**
- `security_headers` finds HSTS, CSP, X-Frame-Options, X-Content-Type-Options
- `tech_fingerprint` detects WAF/CDN (is_waf_cdn flag)
- `email_security` finds SPF, DKIM, DMARC with strong grades (A/A+)
- `ssl_checker` confirms TLS 1.3, strong ciphers, long cert validity

**Scoring:**
- **0–25 (Strong):** HSTS + CSP + WAF + strong email security + TLS 1.3
- **26–50 (Moderate):** Some headers + WAF or good email config
- **51–75 (Weak):** Minimal headers, no WAF, poor email security
- **76–100 (Very Weak):** Almost no controls detected

### 4. Loss Magnitude (LM) — 0–100

**Question:** How much harm would occur if the asset is successfully exploited?

Loss includes:
- Data exfiltration (customer PII, API keys, source code)
- Service disruption (downtime cost, reputational damage)
- Financial loss (fraud, ransomware, regulatory fines)
- Regulatory/compliance exposure (PCI-DSS, HIPAA, GDPR)

**GreyPing signals that raise Loss Magnitude:**
- `ioc_scanner` detects credential harvesting patterns (suggests Magecart-style attacks targeting customer data)
- `secret_scanner` finds exposed secrets (AWS keys enable full account takeover; database credentials expose all data)
- `breach_checker` finds historical breaches (proves data was leaked before; trust is already damaged)
- `tech_fingerprint` detects sensitive tech (admin panels, payment gateways, CMS with user data, databases) — higher impact if compromised
- `email_security` weak DMARC/SPF/DKIM (email account takeover enables lateral movement into other systems)

**Scoring:**
- **0–25 (Low):** Marketing site, no secrets, no breaches, no sensitive tech
- **26–50 (Medium):** Some contact extraction possible, old breach, some exposed secrets
- **51–75 (High):** Database detected, AWS keys found, multiple breaches, credential harvesting patterns
- **76–100 (Critical):** Payment processing detected, admin panel exposed, current data breach, active credential theft

---

## Risk Score Calculation

### Formula

```
Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)
LEF = Threat Event Frequency (TEF) × Vulnerability (V) / (1 + Control Strength attenuator)
Control Strength attenuator = 1 - (CS / 100)
```

**In plain English:**
- Risk increases when threat actors are interested (TEF ↑) AND can succeed (V ↑)
- Risk decreases when defenses are strong (CS ↑)
- Even with strong controls, risk is still non-zero (complete elimination is impossible)
- Loss magnitude multiplies the final risk (high-impact assets are riskier even with good controls)

### Example Calculation

**Scenario 1: Marketing site, no issues**
```
TEF = 20 (simple website, not a target)
V   = 15 (TLS 1.3, all headers, no CVEs)
CS  = 10 (excellent controls, strong defenses)
LM  = 10 (low impact if compromised)

Attenuator = 1 - (10/100) = 0.9
LEF = 20 × 15 / (1 + 0.9) = 300 / 1.9 ≈ 158 / 100 = 1.58 (normalized)
Risk ≈ 1.58 × 10 = 16
```
**Risk: 16/100 (Low)**

**Scenario 2: Ecommerce site, some issues**
```
TEF = 70 (ecommerce = high value target)
V   = 60 (TLS 1.2, some headers missing, one old dependency)
CS  = 40 (partial controls, no WAF)
LM  = 80 (payment processing, customer PII)

Attenuator = 1 - (40/100) = 0.6
LEF = 70 × 60 / (1 + 0.6) = 4200 / 1.6 = 2625 (normalized to ~52)
Risk ≈ 52 × 80 = 4160 (normalized to ~65/100)
```
**Risk: 65/100 (High)**

**Scenario 3: Admin panel exposed, secrets found**
```
TEF = 85 (exposed admin panel, highly attractive target)
V   = 80 (expired cert, missing headers, weak TLS, unpatched)
CS  = 80 (poor controls, no WAF, weak email sec)
LM  = 95 (database access, financial systems, user credentials)

Attenuator = 1 - (80/100) = 0.2
LEF = 85 × 80 / (1 + 0.2) = 6800 / 1.2 ≈ 567 (normalized to ~85)
Risk ≈ 85 × 95 = 8075 (normalized to ~89/100)
```
**Risk: 89/100 (Critical)**

---

## Signal Mapping: How Scanner Outputs Feed FAIR Factors

This table shows which GreyPing modules contribute evidence to each FAIR factor:

| Factor | Signals Detected | Source Modules | Evidence Examples |
|--------|---|---|---|
| **TEF** | Exposed CMS/webmail/VPN/database | `tech_fingerprint` | Detects Wordpress, Exchange, OpenVPN, PostgreSQL |
| | Exposed secrets | `secret_scanner` | AWS AKIA keys, GitHub tokens, DB URIs |
| | Suspicious IoCs | `ioc_scanner` | Cryptominers, credential harvesting, hidden frames |
| | High-value targets | `tech_fingerprint` | Ecommerce, payment gateway, admin panel detected |
| **Vulnerability** | Missing HSTS/CSP headers | `security_headers` | Header audit results |
| | Expired/weak TLS | `ssl_checker` | Certificate expiry, TLS version, cipher strength |
| | Unpatched software | `cve_lookup` | CVE CVSS scores matched to detected tech versions |
| | Historical breaches | `breach_checker` | Domain/email found in HIBP |
| | Weak email security | `email_security` | Missing SPF/DKIM/DMARC or weak alignment |
| **Control Strength** | Strong headers (HSTS/CSP/X-Frame) | `security_headers` | Header grades A/A+ = strong controls |
| | WAF/CDN presence | `tech_fingerprint` | Detects Cloudflare, Akamai, Imperva, etc. |
| | Strong TLS | `ssl_checker` | TLS 1.3, strong ciphers, good cert validity |
| | Email security | `email_security` | SPF/DKIM/DMARC all configured with A grades |
| | Cookie security | `cookie_checker` | Secure/HttpOnly/SameSite flags present |
| **Loss Magnitude** | Credential harvesting patterns | `ioc_scanner` | Magecart-style attacks, skimming code detected |
| | Exposed secrets | `secret_scanner` | AWS keys, DB credentials found (direct impact) |
| | Breach history | `breach_checker` | Past compromises indicate data loss risk |
| | Sensitive tech stack | `tech_fingerprint` | Admin panels, payment gateways, CMS, databases |
| | Admin panel exposed | `path_scanner` | /admin, /wp-admin, /administrator accessible |

---

## How Scan Modes Affect FAIR Scores

### `/scan/passive` (Zero-Traffic Reconnaissance)

**Evidence collected:** DNS, CT logs, WHOIS, Wayback, HIBP, email security only. **No crawling, no path probes.**

**Limitations:**
- **Cannot detect:** Exposed paths, running web applications, secrets in crawled pages, specific tech instances
- **Can infer:** Technology from HTTP headers/HTML metadata, email security, breach history, cert info
- **Impact on FAIR:** Passive mode produces lower *evidence density* for some factors:
  - TEF: Based only on inferred tech + any exposed secrets in headers/metadata (incomplete picture)
  - Vulnerability: Limited to SSL/email security/breaches (misses header audit, unpatched app detection)
  - Control Strength: Inferred from inferred tech + SSL (may miss actual WAF/headers deployed)
  - Loss Magnitude: Based on inferred tech categories only (misses exposed admin panels/paths)

**Use case:** Quick initial reconnaissance, stealth-first assessment, or situations where triggering WAFs is unacceptable.

### `/scan/lighttouch` (Single HTTP GET, WAF-Friendly)

**Evidence collected:** Landing page only (no crawl), headers, metadata, SSL, single-page tech fingerprint + path probes.

**Limitations:**
- **Cannot detect:** Deep site structure, internal secrets on nested pages, full tech stack, all exposed paths
- **Can detect:** Landing-page headers, some tech (CMS, CDN), landing-page SSL cert, accessible admin paths
- **Impact on FAIR:** Moderate evidence density:
  - TEF: Based on landing-page tech only (misses secondary apps, services)
  - Vulnerability: Headers + SSL from landing page only; no crawl-based CVE detection
  - Control Strength: Same as above
  - Loss Magnitude: Missing crawled secrets, missing internal admin panels on subpages

**Use case:** Frequent scanning (rate limits), WAF-heavy targets, or when you want to minimize traffic footprint.

### `/scan` (Full Crawl, Maximum Evidence)

**Evidence collected:** Complete crawl (BFS to configured depth), JS rendering, all passive intel, all security checks, path probes, secret scanning, tech fingerprinting.

**Advantages:**
- **Collects all evidence:** Complete picture of tech stack, exposed paths, secrets in all crawled pages, all headers/cookies
- **Highest confidence:** Multiple independent signals support each FAIR factor
- **Catches edge cases:** Secrets hidden in JavaScript bundles, admin panels on subpaths, dynamic tech detection

**Impact on FAIR:** Highest evidence density — all factors are well-informed.

**Tradeoff:** Longer scan time (30–120s), higher traffic to target (50–200+ requests), increased WAF/IDS likelihood.

---

## Interpreting FAIR Signals

### For Security Operators (CISOs, Risk Managers)

Focus on **Risk** (top-level score) and **Loss Magnitude**:

- **Risk > 75:** High priority. Assess for immediate remediation.
- **Risk 50–75:** Medium priority. Plan fixes within 30 days.
- **Risk < 50:** Low priority. Log for continuous monitoring.

Ask: *"If this asset is compromised, what's the business impact?"* (Loss Magnitude answers this.)

### For Penetration Testers

Focus on **Vulnerability** and **Threat Event Frequency**:

- **Vulnerability > 70 + TEF > 60:** This is an attractive target with exploitable weaknesses. Prioritize testing.
- **Control Strength < 30:** Defenses are weak. Assume successful compromise is likely.

Ask: *"Can I exploit this? Is anyone else interested?"* (Vulnerability + TEF answer this.)

### For Blue Team / Security Operations

Focus on **Control Strength**:

- **CS > 70:** Defenses are strong. Monitor for anomalies.
- **CS 30–70:** Defenses are moderate. Harden headers, patch promptly, monitor for exploits.
- **CS < 30:** Defenses are weak. Urgent hardening required. Deploy WAF, enable HSTS, audit access controls.

Ask: *"Are our defenses working?"* (Control Strength answers this.)

### Role-Specific Summary Example

**Target:** `payments.acme.com` (payment processing)

| Role | Signals | Action |
|------|---------|--------|
| CISO | Risk=78, LM=95 | **Critical.** Payment system with high loss potential. Escalate. |
| Pentester | TEF=72, V=65, CS=35 | **Exploitable.** Weak defenses + high-value target. Focus testing here. |
| Blue Team | CS=35 (missing HSTS, CSP, WAF) | **Urgent.** Deploy WAF, enable HSTS, implement CSP. |

---

## Integration with EASM Reports

The GreyPing API includes an `easm_report` object in every scan result. This report summarizes findings for executive consumption and assigns risk tiers based on FAIR factors.

### EASM Report Structure

```json
{
  "critical_findings": [
    {
      "category": "Exposed Admin Panel",
      "finding": "/wp-admin accessible without authentication",
      "impact": "Full site takeover possible",
      "fair_contribution": "TEF ↑, V ↑, LM ↑",
      "remediation": "Restrict /wp-admin to admin IPs; require 2FA"
    }
  ],
  "high_findings": [ /* ... */ ],
  "medium_findings": [ /* ... */ ],
  "low_findings": [ /* ... */ ]
}
```

Each finding is categorized by severity (Critical/High/Medium/Low) based on how much it contributes to FAIR factors. FAIR factors are the foundation of the EASM report hierarchy.

---

## Using FAIR Signals in Downstream Systems

### Integration with Dashboards (Xano, Tableau, etc.)

The `fair_signals` object is JSON-serializable and ready for database ingestion:

```bash
curl -s -X POST http://localhost:8089/scan/passive \
  -d '{"targets": ["example.com"]}' | \
  jq '.results[0].fair_signals' > /tmp/risks.json
```

**Typical dashboard use cases:**
- Risk heatmap: Plot Risk (y-axis) vs. Asset Criticality (x-axis)
- Trend analysis: Track Risk over time (weekly scans) to measure remediation progress
- SLA reporting: Flag assets where Risk > threshold for escalation

### Integration with Incident Response

When a security event occurs:
1. Run `/scan` on the affected asset
2. Extract `fair_signals` and compare to baseline
3. If Risk score jumped, new vulnerabilities likely introduced or exploited
4. Use `signals` array to pinpoint which evidence changed

### Integration with Continuous Scanning

Schedule periodic `/scan/lighttouch` or `/scan/passive` runs (e.g., weekly) and track FAIR scores over time:

```bash
for target in example.com acme.test; do
  curl -X POST http://localhost:8089/scan/passive \
    -H "X-API-Key: $API_KEY" \
    -d "{\"targets\": [\"$target\"]}" | \
    jq '.results[0] | {target, risk: .fair_signals.risk_score, timestamp: now}'
done
```

---

## Understanding Uncertainty

FAIR scores are derived from available evidence. Passive scans have lower evidence density than full crawls. Some factors are inherently uncertain:

- **TEF** is educated guessing — we infer attacker interest from tech stack, not from actual threat intelligence feeds.
- **Control Strength** is inferred from deployed headers/WAF/email config, not from internal access controls or incident history.
- **Loss Magnitude** is estimated from tech categories and secrets found, not from actual data sensitivity classification.

**Use FAIR signals as one input to risk decisions, not as absolute truth.** Combine with:
- Internal threat intelligence (which assets are actually targeted?)
- Business context (revenue, customer impact, regulatory requirements)
- Historical incident data (has this asset been breached before?)

---

## See Also

- [README.md](../README.md) — API documentation and endpoints
- `.env.example` — Configuration reference
- `src/fair_signals.py` — FAIR calculation source code
- `src/models.py` — `FAIRSignals`, `FAIRFactor`, `FAIRSignal` Pydantic models
