# 🔐 Web Security Audit v6.0

A comprehensive black-box web security auditing tool written in pure Bash. Takes only a domain name and automatically runs ~12 security checks — from DNS recon to SQL injection detection — producing a scored security report.

> ⚠️ **For authorized testing only.** Only use on domains you own or have explicit written permission to test.

---

## Features

| Category | What it checks |
|---|---|
| **Reconnaissance** | DNS records (A, AAAA, NS, MX, TXT), IPv4/IPv6, zone transfer (AXFR), SPF/DMARC, subdomains via crt.sh |
| **WAF / CDN Detection** | Cloudflare, AWS CloudFront, Fastly, Akamai, Azure Front Door, Imperva, Sucuri, BunnyCDN, Google Frontend |
| **Port Scan** | Top 1000 ports via nmap; flags FTP, Telnet, Redis, MongoDB, Docker API, etc. |
| **TLS / SSL** | Certificate validity, expiry, SSLv2/3, TLS 1.0/1.1, HSTS presence & strength, testssl.sh integration |
| **HTTP Security Headers** | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS, Permissions-Policy, CORP/COOP/COEP |
| **Technology Fingerprinting** | Django, React, Vue, Angular, WordPress, Laravel, Rails, Next.js, Nuxt.js — via whatweb or HTML analysis |
| **Sensitive File Discovery** | `.env`, `.git/`, `db.sqlite3`, `docker-compose.yml`, `swagger.json`, `phpinfo.php`, SSH keys, admin panels, and 50+ more paths |
| **CORS Misconfiguration** | Tests wildcard origins, subdomain bypass, `null` origin, credentials leak |
| **SQL Injection** | SQLMap (if installed) or manual timing/error-based payload detection with dynamic baseline |
| **XSS Detection** | Reflected XSS via 8 payloads on real page params + common fallback params |
| **Open Redirect** | Host-aware validation, real param extraction from page, multiple bypass variants |
| **Nikto / Nuclei** | Full scan integration when tools are available |

### Scoring System

Every finding deducts points from a base score of 100. Findings are capped per severity to prevent runaway results:

| Severity | Max Deduction | Example |
|---|---|---|
| 🔴 Critical | −40 | Zone transfer open, `.env` exposed, SQLi detected |
| 🟠 High | −25 | HSTS missing, FTP open, CORS misconfiguration |
| 🟡 Medium | −15 | Missing CSP, deprecated TLS, cookie flags |
| 🟢 Low | −5 | Server version leak, robots.txt info |
| ✅ Bonus | up to +20 | Cloudflare CDN, HSTS preload, strict CSP, DMARC reject |

Final score → Risk level: **Low (80–100) / Medium (60–79) / High (40–59) / Critical (0–39)**

---

## Requirements

### Required (must be installed)

```bash
sudo apt install nmap curl dnsutils openssl python3 -y
```

### Optional (enable more checks)

```bash
sudo apt install nikto sqlmap jq whatweb ffuf amass wafw00f -y
pip3 install sublist3r wafw00f
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
git clone https://github.com/drwetter/testssl.sh
```

The script runs fine without optional tools — it just skips the checks that need them and tells you what's missing at the end.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/web-security-audit.git
cd web-security-audit
chmod +x audit.sh
```

---

## Usage

```bash
bash audit.sh <domain> [options]
```

### Options

| Option | Description |
|---|---|
| `--skip-ports` | Skip nmap port scan |
| `--skip-dirs` | Skip sensitive file/directory discovery |
| `--skip-sqli` | Skip SQL injection checks |
| `--skip-xss` | Skip XSS checks |
| `--output <file>` | Save plain-text report to file |
| `--timeout <sec>` | Set global curl timeout (default: 10) |

### Examples

```bash
# Basic scan
bash audit.sh example.com

# Skip slow checks and save report
bash audit.sh example.com --skip-ports --output report.txt

# Fast scan — skip all active exploit checks
bash audit.sh example.com --skip-ports --skip-sqli --skip-xss --skip-dirs

# Custom timeout (useful on slow targets)
bash audit.sh example.com --timeout 20

# Domain with http:// prefix works too
bash audit.sh https://example.com
```

---

## Sample Output

```
╔══════════════════════════════════════════════╗
║  FINAL SECURITY AUDIT REPORT  v6.0          ║
╚══════════════════════════════════════════════╝

  Target:    example.com
  Date:      2025-10-14 18:32:11
  Duration:  87s
  CDN:       Cloudflare detected

  Base Score:    72 / 100
  Deductions:    Critical:-0  High:-8  Medium:-15  Low:-5
  Bonus Points:  +15
  Security Score:  64 / 100  [████████████░░░░░░░░]  Medium Risk

  [HIGH]  2 finding(s):
     >>  HSTS missing — SSL Strip attack possible
     >>  CORS misconfiguration: https://evil.com accepted

  [MEDIUM]  3 finding(s):
     >>  Missing header: Content-Security-Policy
     >>  SPF record missing — Email Spoofing risk
     >>  One or more cookies missing HttpOnly flag

  POTENTIAL ATTACK VECTORS:
   [>>]  SSL Strip Attack: HTTP downgrade possible → traffic interception
   [>>]  CORS Misconfiguration: Attacker site can make authenticated API calls as victim
   [>>]  Email Spoofing: Attackers can send email as @example.com (phishing risk)

  REMEDIATION PRIORITIES:
   [THIS WEEK]   Fix HIGH findings — within 7 days
   [THIS MONTH]  Fix MEDIUM findings — within 30 days
```

---

## Notes

- **CDN-aware**: When a target is behind a CDN (Cloudflare, etc.), the script automatically adjusts — port scans are skipped (they'd hit the CDN edge, not origin), TLS findings are downgraded, and server headers are not flagged as leaks.
- **No false scoring**: Cookie flag deductions are counted once per flag category, not once per cookie. Same for all finding categories — duplicate findings are deduplicated via MD5 registry.
- **Safe defaults**: SQLMap is run with `--technique=BET` only, no `--crawl`, and a 30-second hard timeout to prevent hangs.

---

## Changelog

### v6.0
- SQLMap: removed `--crawl` (caused hangs), added 30s hard timeout, BET techniques only
- Open Redirect: full rewrite with host-aware validation and real param extraction from page HTML
- Scoring: per-category caps, cookie deductions aggregated once per flag type

---

## License

MIT — use freely, audit responsibly.
