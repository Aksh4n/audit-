#!/bin/bash
# ============================================================
#  Web Security Audit v6.0 — Black Box (Domain Only)
#  Usage:   bash audit.sh <domain> [options]
#  Options:
#    --skip-ports      Skip port scan
#    --skip-dirs       Skip directory/file discovery
#    --skip-sqli       Skip SQLi checks
#    --skip-xss        Skip XSS checks
#    --output <file>   Save report to file (plain text)
#    --timeout <sec>   Global curl timeout (default: 10)
#  Example:
#    bash audit.sh example.com
#    bash audit.sh example.com --skip-ports --output report.txt
#
#  v6.0 changes:
#    - SQLMap: removed --crawl (hangs), added 30s hard timeout,
#              BET techniques only, direct param injection
#    - Open Redirect: full rewrite — host-aware validation,
#              real params extracted from page, bypass variants
#    - Scoring: per-category caps (Critical≤40, High≤25,
#              Medium≤15, Low≤5, Bonus≤20), cookie deductions
#              aggregated once per flag (not per cookie)
# ============================================================

TARGET="${1}"
if [ -z "$TARGET" ] || [[ "$TARGET" == --* ]]; then
    echo "Usage: bash audit.sh <domain> [--skip-ports] [--skip-dirs] [--skip-sqli] [--skip-xss] [--output file] [--timeout sec]"
    echo "Example: bash audit.sh example.com --output report.txt"
    exit 1
fi

# ============================================================
# Parse options
# ============================================================
SKIP_PORTS=0
SKIP_DIRS=0
SKIP_SQLI=0
SKIP_XSS=0
OUTPUT_FILE=""
CURL_TIMEOUT=10

shift
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-ports) SKIP_PORTS=1 ;;
        --skip-dirs)  SKIP_DIRS=1  ;;
        --skip-sqli)  SKIP_SQLI=1  ;;
        --skip-xss)   SKIP_XSS=1   ;;
        --output)     OUTPUT_FILE="$2"; shift ;;
        --timeout)    CURL_TIMEOUT="$2"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

# Strip protocol prefix if user passed it
TARGET="${TARGET#http://}"
TARGET="${TARGET#https://}"
TARGET="${TARGET%%/*}"

START_TIME=$(date +%s)

# Final response headers (redirect-aware)
FINAL_HEADERS=$(curl -skI -L --max-time "$CURL_TIMEOUT" \
    -A "Mozilla/5.0 (compatible; SecurityAudit/5.0)" \
    "https://$TARGET" 2>/dev/null | tr -d '\r')

FINAL_URL=$(curl -skL -o /dev/null -w "%{url_effective}" \
    --max-time "$CURL_TIMEOUT" \
    -A "Mozilla/5.0 (compatible; SecurityAudit/5.0)" \
    "https://$TARGET" 2>/dev/null)


# ============================================================
# Colors
# ============================================================
R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; M='\033[0;35m'; N='\033[0m'

# Output capture for --output flag
_OUT_LINES=()

log()   { local m="[*] $1";  echo -e "${C}${m}${N}";  _OUT_LINES+=("$m"); }
ok()    { local m="[+] $1";  echo -e "${G}${m}${N}";  _OUT_LINES+=("$m"); }
warn()  { local m="[!] $1";  echo -e "${Y}${m}${N}";  _OUT_LINES+=("$m"); }
err()   { local m="[-] $1";  echo -e "${R}${m}${N}";  _OUT_LINES+=("$m"); }
info()  { local m="[i] $1";  echo -e "${M}${m}${N}";  _OUT_LINES+=("$m"); }
vuln()  { local m="[VULN] $1"; echo -e "${R}${m}${N}"; _OUT_LINES+=("$m"); }
plain() { echo -e "$1"; _OUT_LINES+=("$1"); }

title() {
    local line=""
    plain ""
    plain "${B}╔══════════════════════════════════════════════╗${N}"
    plain "${B}║  $1${N}"
    plain "${B}╚══════════════════════════════════════════════╝${N}"
    sep
}
sep() { plain "${C}────────────────────────────────────────${N}"; }

has() { command -v "$1" &>/dev/null; }

# ============================================================
# Score tracking & findings
# ============================================================
SCORE=100
BONUS=0

# Per-category deduction caps to prevent runaway scoring
DEDUCT_CRITICAL=0
DEDUCT_HIGH=0
DEDUCT_MEDIUM=0
DEDUCT_LOW=0
CAP_CRITICAL=40   # max 40 pts from critical findings
CAP_HIGH=25       # max 25 pts from high findings
CAP_MEDIUM=15     # max 15 pts from medium findings
CAP_LOW=5         # max 5 pts from low findings
MAX_BONUS=20      # bonus capped at 20

declare -a FINDINGS_CRITICAL=()
declare -a FINDINGS_HIGH=()
declare -a FINDINGS_MEDIUM=()
declare -a FINDINGS_LOW=()
declare -a FINDINGS_INFO=()
declare -a MISSING_TOOLS=()
declare -A FINDING_REGISTRY=()

finding() {
    local severity="$1" msg="$2" deduct="${3:-0}"
    local key
    key=$(echo "$msg" | md5sum 2>/dev/null | cut -d' ' -f1 || echo "${msg:0:80}")
    [ -n "${FINDING_REGISTRY[$key]}" ] && return
    FINDING_REGISTRY["$key"]=1
    case "$severity" in
        CRITICAL)
            FINDINGS_CRITICAL+=("$msg")
            DEDUCT_CRITICAL=$(( DEDUCT_CRITICAL + deduct ))
            ;;
        HIGH)
            FINDINGS_HIGH+=("$msg")
            DEDUCT_HIGH=$(( DEDUCT_HIGH + deduct ))
            ;;
        MEDIUM)
            FINDINGS_MEDIUM+=("$msg")
            DEDUCT_MEDIUM=$(( DEDUCT_MEDIUM + deduct ))
            ;;
        LOW)
            FINDINGS_LOW+=("$msg")
            DEDUCT_LOW=$(( DEDUCT_LOW + deduct ))
            ;;
        INFO)
            FINDINGS_INFO+=("$msg")
            ;;
    esac
}

bonus() {
    BONUS=$((BONUS + $1))
    FINDINGS_INFO+=("✓ BONUS +${1}: $2")
}

# ============================================================
title "0. Prerequisites & Tool Check"
# ============================================================

REQUIRED_MISSING=()
for tool in nmap curl dig openssl python3; do
    has "$tool" || REQUIRED_MISSING+=("$tool")
done

if [ ${#REQUIRED_MISSING[@]} -gt 0 ]; then
    err "Required tools missing: ${REQUIRED_MISSING[*]}"
    err "Install: sudo apt install ${REQUIRED_MISSING[*]} -y"
    exit 1
fi

OPTIONAL_LIST=(nikto ffuf sqlmap nuclei sublist3r amass whatweb testssl.sh wafw00f jq)
for tool in "${OPTIONAL_LIST[@]}"; do
    has "$tool" || MISSING_TOOLS+=("$tool")
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    warn "Optional tools not installed (some checks will be skipped):"
    for t in "${MISSING_TOOLS[@]}"; do
        plain "   ${Y}•${N} $t"
    done
fi

ok "Starting audit for: ${B}$TARGET${N}"
[ $SKIP_PORTS -eq 1 ] && info "Port scan: SKIPPED (--skip-ports)"
[ $SKIP_DIRS  -eq 1 ] && info "Dir scan: SKIPPED (--skip-dirs)"
[ $SKIP_SQLI  -eq 1 ] && info "SQLi check: SKIPPED (--skip-sqli)"
[ $SKIP_XSS   -eq 1 ] && info "XSS check: SKIPPED (--skip-xss)"

# ============================================================
title "1. Reconnaissance — DNS & IP Information"
# ============================================================

log "Collecting DNS / IP records ..."

IP_LIST=$(dig A "$TARGET" +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')
IPV6_LIST=$(dig AAAA "$TARGET" +short 2>/dev/null | grep -v '\.$')
NS_LIST=$(dig NS "$TARGET" +short 2>/dev/null)
MX_LIST=$(dig MX "$TARGET" +short 2>/dev/null)
TXT_LIST=$(dig TXT "$TARGET" +short 2>/dev/null)
DMARC=$(dig TXT "_dmarc.$TARGET" +short 2>/dev/null)
CNAME=$(dig CNAME "www.$TARGET" +short 2>/dev/null | grep -v '^$')

plain "  ${C}IPv4:${N}   ${IP_LIST:-Not found}"
plain "  ${C}IPv6:${N}   ${IPV6_LIST:-None}"
plain "  ${C}NS:${N}     ${NS_LIST:-None}"
plain "  ${C}MX:${N}     ${MX_LIST:-None}"
plain "  ${C}CNAME:${N}  ${CNAME:-None}"

if [ -z "$IP_LIST" ]; then
    err "No IP resolved for $TARGET — cannot continue"
    exit 1
fi

# Zone Transfer
log "Testing Zone Transfer ..."
ZONE_VULN=0
for ns in $NS_LIST; do
    ns="${ns%.}"    # strip trailing dot
    RESULT=$(dig AXFR "$TARGET" @"$ns" 2>/dev/null)
    # A successful AXFR returns actual DNS records (SOA, A, MX, etc.)
    # We check if we got real resource record lines (not just error messages)
    if echo "$RESULT" | grep -qE "^$TARGET\s+[0-9]+\s+IN\s+"; then
        plain "   ${R}[VULN]${N} $ns — Zone Transfer is OPEN!"
        ZONE_VULN=1
    else
        plain "   ${G}[OK]${N} $ns — Zone Transfer is closed"
    fi
done
[ "$ZONE_VULN" = "1" ] && finding CRITICAL "Zone Transfer open — full DNS zone exposed" 15

# SPF / DMARC
if echo "$TXT_LIST" | grep -qi "v=spf1"; then
    plain "   ${G}[OK]${N} SPF record present"
    SPF_OK=1
else
    warn "SPF record missing"
    finding MEDIUM "SPF record missing — Email Spoofing risk" 5
    SPF_OK=0
fi

if [ -n "$DMARC" ]; then
    plain "   ${G}[OK]${N} DMARC: $DMARC"
    DMARC_OK=1
    if echo "$DMARC" | grep -qi "p=reject";     then bonus 3 "DMARC policy=reject (strongest protection)"
    elif echo "$DMARC" | grep -qi "p=quarantine"; then bonus 2 "DMARC policy=quarantine"
    fi
else
    warn "DMARC record missing"
    finding MEDIUM "DMARC record missing — Email Spoofing risk" 5
    DMARC_OK=0
fi
[ "$SPF_OK" = "1" ] && [ "$DMARC_OK" = "1" ] && bonus 2 "Both SPF and DMARC configured"

# Subdomains via crt.sh — FIX: proper empty-check without grep -c
log "Fetching subdomains from Certificate Transparency (crt.sh) ..."
SUBDOMAINS_RAW=$(curl -s --max-time 20 \
    "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
    | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    names = set()
    for e in data:
        for n in e.get('name_value','').split('\n'):
            n = n.strip().lstrip('*.')
            if n and n != '$TARGET':
                names.add(n)
    for n in sorted(names):
        print(n)
except:
    pass
" 2>/dev/null)

SUBDOMAINS=$(echo "$SUBDOMAINS_RAW" | grep -v '^$' || true)
if [ -n "$SUBDOMAINS" ]; then
    SUB_COUNT=$(echo "$SUBDOMAINS" | wc -l)
    info "Found $SUB_COUNT unique subdomains via crt.sh"
else
    info "No subdomains found via crt.sh"
fi

# ============================================================
title "2. WAF / CDN Detection"
# ============================================================

log "Detecting WAF / CDN / Proxy ..."

# FIX: follow redirects (-L) and capture final headers properly
HEADERS_RAW=$(curl -sI -L --max-time "$CURL_TIMEOUT" \
    -A "Mozilla/5.0 (compatible; SecurityAudit/4.0)" \
    "https://$TARGET" 2>/dev/null)

# Also try HTTP in case HTTPS fails/redirects differently
if [ -z "$HEADERS_RAW" ]; then
    HEADERS_RAW=$(curl -sI -L --max-time "$CURL_TIMEOUT" \
        -A "Mozilla/5.0 (compatible; SecurityAudit/4.0)" \
        "http://$TARGET" 2>/dev/null)
fi

CF_RAY=$(echo "$HEADERS_RAW"    | grep -i "^cf-ray:")
CLOUDFRONT=$(echo "$HEADERS_RAW" | grep -i "x-amz\|x-cache.*cloudfront\|via.*cloudfront")
GOOGLE_FRONT=$(echo "$HEADERS_RAW" | grep -i "server:.*gws\|server:.*Google Frontend\|x-goog-")
FASTLY=$(echo "$HEADERS_RAW"    | grep -i "x-fastly\|x-served-by.*cache")
SUCURI=$(echo "$HEADERS_RAW"    | grep -i "x-sucuri\|server:.*Sucuri")
AKAMAI=$(echo "$HEADERS_RAW"    | grep -i "x-akamai\|akamai-grn\|x-check-cacheable")
AZURE=$(echo "$HEADERS_RAW"     | grep -i "x-azure-\|x-msedge-\|x-fd-healthprobe")
IMPERVA=$(echo "$HEADERS_RAW"   | grep -i "x-iinfo:\|incap-ses\|visid_incap")
BUNNY=$(echo "$HEADERS_RAW"     | grep -i "bunny-\|bunnyCDN\|server:.*BunnyCDN")

BEHIND_CDN=0
CDN_NAME=""

if   [ -n "$CF_RAY" ];      then CDN_NAME="Cloudflare";        BEHIND_CDN=1; ok "Behind ${B}Cloudflare${N}"
elif [ -n "$CLOUDFRONT" ];  then CDN_NAME="AWS CloudFront";     BEHIND_CDN=1; ok "Behind ${B}AWS CloudFront${N}"
elif [ -n "$GOOGLE_FRONT" ];then CDN_NAME="Google Frontend";    BEHIND_CDN=1; ok "Behind ${B}Google Frontend / GFE${N}"
elif [ -n "$FASTLY" ];      then CDN_NAME="Fastly";             BEHIND_CDN=1; ok "Behind ${B}Fastly${N}"
elif [ -n "$SUCURI" ];      then CDN_NAME="Sucuri WAF";         BEHIND_CDN=1; ok "Behind ${B}Sucuri WAF${N}"
elif [ -n "$AKAMAI" ];      then CDN_NAME="Akamai";             BEHIND_CDN=1; ok "Behind ${B}Akamai${N}"
elif [ -n "$AZURE" ];       then CDN_NAME="Azure Front Door";   BEHIND_CDN=1; ok "Behind ${B}Azure Front Door${N}"
elif [ -n "$IMPERVA" ];     then CDN_NAME="Imperva/Incapsula";  BEHIND_CDN=1; ok "Behind ${B}Imperva WAF${N}"
elif [ -n "$BUNNY" ];       then CDN_NAME="BunnyCDN";           BEHIND_CDN=1; ok "Behind ${B}BunnyCDN${N}"
else
    info "No known WAF/CDN detected via headers"
    if has wafw00f; then
        wafw00f "https://$TARGET" 2>/dev/null | grep -v "^$" | tail -5
    fi
fi

if [ "$BEHIND_CDN" = "1" ]; then
    bonus 8 "Protected by $CDN_NAME (DDoS mitigation, WAF, edge security)"
    finding INFO "Server is behind $CDN_NAME CDN — some scans limited"
    warn "Behind $CDN_NAME — port scan and TLS checks are against CDN edge, not origin"
    warn "To find real origin IP: check DNS history, MX/TXT records, subdomains, Shodan"

    # HTTP/2 support check (bonus for modern protocol)
    H2_CHECK=$(curl -sI --http2 --max-time "$CURL_TIMEOUT" \
        -A "Mozilla/5.0" "https://$TARGET" 2>/dev/null | grep -i "^HTTP/2")
    [ -n "$H2_CHECK" ] && bonus 2 "HTTP/2 supported"

    # Try real IP via MX
    if [ -n "$MX_LIST" ]; then
        log "Checking for real IP leak via MX records ..."
        while read -r mx; do
            mx_host=$(echo "$mx" | awk '{print $NF}' | sed 's/\.$//')
            [ -z "$mx_host" ] && continue
            mx_ip=$(dig A "$mx_host" +short 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
            if [ -n "$mx_ip" ]; then
                if ! echo "$IP_LIST" | grep -q "$mx_ip"; then
                    plain "   ${Y}[Possible Origin]${N} $mx_host -> $mx_ip (differs from CDN IPs)"
                fi
            fi
        done <<< "$MX_LIST"
    fi
else
    # HTTP/2 support check for non-CDN sites
    H2_CHECK=$(curl -sI --http2 --max-time "$CURL_TIMEOUT" \
        -A "Mozilla/5.0" "https://$TARGET" 2>/dev/null | grep -i "^HTTP/2")
    [ -n "$H2_CHECK" ] && bonus 2 "HTTP/2 supported"
fi

# DNSSEC check
DNSSEC=$(dig A "$TARGET" +dnssec +short 2>/dev/null | grep -E "RRSIG|DNSKEY")
if [ -n "$DNSSEC" ]; then
    bonus 2 "DNSSEC enabled — DNS records cryptographically signed"
    ok "DNSSEC is enabled"
else
    info "DNSSEC not detected (optional but recommended)"
fi

# ============================================================
title "3. Port Scan"
# ============================================================

if [ $SKIP_PORTS -eq 1 ]; then
    info "Port scan skipped (--skip-ports)"
elif [ "$BEHIND_CDN" = "1" ]; then
    warn "Port scan SKIPPED — IPs resolve to $CDN_NAME edge (results meaningless)"
    info "Resolve real origin IP first, then re-run with that IP directly"
else
    log "Port scanning resolved IPs ..."
    for IP in $IP_LIST; do
        plain ""
        log "Scanning $IP ..."
        NMAP_OUT=$(nmap -sV -sC --open -T4 --top-ports 1000 \
            --script-timeout 10s "$IP" 2>/dev/null)
        echo "$NMAP_OUT" | grep -E "^[0-9]+/|open|filtered" | head -50

        while IFS= read -r line; do
            PORT=$(echo "$line" | awk '{print $1}')
            case "$PORT" in
                21/*)
                    finding HIGH "FTP open ($IP:21) — check anonymous login" 8
                    # FTP anonymous login check
                    FTP_ANON=$(timeout 5 bash -c "echo -e 'USER anonymous\nPASS test@test.com\nQUIT' | nc -w3 $IP 21 2>/dev/null" | grep -E "^230|Login successful")
                    if [ -n "$FTP_ANON" ]; then
                        finding CRITICAL "FTP anonymous login ALLOWED on $IP:21 — public read/write access!" 20
                        warn "FTP ANONYMOUS LOGIN ENABLED! Anyone can connect without credentials."
                    fi ;;
                22/*)    info "SSH open ($IP:22) — check for weak credentials/old versions" ;;
                23/*)    finding CRITICAL "Telnet open ($IP:23) — cleartext protocol" 15 ;;
                25/*)
                    finding MEDIUM "SMTP open ($IP:25) — check open relay" 5
                    # SMTP open relay check
                    RELAY=$(timeout 8 bash -c "echo -e 'EHLO test.com\nMAIL FROM: test@test.com\nRCPT TO: victim@external.com\nQUIT' | nc -w4 $IP 25 2>/dev/null" | grep -E "^250.*RCPT|relay accepted")
                    if [ -n "$RELAY" ]; then
                        finding HIGH "SMTP open relay detected on $IP:25 — can send spam as this domain" 10
                        warn "SMTP OPEN RELAY! Can be used to send spam/phishing as $TARGET"
                    fi ;;
                110/*)   finding LOW      "POP3 plain open ($IP:110) — use 995/TLS instead" 2 ;;
                143/*)   finding LOW      "IMAP plain open ($IP:143) — use 993/TLS instead" 2 ;;
                445/*)   finding HIGH     "SMB/CIFS open ($IP:445) — ransomware attack surface" 10 ;;
                1433/*)  finding HIGH     "MSSQL directly accessible ($IP:1433)" 10 ;;
                3306/*)  finding HIGH     "MySQL directly accessible ($IP:3306)" 10 ;;
                3389/*)  finding HIGH     "RDP exposed ($IP:3389) — brute-force/BlueKeep risk" 10 ;;
                5432/*)  finding HIGH     "PostgreSQL directly accessible ($IP:5432)" 10 ;;
                6379/*)
                    finding CRITICAL "Redis accessible ($IP:6379) — likely unauthenticated" 15
                    # Redis auth check
                    REDIS_RESP=$(timeout 5 bash -c "echo -e 'PING\r\nQUIT\r\n' | nc -w3 $IP 6379 2>/dev/null" | grep "+PONG")
                    if [ -n "$REDIS_RESP" ]; then
                        finding CRITICAL "Redis UNAUTHENTICATED on $IP:6379 — full data access!" 20
                    fi ;;
                8443/*)  info "HTTPS-alt port 8443 open ($IP:8443) — check for separate service" ;;
                8080/*)  finding MEDIUM   "Dev/proxy port 8080 open ($IP:8080)" 5 ;;
                8888/*)  finding MEDIUM   "Dev port 8888 open ($IP:8888) — possible Jupyter/dev server" 5 ;;
                27017/*) finding HIGH     "MongoDB accessible ($IP:27017)" 10 ;;
                9200/*)
                    finding HIGH "Elasticsearch accessible ($IP:9200)" 10
                    ES_UNAUTH=$(curl -sk --max-time 5 "http://$IP:9200/" 2>/dev/null | grep -i "cluster_name\|tagline")
                    if [ -n "$ES_UNAUTH" ]; then
                        finding CRITICAL "Elasticsearch UNAUTHENTICATED on $IP:9200 — all data exposed!" 20
                    fi ;;
                9300/*)  finding HIGH     "Elasticsearch cluster port open ($IP:9300)" 8 ;;
                2375/*)  finding CRITICAL "Docker API exposed ($IP:2375) — container escape risk" 20 ;;
                2376/*)  finding HIGH     "Docker TLS API exposed ($IP:2376) — verify auth" 10 ;;
                4243/*)  finding CRITICAL "Docker API exposed ($IP:4243) — container escape risk" 20 ;;
                5984/*)  finding HIGH     "CouchDB accessible ($IP:5984)" 8 ;;
                5601/*)  finding HIGH     "Kibana exposed ($IP:5601) — may expose Elasticsearch data" 8 ;;
                9090/*)  finding MEDIUM   "Prometheus/admin port 9090 open ($IP:9090)" 5 ;;
                11211/*) finding HIGH     "Memcached accessible ($IP:11211) — amplification DDoS risk" 10 ;;
                50000/*) finding HIGH     "Jenkins possibly exposed ($IP:50000)" 10 ;;
            esac
            [ -n "$PORT" ] && warn "Potentially dangerous port: $line"
        done < <(echo "$NMAP_OUT" | grep "open" | grep -E \
            "21/|23/|25/|110/|143/|445/|1433/|3306/|3389/|5432/|6379/|8080/|8888/|27017/|9200/|9300/|2375/|2376/|4243/|5984/|5601/|9090/|11211/|50000/")

        log "UDP scan (key ports) ..."
        # FIX: warn if not root — UDP scan needs privilege for accurate results
        if [ "$(id -u)" -ne 0 ]; then
            warn "UDP scan requires root/sudo for accurate results — running with limited accuracy"
            nmap -sU --open -T4 -p 53,161,500,1194,5353,1900 "$IP" 2>/dev/null \
                | grep -E "open" | grep -v "^$" || info "No open UDP ports detected (may be inaccurate without root)"
        else
            nmap -sU --open -T4 -p 53,161,500,1194,5353,1900 "$IP" 2>/dev/null \
                | grep -E "open" | grep -v "^$"
        fi
    done
fi

# ============================================================
title "4. TLS / SSL Analysis"
# ============================================================

log "Analyzing TLS/SSL certificate ..."

# FIX: use `timeout` wrapper instead of invalid -timeout flag
CERT_INFO=$(timeout 10 openssl s_client \
    -connect "$TARGET:443" \
    -servername "$TARGET" \
    </dev/null 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null)

SSL_OK=0
if [ -n "$CERT_INFO" ]; then
    SSL_OK=1
    echo "$CERT_INFO"
    EXPIRE_DATE=$(echo "$CERT_INFO" | grep "notAfter" | cut -d= -f2-)
    if [ -n "$EXPIRE_DATE" ]; then
        EXPIRE_EPOCH=$(date -d "$EXPIRE_DATE" +%s 2>/dev/null \
            || date -j -f "%b %d %T %Y %Z" "$EXPIRE_DATE" +%s 2>/dev/null)
        NOW_EPOCH=$(date +%s)
        DAYS_LEFT=$(( (EXPIRE_EPOCH - NOW_EPOCH) / 86400 ))
        if   [ "$DAYS_LEFT" -lt 0 ];  then finding CRITICAL "SSL cert EXPIRED ($((DAYS_LEFT * -1)) days ago)" 20; err "SSL cert EXPIRED!"
        elif [ "$DAYS_LEFT" -lt 14 ]; then finding CRITICAL "SSL cert expires in $DAYS_LEFT days" 15; warn "SSL cert expires in $DAYS_LEFT days!"
        elif [ "$DAYS_LEFT" -lt 30 ]; then finding HIGH    "SSL cert expires in $DAYS_LEFT days" 10; warn "SSL cert expires in $DAYS_LEFT days"
        else ok "SSL cert valid ($DAYS_LEFT days remaining)"
        fi
    fi

    # Check certificate issuer (self-signed = no CA trust)
    CERT_ISSUER=$(echo "$CERT_INFO" | grep "^issuer" | head -1)
    CERT_SUBJECT=$(echo "$CERT_INFO" | grep "^subject" | head -1)
    if [ "$CERT_ISSUER" = "$CERT_SUBJECT" ]; then
        finding HIGH "Self-signed certificate detected — no trusted CA" 8
        warn "Self-signed certificate! Browsers will show security warnings."
    fi
    # Check for wildcard cert (informational)
    CERT_CN=$(echo "$CERT_INFO" | grep -oE 'CN\s*=\s*\*\.[^ ,]+')
    [ -n "$CERT_CN" ] && info "Wildcard certificate detected: $CERT_CN"
else
    finding HIGH "SSL/TLS unreachable or broken on port 443" 10
    err "Could not establish SSL connection"
fi

# TLS protocol check — verify actual cipher negotiation, not just TCP connection
plain ""
log "Checking for weak/deprecated TLS protocols ..."
if [ "$BEHIND_CDN" = "1" ]; then
    info "TLS checks are performed against CDN edge infrastructure"
fi

for proto in ssl2 ssl3 tls1 tls1_1; do
    # FIX: check for actual cipher negotiation (not just CONNECTED which can appear even when proto rejected)
    RES=$(timeout 8 openssl s_client \
        -connect "$TARGET:443" \
        -"$proto" \
        -servername "$TARGET" \
        </dev/null 2>&1)
    # Protocol is truly enabled only if a cipher was actually negotiated
    if echo "$RES" | grep -qE "^\s*Cipher\s*:\s*[A-Z0-9]" || echo "$RES" | grep -qE "Cipher is [A-Z0-9]"; then
        vuln "$proto is ENABLED!"
        case "$proto" in
            ssl2|ssl3)
                finding CRITICAL "Protocol $proto enabled — POODLE/DROWN attack possible" 15 ;;
            tls1|tls1_1)
                if [ "$BEHIND_CDN" = "1" ]; then
                    finding LOW "Protocol $proto enabled on CDN edge (ask CDN provider to disable)" 2
                else
                    finding MEDIUM "Protocol $proto enabled on server — deprecated, disable it" 5
                fi ;;
        esac
    elif echo "$RES" | grep -qiE "no protocols available|ssl alert|handshake failure|unsupported protocol|wrong version"; then
        plain "   ${G}[OK]${N} $proto is disabled"
    elif echo "$RES" | grep -q "CONNECTED"; then
        # Connected but no cipher → server rejected the protocol version (correct behaviour)
        plain "   ${G}[OK]${N} $proto — connection made but protocol rejected by server"
    else
        plain "   ${G}[OK]${N} $proto is disabled (no response)"
    fi
done

# HSTS check (redirect-aware)
HSTS=$(echo "$FINAL_HEADERS" | grep -i "^strict-transport-security:" | tail -1)

HSTS_REGISTERED=0
if [ -n "$HSTS" ]; then
    ok "HSTS present: $HSTS"
    HSTS_REGISTERED=1

    MAX_AGE=$(echo "$HSTS" | grep -oiE "max-age=[0-9]+" | grep -oE "[0-9]+")

    if echo "$HSTS" | grep -qi "preload"; then
        bonus 5 "HSTS preload enabled"
    elif [ -n "$MAX_AGE" ] && [ "$MAX_AGE" -ge 31536000 ]; then
        bonus 3 "Strong HSTS max-age"
    fi
else
    if [ "$BEHIND_CDN" = "1" ]; then
        finding MEDIUM "HSTS header not observed on CDN edge" 4
    else
        finding HIGH "HSTS missing — SSL Strip attack possible" 8
    fi
fi

if has testssl.sh; then
    log "Running testssl.sh ..."
    testssl.sh --quiet --color 0 --warnings off \
        --protocols --headers "$TARGET" 2>/dev/null \
        | grep -E "VULNERABLE|WARN|OK" | head -25
fi

# ============================================================
title "5. HTTP Security Headers"
# ============================================================

log "Checking security headers ..."

# CSP: check report-only before main loop
CSP_REPORT_ONLY=$(echo "$HEADERS_RAW" | grep -i "^content-security-policy-report-only" | tr -d '\r')
CSP_ENFORCED=$(echo "$HEADERS_RAW" | grep -i "^content-security-policy:" | grep -iv "report-only" | tr -d '\r')
CSP_REPORT_ONLY_MODE=0

if [ -n "$CSP_ENFORCED" ]; then
    : # handled in loop below as PRESENT
elif [ -n "$CSP_REPORT_ONLY" ]; then
    plain "   ${Y}[PARTIAL]${N} Content-Security-Policy-Report-Only present (not enforced yet)"
    finding LOW "CSP in report-only mode — convert to Content-Security-Policy" 3
    CSP_REPORT_ONLY_MODE=1
fi

declare -A HEADER_DESC=(
    ["Strict-Transport-Security"]="HSTS — prevents SSL downgrade attacks"
    ["Content-Security-Policy"]="CSP — prevents XSS and data injection"
    ["X-Frame-Options"]="Clickjacking protection"
    ["X-Content-Type-Options"]="MIME sniffing protection"
    ["Referrer-Policy"]="Controls Referer leakage"
    ["Permissions-Policy"]="Controls browser feature access"
    ["Cross-Origin-Opener-Policy"]="COOP — cross-tab isolation"
    ["Cross-Origin-Resource-Policy"]="CORP — resource isolation"
    ["Cross-Origin-Embedder-Policy"]="COEP — embedding isolation"
)
declare -A HEADER_SEVERITY=(
    ["Strict-Transport-Security"]="HIGH"
    ["Content-Security-Policy"]="HIGH"
    ["X-Frame-Options"]="MEDIUM"
    ["X-Content-Type-Options"]="MEDIUM"
    ["Referrer-Policy"]="LOW"
    ["Permissions-Policy"]="INFO"
    ["Cross-Origin-Opener-Policy"]="INFO"
    ["Cross-Origin-Resource-Policy"]="INFO"
    ["Cross-Origin-Embedder-Policy"]="INFO"
)
declare -A HEADER_DEDUCT=(
    ["Strict-Transport-Security"]="0"
    ["Content-Security-Policy"]="8"
    ["X-Frame-Options"]="4"
    ["X-Content-Type-Options"]="3"
    ["Referrer-Policy"]="2"
    ["Permissions-Policy"]="1"
    ["Cross-Origin-Opener-Policy"]="1"
    ["Cross-Origin-Resource-Policy"]="1"
    ["Cross-Origin-Embedder-Policy"]="1"
)

for h in "${!HEADER_DESC[@]}"; do
    val=$(echo "$HEADERS_RAW" | grep -i "^${h}:" | head -1 | tr -d '\r')
    if [ -n "$val" ]; then
        plain "   ${G}[PRESENT]${N} $val"
    else
        plain "   ${R}[MISSING]${N} ${B}$h${N} — ${HEADER_DESC[$h]}"
        if   [ "$h" = "Strict-Transport-Security" ] && [ "$HSTS_REGISTERED" = "1" ]; then
            : # already counted
        elif [ "$h" = "Content-Security-Policy" ]   && [ "$CSP_REPORT_ONLY_MODE" = "1" ]; then
            : # already counted as LOW
        else
            if [[ "$h" =~ ^(Cross-Origin-Opener-Policy|Cross-Origin-Resource-Policy|Cross-Origin-Embedder-Policy|Permissions-Policy)$ ]]; then
            info "Optional modern header missing: $h"
        else
            finding "${HEADER_SEVERITY[$h]}" "Missing header: $h — ${HEADER_DESC[$h]}" "${HEADER_DEDUCT[$h]}"
        fi
        fi
    fi
done

# Bonus: header hygiene
CORE_PRESENT=0
for h in "Content-Security-Policy" "X-Frame-Options" "X-Content-Type-Options" "Cross-Origin-Opener-Policy"; do
    [ -n "$(echo "$HEADERS_RAW" | grep -i "^${h}:" | head -1)" ] && CORE_PRESENT=$((CORE_PRESENT + 1))
done
[ "$CORE_PRESENT" -ge 3 ] && bonus 3 "Good HTTP security header hygiene ($CORE_PRESENT/4 core headers)"
[ "$CORE_PRESENT" -eq 4 ] && bonus 2 "All 4 core security headers present"

# CSP quality check — bonus if strict CSP (no unsafe-inline/unsafe-eval)
if [ -n "$CSP_ENFORCED" ]; then
    if ! echo "$CSP_ENFORCED" | grep -qi "unsafe-inline\|unsafe-eval"; then
        bonus 3 "CSP enforced without unsafe-inline/unsafe-eval (strict policy)"
    else
        info "CSP present but uses unsafe-inline or unsafe-eval — consider tightening"
    fi
fi

# Server info leakage — FIX: CDN server headers (cloudflare, gws) are not real server leaks
plain ""
log "Checking for server information leakage ..."
SERVER_LEAK=$(echo "$HEADERS_RAW" | grep -iE "^server:|^x-powered-by:|^x-aspnet|^x-runtime:|^x-generator:" | tr -d '\r')
if [ -n "$SERVER_LEAK" ]; then
    # FIX: if behind CDN, the server header is just the CDN's own identity — not a real leak
    if [ "$BEHIND_CDN" = "1" ]; then
        info "Server header shows CDN identity (expected for $CDN_NAME):"
        echo "$SERVER_LEAK" | while IFS= read -r line; do
            plain "   ${C}->  $line${N}"
        done
        # Only flag x-powered-by as a real leak even behind CDN
        echo "$SERVER_LEAK" | grep -qi "x-powered-by\|x-aspnet\|x-runtime\|x-generator" && \
            finding LOW "Backend technology version leaked via x-powered-by or similar header" 2
    else
        warn "Server/technology info leaked in headers:"
        echo "$SERVER_LEAK" | while IFS= read -r line; do
            plain "   ${Y}->  $line${N}"
        done
        finding LOW "Server/technology version exposed in headers" 2
    fi
else
    ok "No server technology information leaked"
fi

# Cookie security check
plain ""
log "Checking cookie security flags ..."
COOKIES=$(curl -sI --max-time "$CURL_TIMEOUT" \
    -A "Mozilla/5.0" "https://$TARGET" 2>/dev/null \
    | grep -i "^set-cookie:" | tr -d '\r')
if [ -n "$COOKIES" ]; then
    COOKIE_HTTPONLY_MISS=0
    COOKIE_SECURE_MISS=0
    COOKIE_SAMESITE_MISS=0
    while IFS= read -r cookie; do
        cname=$(echo "$cookie" | sed 's/[Ss]et-[Cc]ookie: //;s/=.*//')
        if ! echo "$cookie" | grep -qi "httponly"; then
            warn "Cookie '$cname' missing HttpOnly flag"
            COOKIE_HTTPONLY_MISS=1
        fi
        if ! echo "$cookie" | grep -qi "secure"; then
            warn "Cookie '$cname' missing Secure flag"
            COOKIE_SECURE_MISS=1
        fi
        if ! echo "$cookie" | grep -qi "samesite"; then
            info "Cookie '$cname' missing SameSite attribute"
            COOKIE_SAMESITE_MISS=1
        fi
    done <<< "$COOKIES"
    # Deduct once per flag category (not per cookie) to avoid runaway scoring
    [ "$COOKIE_HTTPONLY_MISS" = "1" ] && finding MEDIUM "One or more cookies missing HttpOnly — JS-readable session token risk" 3
    [ "$COOKIE_SECURE_MISS"   = "1" ] && finding MEDIUM "One or more cookies missing Secure flag — may transmit over HTTP" 3
    [ "$COOKIE_SAMESITE_MISS" = "1" ] && finding LOW    "One or more cookies missing SameSite — CSRF exposure" 1
else
    info "No Set-Cookie headers found on homepage"
fi

# ============================================================
title "6. Technology Fingerprinting"
# ============================================================

log "Identifying site technologies ..."

if has whatweb; then
    whatweb -a 3 "https://$TARGET" 2>/dev/null | grep -v "^$"
else
    PAGE=$(curl -sk --max-time 15 -A "Mozilla/5.0" "https://$TARGET" 2>/dev/null)
    TECHS=()
    echo "$PAGE" | grep -qi "django\|csrfmiddlewaretoken" && TECHS+=("Django")
    echo "$PAGE" | grep -qi "__reactFiber\|react-root"   && TECHS+=("React")
    echo "$PAGE" | grep -qi "__vue__\|vue\.js"            && TECHS+=("Vue.js")
    echo "$PAGE" | grep -qi "ng-version\|angular"         && TECHS+=("Angular")
    echo "$PAGE" | grep -qi "wp-content\|wordpress"       && TECHS+=("WordPress")
    echo "$PAGE" | grep -qi "joomla"                       && TECHS+=("Joomla")
    echo "$PAGE" | grep -qi "drupal"                       && TECHS+=("Drupal")
    echo "$PAGE" | grep -qi "jquery"                       && TECHS+=("jQuery")
    echo "$PAGE" | grep -qi "bootstrap"                    && TECHS+=("Bootstrap")
    echo "$PAGE" | grep -qi "__NEXT_DATA__"                && TECHS+=("Next.js")
    echo "$PAGE" | grep -qi "nuxt"                         && TECHS+=("Nuxt.js")
    echo "$PAGE" | grep -qi "laravel_session\|laravel"     && TECHS+=("Laravel")
    echo "$PAGE" | grep -qi "rails\|authenticity_token"   && TECHS+=("Ruby on Rails")
    if [ ${#TECHS[@]} -gt 0 ]; then
        info "Detected: ${TECHS[*]}"
    else
        info "No specific technologies identified from HTML"
    fi
fi

log "Checking robots.txt ..."
ROBOTS=$(curl -sk --max-time 10 -L "https://$TARGET/robots.txt" 2>/dev/null)
if [ -n "$ROBOTS" ] && ! echo "$ROBOTS" | grep -qi "<html\|404"; then
    echo "$ROBOTS" | head -20
    DISALLOWED=$(echo "$ROBOTS" | grep -ic "^Disallow:")
    info "$DISALLOWED Disallow entries in robots.txt"
    # Check for sensitive paths in robots
    if echo "$ROBOTS" | grep -qiE "admin|backup|config|database|secret|private"; then
        warn "robots.txt reveals potentially sensitive path(s)"
        finding LOW "robots.txt exposes sensitive directory names" 2
    fi
else
    info "robots.txt not found or empty"
fi

# ============================================================
title "7. Directory & Sensitive File Discovery"
# ============================================================

if [ $SKIP_DIRS -eq 1 ]; then
    info "Directory scan skipped (--skip-dirs)"
else
    log "Checking for exposed sensitive files ..."

    SENSITIVE_PATHS=(
        "/.env" "/.env.bak" "/.env.prod" "/.env.local" "/.env.example" "/.env.backup"
        "/settings.py" "/local_settings.py" "/config.py" "/config.json" "/config.yml" "/config.yaml"
        "/requirements.txt" "/Pipfile" "/Pipfile.lock" "/composer.json" "/package.json"
        "/manage.py" "/wsgi.py" "/asgi.py"
        "/db.sqlite3" "/database.db" "/dump.sql" "/backup.sql" "/db.sql" "/data.sql"
        "/docker-compose.yml" "/docker-compose.yaml" "/Dockerfile" "/.dockerenv"
        "/.git/" "/.git/config" "/.git/HEAD" "/.git/COMMIT_EDITMSG"
        "/.svn/" "/.hg/" "/.bzr/"
        "/backup/" "/backups/" "/backup.zip" "/site.tar.gz" "/www.tar.gz"
        "/logs/" "/debug.log" "/error.log" "/access.log" "/app.log"
        "/admin/" "/admin/login/" "/wp-admin/" "/wp-login.php" "/xmlrpc.php"
        "/phpinfo.php" "/info.php" "/test.php" "/php-info.php"
        "/.htaccess" "/.htpasswd"
        "/server-status" "/server-info" "/nginx_status" "/stub_status"
        "/api/" "/api/v1/" "/api/v2/" "/graphql" "/graphql/"
        "/swagger/" "/swagger.json" "/swagger.yaml" "/openapi.json" "/openapi.yaml" "/redoc/"
        "/__debug__/" "/phpmyadmin/" "/pma/" "/adminer.php"
        "/security.txt" "/.well-known/security.txt"
        "/crossdomain.xml" "/clientaccesspolicy.xml"
        "/.aws/credentials" "/id_rsa" "/.ssh/id_rsa"
    )

    EXPOSED_COUNT=0
    for path in "${SENSITIVE_PATHS[@]}"; do
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
            -A "Mozilla/5.0 (compatible; SecurityAudit/3.0)" \
            --max-time 8 \
            --connect-timeout 5 \
            "https://$TARGET$path" 2>/dev/null)
        # Only flag 200, 201, 204 as definite exposures
        # Flag 301/302/403 as informational (might still be meaningful)
        case "$STATUS" in
            200|201|204)
                printf "   ${R}[HTTP %-3s]${N}  %s\n" "$STATUS" "$path"
                EXPOSED_COUNT=$((EXPOSED_COUNT + 1))
                case "$path" in
                    */.env*|*/config.json*|*/settings.py*|*/.aws*|*/id_rsa*)
                        finding CRITICAL "Sensitive file exposed: $path (HTTP $STATUS)" 20 ;;
                    */.git/*|*/.svn/*|*/.hg/*)
                        finding CRITICAL "VCS repository exposed: $path (HTTP $STATUS)" 20 ;;
                    */db.sqlite3*|*/database.db*|*dump.sql*|*/data.sql*)
                        finding CRITICAL "Database file exposed: $path (HTTP $STATUS)" 25 ;;
                    */phpinfo.php*|*/info.php*)
                        finding HIGH "PHP info page exposed: $path (HTTP $STATUS)" 10 ;;
                    */swagger*|*/openapi*|*/redoc*|*/graphql*)
                        finding MEDIUM "API docs/endpoint public: $path (HTTP $STATUS)" 3 ;;
                    */admin/*|*/wp-admin/*)
                        finding MEDIUM "Admin panel accessible: $path (HTTP $STATUS)" 3 ;;
                esac
                ;;
            301|302|307)
                printf "   ${Y}[HTTP %-3s]${N}  %s (redirect)\n" "$STATUS" "$path" ;;
            403)
                printf "   ${M}[HTTP %-3s]${N}  %s (forbidden — exists but blocked)\n" "$STATUS" "$path" ;;
            # 404, 410, 000 = not found / no connection — skip silently
        esac
    done
    [ "$EXPOSED_COUNT" -eq 0 ] && ok "No directly exposed sensitive files found"

    if has ffuf; then
        WORDLIST=""
        for wl in \
            /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
            /usr/share/seclists/Discovery/Web-Content/common.txt \
            /usr/share/wordlists/dirb/common.txt \
            /usr/share/dirb/wordlists/common.txt; do
            [ -f "$wl" ] && WORDLIST="$wl" && break
        done
        if [ -n "$WORDLIST" ]; then
            log "Running ffuf with wordlist ..."
            ffuf -u "https://$TARGET/FUZZ" -w "$WORDLIST" \
                -mc 200,201,204,301,302,307,401,403 \
                -t 40 -timeout 10 -s 2>/dev/null | head -20 \
                | while IFS= read -r line; do
                    plain "   ${C}[ffuf]${N} $line"
                done
        else
            info "No wordlist found for ffuf (install seclists or dirb)"
        fi
    fi
fi

# ============================================================
title "8. CORS Misconfiguration"
# ============================================================

log "Testing CORS misconfiguration ..."

CORS_VULN=0
# Test multiple origins including subdomain-of-target tricks
for ORIGIN in \
    "https://evil.com" \
    "https://evil.${TARGET}" \
    "https://${TARGET}.evil.com" \
    "null" \
    "http://${TARGET}"; do

    CORS_RESP=$(curl -sI --max-time "$CURL_TIMEOUT" \
        "https://$TARGET/" \
        -H "Origin: $ORIGIN" \
        -H "Access-Control-Request-Method: GET" \
        2>/dev/null | grep -i "access-control-allow" | tr -d '\r')

    if [ -n "$CORS_RESP" ]; then
        ACAO=$(echo "$CORS_RESP" | grep -i "allow-origin" | awk '{print $2}')
        ACAC=$(echo "$CORS_RESP" | grep -i "allow-credentials" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
        if echo "$ACAO" | grep -qE "evil\.com|\*"; then
            plain "   ${R}[VULN]${N} CORS accepts $ORIGIN  →  $CORS_RESP"
            # Credentials + wildcard is most dangerous
            if [ "$ACAC" = "true" ] && [ "$ACAO" = "*" ]; then
                finding CRITICAL "CORS wildcard with credentials=true — cookie theft possible" 20
            else
                finding HIGH "CORS misconfiguration: $ORIGIN accepted" 10
            fi
            CORS_VULN=1
        elif echo "$ACAO" | grep -q "$TARGET"; then
            plain "   ${G}[OK]${N} Origin: $ORIGIN — reflected but scoped to target domain"
        elif [ -n "$ACAO" ]; then
            plain "   ${G}[OK]${N} Origin: $ORIGIN — restricted ($ACAO)"
        fi
    fi
done
[ "$CORS_VULN" = "0" ] && ok "CORS configuration looks safe"

# ============================================================
title "9. SQL Injection (Basic Check)"
# ============================================================

if [ $SKIP_SQLI -eq 1 ]; then
    info "SQLi check skipped (--skip-sqli)"
elif has sqlmap; then
    warn "SQLMap installed — tip: run manually for deeper scan:"
    info "sqlmap -u \"https://$TARGET/?q=1\" --forms --level=2 --risk=1 --batch --crawl=3"
    log "Running quick SQLMap check (30s hard limit, no crawl) ..."
    SQLI_RESULT=$(timeout 30 sqlmap \
        -u "https://$TARGET/?q=1&id=1&search=test" \
        --level=1 --risk=1 \
        --technique=BET \
        --batch --random-agent \
        --timeout=8 --retries=1 \
        --no-cast --no-escape \
        --output-dir="/tmp/sqlmap_$$" 2>/dev/null | tail -10)
    if echo "$SQLI_RESULT" | grep -qiE "vulnerable|injection|parameter"; then
        echo "$SQLI_RESULT" | grep -iE "vulnerable|injection|parameter" | while IFS= read -r line; do
            plain "   ${R}[SQLI]${N} $line"
            finding CRITICAL "SQL Injection detected: $line" 20
        done
    else
        ok "SQLMap: no injection found in quick parameter test"
    fi
    rm -rf "/tmp/sqlmap_$$" 2>/dev/null
else
    log "Testing basic SQLi indicators (manual payloads) ..."
    # FIX: Use a realistic baseline first to calibrate timing
    BASELINE_TIMES=()
    for i in 1 2 3; do
        T0=$(date +%s%3N)
        curl -sk -o /dev/null --max-time 8 "https://$TARGET/" 2>/dev/null
        T1=$(date +%s%3N)
        BASELINE_TIMES+=($((T1 - T0)))
    done
    # Average baseline
    BASELINE_AVG=$(python3 -c "times=[${BASELINE_TIMES[*]}]; print(int(sum(times)/len(times)))" 2>/dev/null || echo "500")
    # Dynamic threshold: baseline + 3 seconds (generous for network jitter)
    TIME_THRESHOLD=$(( BASELINE_AVG + 3000 ))
    info "Network baseline: ~${BASELINE_AVG}ms — timing threshold: ${TIME_THRESHOLD}ms"

    SQLI_PAYLOADS=("'" "\"" "1 OR 1=1" "1' OR '1'='1" "1 AND SLEEP(5)--" "1; SELECT SLEEP(5)--")
    SQLI_FOUND=0
    for payload in "${SQLI_PAYLOADS[@]}"; do
        ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
        [ -z "$ENCODED" ] && continue
        T0=$(date +%s%3N)
        RES=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 12 \
            "https://$TARGET/?q=$ENCODED&search=$ENCODED" 2>/dev/null)
        T1=$(date +%s%3N)
        ELAPSED=$((T1 - T0))

        if [ "$ELAPSED" -gt "$TIME_THRESHOLD" ]; then
            warn "Possible time-based SQLi: payload='$payload' elapsed=${ELAPSED}ms (threshold=${TIME_THRESHOLD}ms)"
            finding HIGH "Possible time-based SQL Injection (payload: $payload, ${ELAPSED}ms)" 10
            SQLI_FOUND=1
        elif [ "$RES" = "500" ]; then
            warn "HTTP 500 on SQLi payload '$payload' — may indicate error-based SQLi"
            finding MEDIUM "HTTP 500 on SQLi payload — possible error-based injection" 5
        fi
    done
    [ "$SQLI_FOUND" = "0" ] && ok "No SQLi indicators found in basic test (sqlmap recommended)"
fi

# ============================================================
title "10. XSS Detection"
# ============================================================

if [ $SKIP_XSS -eq 1 ]; then
    info "XSS check skipped (--skip-xss)"
else
    log "Testing for Reflected XSS ..."

    XSS_PAYLOADS=(
        "<script>alert(1)</script>"
        "\"'><script>alert(1)</script>"
        "<img src=x onerror=alert(1)>"
        "<svg/onload=alert(1)>"
        "javascript:alert(1)"
        "'-alert(1)-'"
        "<details open ontoggle=alert(1)>"
        "\"><img src=1 onerror=alert(1)>"
    )

    XSS_FOUND=0
    # Collect real query params from the page's own links for more targeted testing
    PAGE_HTML=$(curl -sk --max-time 15 -L -A "Mozilla/5.0" "https://$TARGET/" 2>/dev/null)
    # Extract unique GET param names from href attributes
    REAL_PARAMS=$(echo "$PAGE_HTML" | grep -oE '[?&][a-zA-Z_][a-zA-Z0-9_-]*=' | sed 's/[?&]//;s/=//' | sort -u | head -10)

    # Build test param list: real params first, then common fallbacks
    TEST_PARAMS=(q search s id name page query term keyword input)
    if [ -n "$REAL_PARAMS" ]; then
        while IFS= read -r p; do
            TEST_PARAMS=("$p" "${TEST_PARAMS[@]}")
        done <<< "$REAL_PARAMS"
    fi

    for payload in "${XSS_PAYLOADS[@]}"; do
        ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
        [ -z "$ENCODED" ] && continue
        for param in "${TEST_PARAMS[@]:0:6}"; do
            test_url="https://$TARGET/?${param}=${ENCODED}"
            RES=$(curl -sk --max-time 10 -A "Mozilla/5.0" "$test_url" 2>/dev/null)
            if echo "$RES" | grep -qF "$payload"; then
                plain "   ${R}[REFLECTED XSS]${N} Payload reflected unescaped: $payload"
                plain "   ${R}             URL:${N} $test_url"
                finding HIGH "Reflected XSS: payload reflected in response ($test_url)" 10
                XSS_FOUND=1
                break 2
            fi
        done
    done

    # Also check error pages for reflection
    ERR_RES=$(curl -sk --max-time 8 -A "Mozilla/5.0" \
        "https://$TARGET/nonexistent-xss-test-<script>alert(1)</script>" 2>/dev/null)
    if echo "$ERR_RES" | grep -qF "<script>alert(1)</script>"; then
        plain "   ${R}[REFLECTED XSS]${N} Error page reflects URL path unescaped!"
        finding HIGH "Reflected XSS in error page: URL path reflected unescaped" 10
        XSS_FOUND=1
    fi

    [ "$XSS_FOUND" = "0" ] && ok "No reflected XSS found in basic GET parameter tests"
    info "Note: POST/form-based and DOM XSS require manual testing or a dedicated scanner"
fi

# ============================================================
title "11. Rate Limiting"
# ============================================================

log "Testing rate limiting on homepage ..."

BLOCK=0
BLOCK_AT=0
for i in $(seq 1 30); do
    S=$(curl -sk -o /dev/null -w "%{http_code}" \
        -A "Mozilla/5.0" --max-time 5 "https://$TARGET/" 2>/dev/null)
    if [ "$S" = "429" ] || [ "$S" = "503" ]; then
        BLOCK=1; BLOCK_AT=$i
        ok "Rate limiting active (blocked at request #$i with HTTP $S)"
        break
    fi
done

if [ "$BLOCK" = "0" ]; then
    if [ "$BEHIND_CDN" = "1" ]; then
        warn "Rate limiting not triggered after 30 rapid requests (CDN may handle at edge)"
        finding LOW "Homepage rate limit unconfirmed — CDN likely handles at edge" 2
    else
        warn "Rate limiting not triggered after 30 rapid requests"
        finding INFO "Rate limiting not confirmed via basic burst test"
    fi
else
    bonus 3 "Rate limiting active (blocked at request $BLOCK_AT)"
fi

log "Testing brute-force protection on login endpoints ..."
LOGIN_FOUND=0
for ENDPOINT in \
    "/admin/login/" "/login/" "/signin" \
    "/api/auth/" "/api/login/" "/api/token/" \
    "/account/login/" "/user/login/" "/auth/login/"; do

    S=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        -X POST "https://$TARGET$ENDPOINT" \
        -d "username=admin&password=test123" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -A "Mozilla/5.0" 2>/dev/null)

    # 200/302/400/422 = endpoint exists and responds to auth requests; 403 = endpoint exists but blocked
    if [[ "$S" =~ ^(200|302|400|401|422)$ ]]; then
        info "Login endpoint: $ENDPOINT (HTTP $S)"
        LOGIN_FOUND=1
        RATE_BLOCKED=0
        for j in $(seq 1 10); do
            LS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
                -X POST "https://$TARGET$ENDPOINT" \
                -d "username=admin&password=wrongpass${RANDOM}${RANDOM}" \
                -H "Content-Type: application/x-www-form-urlencoded" \
                -A "Mozilla/5.0" 2>/dev/null)
            if [ "$LS" = "429" ] || [ "$LS" = "403" ]; then
                ok "Login rate limit active at attempt #$j: $ENDPOINT"
                RATE_BLOCKED=1
                break
            fi
        done
        if [ "$RATE_BLOCKED" = "0" ]; then
            warn "No rate limiting on login after 10 attempts: $ENDPOINT"
            finding HIGH "Login endpoint $ENDPOINT has no brute-force protection" 8
        fi
    fi
done
[ "$LOGIN_FOUND" = "0" ] && info "No common login endpoints found (may use custom path)"

# ============================================================
title "12. Additional Scanners (Nikto / Nuclei)"
# ============================================================

if has nikto; then
    log "Running Nikto (quick scan, 60s max) ..."
    NIKTO_OUT=$(nikto -h "https://$TARGET" -maxtime 60 \
        -Plugins "headers;paths;outdated" 2>/dev/null \
        | grep -E "^\+|OSVDB|CVE" | head -20)
    if [ -n "$NIKTO_OUT" ]; then
        while IFS= read -r line; do
            plain "   ${Y}[Nikto]${N} $line"
        done <<< "$NIKTO_OUT"
    else
        ok "Nikto: nothing significant found"
    fi
else
    warn "Nikto SKIPPED (not installed)"
fi

# FIX: Nuclei — build flags array properly and actually use them
if has nuclei; then
    log "Running Nuclei scan ..."
    NUCLEI_VER=$(nuclei -version 2>&1 | grep -oE '[0-9]+\.[0-9]+' | head -1)
    NUCLEI_MAJOR=$(echo "$NUCLEI_VER" | cut -d. -f1)

    # Build flags as array (not string) to avoid quoting issues
    NUCLEI_FLAGS_ARR=()
    if [ "${NUCLEI_MAJOR:-2}" -ge 3 ]; then
        NUCLEI_FLAGS_ARR+=(-header "User-Agent: Mozilla/5.0 (compatible; SecurityAudit/4.0)")
    else
        NUCLEI_FLAGS_ARR+=(-H "User-Agent: Mozilla/5.0 (compatible; SecurityAudit/4.0)")
    fi

    # FIX: actually pass the flags array to nuclei
    NUCLEI_OUT=$(nuclei -u "https://$TARGET" \
        -t misconfigurations/ -t exposures/ -t technologies/ \
        -t cves/ -t vulnerabilities/ \
        -severity medium,high,critical \
        "${NUCLEI_FLAGS_ARR[@]}" \
        -silent -timeout 15 2>/dev/null | head -50)

    if [ -n "$NUCLEI_OUT" ]; then
        while IFS= read -r line; do
            SEV=$(echo "$line" | grep -oE '\[critical\]|\[high\]|\[medium\]')
            case "$SEV" in
                *critical*) plain "   ${R}[Nuclei]${N} $line"; finding CRITICAL "Nuclei: $line" 10 ;;
                *high*)     plain "   ${Y}[Nuclei]${N} $line"; finding HIGH "Nuclei: $line" 7 ;;
                *medium*)   plain "   ${C}[Nuclei]${N} $line"; finding MEDIUM "Nuclei: $line" 4 ;;
                *)          plain "   [Nuclei] $line" ;;
            esac
        done <<< "$NUCLEI_OUT"
    else
        ok "Nuclei: nothing found in checked templates"
    fi
else
    warn "Nuclei SKIPPED (not installed)"
fi

# ============================================================
title "13. Subdomain Enumeration"
# ============================================================

log "Enumerating subdomains ..."

declare -a ALL_SUBS=()

# Show crt.sh results gathered earlier
if [ -n "$SUBDOMAINS" ]; then
    while IFS= read -r sub; do
        plain "   ${C}[crt.sh]${N} $sub"
        ALL_SUBS+=("$sub")
    done < <(echo "$SUBDOMAINS" | head -20)
    TOTAL_SUBS=$(echo "$SUBDOMAINS" | wc -l)
    [ "$TOTAL_SUBS" -gt 20 ] && info "... and $((TOTAL_SUBS - 20)) more via crt.sh"
fi

log "Brute-forcing common subdomains ..."

# FIX: detect wildcard DNS first to avoid false positives
WILDCARD_IP=$(dig A "nonexistent-xyzzy-$$.$TARGET" +short 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
if [ -n "$WILDCARD_IP" ]; then
    warn "Wildcard DNS detected ($WILDCARD_IP) — subdomain brute-force results may be unreliable"
    WILDCARD_DNS=1
else
    WILDCARD_DNS=0
fi
COMMON_SUBS=(
    www mail smtp ftp cpanel webmail
    dev staging api test beta admin portal
    vpn remote git jenkins ci old backup
    app static cdn assets media upload download
    shop store blog forum help support
    m mobile api2 api-v2 dashboard panel
)

for sub in "${COMMON_SUBS[@]}"; do
    IP_SUB=$(dig A "${sub}.${TARGET}" +short 2>/dev/null \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1)
    CNAME_SUB=$(dig CNAME "${sub}.${TARGET}" +short 2>/dev/null | grep -v '^$')
    RESULT="${IP_SUB:-$CNAME_SUB}"
    if [ -n "$RESULT" ]; then
        # FIX: skip if matches wildcard IP
        if [ "$WILDCARD_DNS" = "1" ] && [ "$IP_SUB" = "$WILDCARD_IP" ]; then
            continue
        fi
        plain "   ${G}[FOUND]${N} ${sub}.${TARGET} -> $RESULT"
        ALL_SUBS+=("${sub}.${TARGET}")
        case "$sub" in
            dev|staging|test|beta|old|backup)
                finding MEDIUM "Non-production subdomain exposed: ${sub}.${TARGET}" 5 ;;
            git|jenkins|ci)
                finding MEDIUM "CI/CD subdomain exposed: ${sub}.${TARGET}" 5 ;;
            admin|cpanel|panel|dashboard)
                finding LOW "Admin-like subdomain exposed: ${sub}.${TARGET}" 3 ;;
        esac
    fi
done

[ ${#ALL_SUBS[@]} -eq 0 ] && info "No subdomains discovered"

if has sublist3r; then
    log "Running Sublist3r ..."
    sublist3r -d "$TARGET" -o "/tmp/sub_$$.txt" 2>/dev/null
    if [ -f "/tmp/sub_$$.txt" ]; then
        head -10 "/tmp/sub_$$.txt"
        rm -f "/tmp/sub_$$.txt"
    fi
fi

if has amass; then
    log "Running Amass (passive, 60s) ..."
    timeout 60 amass enum -passive -d "$TARGET" 2>/dev/null | head -20 \
        | while IFS= read -r line; do plain "   ${C}[amass]${N} $line"; done
fi

# ============================================================
title "14. Additional Attack Surface Checks"
# ============================================================

# Open Redirect
log "Testing for Open Redirect ..."
REDIRECT_PARAMS=(redirect url return next goto redir dest destination callback
                 continue forward location target link to href ref redirect_uri
                 return_url next_url success_url cancel_url)
REDIRECT_FOUND=0
OPEN_REDIRECT_TESTED=0

# Fetch page HTML once to extract real redirect-like links/forms
PAGE_REDIR=$(curl -sk --max-time 10 -A "Mozilla/5.0" "https://$TARGET/" 2>/dev/null)

# Extract real param names from page hrefs that look like redirect params
REAL_REDIR_PARAMS=$(echo "$PAGE_REDIR" \
    | grep -oE '[?&](redirect|url|return|next|goto|redir|dest|destination|callback|continue|forward|location|target|return_url|redirect_uri)=[^&"'"'"' ]+' \
    | sed 's/^[?&]//;s/=.*//' | sort -u | head -5)

# Build final list: real params from page first, then generic list
FINAL_REDIR_PARAMS=()
[ -n "$REAL_REDIR_PARAMS" ] && while IFS= read -r p; do
    FINAL_REDIR_PARAMS+=("$p")
done <<< "$REAL_REDIR_PARAMS"
for p in "${REDIRECT_PARAMS[@]}"; do
    FINAL_REDIR_PARAMS+=("$p")
done

# External destinations to test
EVIL_TARGETS=("https://evil.com" "//evil.com" "https://evil.com%2F@${TARGET}" "/%09/evil.com")

for param in "${FINAL_REDIR_PARAMS[@]:0:12}"; do
    for test_val in "${EVIL_TARGETS[@]}"; do
        ENCODED_VAL=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1],safe=''))" "$test_val" 2>/dev/null)
        [ -z "$ENCODED_VAL" ] && ENCODED_VAL="$test_val"

        # Follow only first redirect (no -L) to capture the Location header
        REDIR_RESP=$(curl -sI --max-time 6 -A "Mozilla/5.0" \
            "https://$TARGET/?${param}=${ENCODED_VAL}" 2>/dev/null)
        LOCATION=$(echo "$REDIR_RESP" | grep -i "^location:" | tr -d '\r\n' | sed 's/^[Ll]ocation: //')
        HTTP_CODE=$(echo "$REDIR_RESP" | grep "^HTTP/" | tail -1 | awk '{print $2}')

        # A real open redirect: 3xx AND location points outside our target
        if [[ "$HTTP_CODE" =~ ^3 ]] && [ -n "$LOCATION" ]; then
            # Normalize: strip protocol and leading slashes
            LOC_HOST=$(echo "$LOCATION" | sed 's|^https\?://||;s|^//||;s|/.*||' | tr '[:upper:]' '[:lower:]')
            TGT_LOWER=$(echo "$TARGET" | tr '[:upper:]' '[:lower:]')
            # Flag only if destination host is NOT our target or a subdomain
            if ! echo "$LOC_HOST" | grep -qE "(^|\.)(${TGT_LOWER})(:|$)" && [ -n "$LOC_HOST" ]; then
                plain "   ${R}[OPEN REDIRECT]${N} ?${param}=${test_val} → HTTP $HTTP_CODE → $LOCATION"
                finding HIGH "Open Redirect via ?${param}= → $LOC_HOST (phishing/token theft risk)" 8
                REDIRECT_FOUND=1
                break 2
            fi
        fi
        OPEN_REDIRECT_TESTED=$((OPEN_REDIRECT_TESTED + 1))
    done
done
[ "$REDIRECT_FOUND" = "0" ] && ok "No open redirect found ($OPEN_REDIRECT_TESTED parameter combinations tested)"

# Clickjacking check (X-Frame-Options already checked, but check CSP frame-ancestors too)
log "Checking Clickjacking protection ..."
XFO=$(echo "$HEADERS_RAW" | grep -i "^x-frame-options:" | tr -d '\r')
CSP_FRAME=$(echo "$HEADERS_RAW" | grep -i "^content-security-policy:" | grep -i "frame-ancestors" | tr -d '\r')
if [ -n "$XFO" ] || [ -n "$CSP_FRAME" ]; then
    ok "Clickjacking protection present: ${XFO:-$CSP_FRAME}"
    bonus 1 "Clickjacking protection via X-Frame-Options or CSP frame-ancestors"
else
    finding MEDIUM "No clickjacking protection (missing X-Frame-Options and CSP frame-ancestors)" 4
    warn "Site may be embeddable in iframes — clickjacking risk"
fi

# HTTP → HTTPS redirect check
log "Checking HTTP to HTTPS redirect ..."
HTTP_REDIR=$(curl -sI --max-time 8 -A "Mozilla/5.0" "http://$TARGET/" 2>/dev/null \
    | grep -i "^location:" | tr -d '\r')
if echo "$HTTP_REDIR" | grep -qi "https://"; then
    ok "HTTP properly redirects to HTTPS"
    bonus 2 "HTTP→HTTPS redirect enforced"
else
    HTTP_STATUS=$(curl -sI --max-time 8 -A "Mozilla/5.0" "http://$TARGET/" 2>/dev/null \
        | grep "^HTTP/" | awk '{print $2}' | head -1)
    if [ "$HTTP_STATUS" = "200" ]; then
        finding HIGH "HTTP site accessible without redirect to HTTPS — traffic interception risk" 8
        warn "Site serves content over plain HTTP — MITM attack possible"
    else
        info "HTTP returned $HTTP_STATUS (no direct HTTPS redirect detected)"
    fi
fi

# Version disclosure in headers — check for outdated software versions
log "Checking for outdated software version disclosure ..."
ALL_HEADERS_LOWER=$(echo "$HEADERS_RAW" | tr '[:upper:]' '[:lower:]')
# Check for specific old versions in server/x-powered-by
OLD_PHP=$(echo "$HEADERS_RAW" | grep -iE "php/[34567]\." | grep -oE "PHP/[0-9]+\.[0-9]+\.[0-9]+")
OLD_APACHE=$(echo "$HEADERS_RAW" | grep -iE "Apache/[12]\." | grep -oE "Apache/[0-9]+\.[0-9]+\.[0-9]+")
OLD_NGINX=$(echo "$HEADERS_RAW" | grep -iE "nginx/[01]\." | grep -oE "nginx/[0-9]+\.[0-9]+\.[0-9]+")
[ -n "$OLD_PHP" ]    && finding HIGH "Outdated PHP version disclosed: $OLD_PHP — check for known CVEs" 8 && warn "Old PHP version: $OLD_PHP"
[ -n "$OLD_APACHE" ] && finding MEDIUM "Outdated Apache version disclosed: $OLD_APACHE" 5 && warn "Old Apache: $OLD_APACHE"
[ -n "$OLD_NGINX" ]  && finding MEDIUM "Outdated nginx version disclosed: $OLD_NGINX" 5 && warn "Old nginx: $OLD_NGINX"

# ============================================================
# FINAL REPORT
# ============================================================

END_TIME=$(date +%s)
DURATION=$(( END_TIME - START_TIME ))

# Apply per-category caps before computing final score
[ "$DEDUCT_CRITICAL" -gt "$CAP_CRITICAL" ] && DEDUCT_CRITICAL=$CAP_CRITICAL
[ "$DEDUCT_HIGH"     -gt "$CAP_HIGH"     ] && DEDUCT_HIGH=$CAP_HIGH
[ "$DEDUCT_MEDIUM"   -gt "$CAP_MEDIUM"   ] && DEDUCT_MEDIUM=$CAP_MEDIUM
[ "$DEDUCT_LOW"      -gt "$CAP_LOW"      ] && DEDUCT_LOW=$CAP_LOW
[ "$BONUS"           -gt "$MAX_BONUS"    ] && BONUS=$MAX_BONUS

SCORE=$(( 100 - DEDUCT_CRITICAL - DEDUCT_HIGH - DEDUCT_MEDIUM - DEDUCT_LOW ))
[ "$SCORE" -lt 0 ]   && SCORE=0
[ "$SCORE" -gt 100 ] && SCORE=100
FINAL_SCORE=$(( SCORE + BONUS ))
[ "$FINAL_SCORE" -gt 100 ] && FINAL_SCORE=100
[ "$FINAL_SCORE" -lt 0 ]   && FINAL_SCORE=0

if   [ "$FINAL_SCORE" -ge 80 ]; then LEVEL="Low Risk";      SCORE_COLOR="$G"
elif [ "$FINAL_SCORE" -ge 60 ]; then LEVEL="Medium Risk";   SCORE_COLOR="$Y"
elif [ "$FINAL_SCORE" -ge 40 ]; then LEVEL="High Risk";     SCORE_COLOR="$R"
else                                  LEVEL="Critical Risk"; SCORE_COLOR="${R}${B}"
fi

plain ""
plain ""
plain "${B}╔══════════════════════════════════════════════════════════════╗${N}"
plain "${B}║           FINAL SECURITY AUDIT REPORT  v6.0                ║${N}"
plain "${B}╚══════════════════════════════════════════════════════════════╝${N}"
plain ""
plain "  ${C}Target:${N}    $TARGET"
plain "  ${C}Date:${N}      $(date '+%Y-%m-%d %H:%M:%S')"
plain "  ${C}Duration:${N}  ${DURATION}s"
[ "$BEHIND_CDN" = "1" ] && plain "  ${C}CDN:${N}       $CDN_NAME detected"
plain ""

BAR=""
FILLED=$(( FINAL_SCORE / 5 ))
EMPTY=$(( 20 - FILLED ))
for _ in $(seq 1 $FILLED); do BAR="${BAR}█"; done
for _ in $(seq 1 $EMPTY);  do BAR="${BAR}░"; done

plain "  ${B}Base Score:${N}    ${SCORE} / 100"
plain "  ${C}Deductions:${N}    Critical:-${DEDUCT_CRITICAL}  High:-${DEDUCT_HIGH}  Medium:-${DEDUCT_MEDIUM}  Low:-${DEDUCT_LOW}"
plain "  ${G}Bonus Points:${N}  +${BONUS}"
plain "  ${B}Security Score:${N}  ${SCORE_COLOR}${B}${FINAL_SCORE} / 100${N}  [${SCORE_COLOR}${BAR}${N}]  ${SCORE_COLOR}${B}${LEVEL}${N}"
plain ""
plain "${B}══════════════════════════════════════════════════════════════${N}"

_print_findings() {
    local color="$1" label="$2"
    shift 2
    local arr=("$@")
    [ ${#arr[@]} -eq 0 ] && return
    plain ""
    plain "  ${color}${B}[$label]  ${#arr[@]} finding(s):${N}"
    for f in "${arr[@]}"; do
        plain "     ${color}>>  $f${N}"
    done
}

_print_findings "$R" "CRITICAL" "${FINDINGS_CRITICAL[@]}"
_print_findings "$Y" "HIGH"     "${FINDINGS_HIGH[@]}"
_print_findings "$C" "MEDIUM"   "${FINDINGS_MEDIUM[@]}"
_print_findings "$G" "LOW"      "${FINDINGS_LOW[@]}"

if [ ${#FINDINGS_INFO[@]} -gt 0 ]; then
    plain ""
    plain "  ${B}[INFO]:${N}"
    for f in "${FINDINGS_INFO[@]}"; do
        plain "     •  $f"
    done
fi

plain ""
plain "${B}══════════════════════════════════════════════════════════════${N}"

# Attack vectors
plain ""
plain "  ${B}POTENTIAL ATTACK VECTORS:${N}"
plain ""

TOTAL_VULNS=$(( ${#FINDINGS_CRITICAL[@]} + ${#FINDINGS_HIGH[@]} + ${#FINDINGS_MEDIUM[@]} ))

if [ "$TOTAL_VULNS" -eq 0 ]; then
    plain "   ${G}[CLEAN]${N} No significant vulnerabilities found in this scan"
else
    _seen_vectors=()
    _vector() {
        local key="$1" msg="$2"
        for v in "${_seen_vectors[@]}"; do [ "$v" = "$key" ] && return; done
        _seen_vectors+=("$key")
        plain "   ${R}[>>]${N} ${B}${msg}${N}"
    }
    for f in "${FINDINGS_CRITICAL[@]}" "${FINDINGS_HIGH[@]}" "${FINDINGS_MEDIUM[@]}"; do
        case "$f" in
            *".env"*|*"config"*|*"settings.py"*|*"credentials"*)
                _vector "creds" "Data Exfiltration: Config/credentials file readable → full compromise" ;;
            *".git"*|*"VCS"*|*"Source code"*)
                _vector "git" "Source Code Disclosure: Repo downloadable → business logic & secrets exposed" ;;
            *"Database"*|*"sqlite"*|*"dump.sql"*)
                _vector "db" "Database Dump: DB file downloadable → all user data exposed" ;;
            *"SQL Injection"*|*"SQLi"*)
                _vector "sqli" "SQL Injection: Query manipulation → data leak / auth bypass / possible RCE" ;;
            *"XSS"*)
                _vector "xss" "Cross-Site Scripting: Script execution in victim browser → session hijack / phishing" ;;
            *"CORS"*)
                _vector "cors" "CORS Misconfiguration: Attacker site can make authenticated API calls as victim" ;;
            *"Zone Transfer"*)
                _vector "axfr" "DNS Zone Transfer: Full infrastructure map downloadable via AXFR" ;;
            *"Redis"*|*"MongoDB"*|*"Elasticsearch"*|*"CouchDB"*)
                _vector "dbexposed" "Unauthenticated DB Access: Direct database access without credentials" ;;
            *"brute-force"*)
                _vector "bruteforce" "Brute Force: Unlimited login attempts → credential stuffing" ;;
            *"HSTS"*)
                _vector "sslstrip" "SSL Strip Attack: HTTP downgrade possible → traffic interception" ;;
            *"Telnet"*)
                _vector "telnet" "Cleartext Protocol: Credentials transmitted in plaintext over network" ;;
            *"FTP"*)
                _vector "ftp" "FTP Access: Possible anonymous login or unencrypted file transfer" ;;
            *"Docker"*)
                _vector "docker" "Docker API Exposed: Container escape / host takeover possible" ;;
            *"Email Spoofing"*|*"SPF"*|*"DMARC"*)
                _vector "spoofing" "Email Spoofing: Attackers can send email as @${TARGET} (phishing risk)" ;;
            *"Cookie"*|*"HttpOnly"*|*"Secure flag"*)
                _vector "cookie" "Cookie Theft: Session cookies accessible to JavaScript or sent over HTTP" ;;
        esac
    done
fi

plain ""
plain "${B}══════════════════════════════════════════════════════════════${N}"

# Remediation priorities
plain ""
plain "  ${B}REMEDIATION PRIORITIES:${N}"
plain ""
[ ${#FINDINGS_CRITICAL[@]} -gt 0 ] && plain "   ${R}[IMMEDIATE]${N}  Fix CRITICAL findings — within 24 hours"
[ ${#FINDINGS_HIGH[@]} -gt 0 ]     && plain "   ${Y}[THIS WEEK]${N}  Fix HIGH findings — within 7 days"
[ ${#FINDINGS_MEDIUM[@]} -gt 0 ]   && plain "   ${C}[THIS MONTH]${N} Fix MEDIUM findings — within 30 days"
[ ${#FINDINGS_LOW[@]} -gt 0 ]      && plain "   ${G}[PLANNED]${N}    Fix LOW findings — next sprint"
[ ${#FINDINGS_CRITICAL[@]} -eq 0 ] && [ ${#FINDINGS_HIGH[@]} -eq 0 ] && \
    [ ${#FINDINGS_MEDIUM[@]} -eq 0 ] && [ ${#FINDINGS_LOW[@]} -eq 0 ] && \
    plain "   ${G}[CLEAN]${N}      No issues requiring remediation found"

# Missing tools
if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    plain ""
    plain "${B}══════════════════════════════════════════════════════════════${N}"
    plain ""
    plain "  ${Y}${B}MISSING TOOLS (install for a more complete scan):${N}"
    plain ""

    declare -A TOOL_INFO=(
        ["nikto"]="Web vulnerability scanner|sudo apt install nikto -y"
        ["wafw00f"]="WAF detection|pip3 install wafw00f"
        ["sqlmap"]="SQL Injection testing|sudo apt install sqlmap -y"
        ["jq"]="JSON processing|sudo apt install jq -y"
        ["whatweb"]="Technology fingerprinting|sudo apt install whatweb -y"
        ["ffuf"]="Directory fuzzing|sudo apt install ffuf -y"
        ["nuclei"]="CVE & misconfiguration scanning|go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        ["sublist3r"]="Subdomain enumeration|pip3 install sublist3r"
        ["amass"]="Advanced subdomain OSINT|sudo apt install amass -y"
        ["testssl.sh"]="Comprehensive TLS analysis|git clone https://github.com/drwetter/testssl.sh"
    )

    APT_TOOLS=()
    for t in "${MISSING_TOOLS[@]}"; do
        IFS='|' read -r desc install <<< "${TOOL_INFO[$t]:-Unknown|unknown}"
        plain "   ${Y}*${N} ${B}$t${N}  —  $desc"
        plain "     ${C}Install:${N} $install"
        plain ""
        case "$t" in
            nikto|sqlmap|jq|whatweb|ffuf|sublist3r|amass|wafw00f) APT_TOOLS+=("$t") ;;
        esac
    done

    if [ ${#APT_TOOLS[@]} -gt 0 ]; then
        plain "  ${C}Install all at once (Debian/Ubuntu):${N}"
        plain "   ${G}sudo apt install ${APT_TOOLS[*]} -y${N}"
    fi
fi

plain ""
plain "${B}══════════════════════════════════════════════════════════════${N}"
plain "  ${G}[DONE]${N} Audit completed in ${DURATION}s  —  Score: ${SCORE_COLOR}${B}${FINAL_SCORE}/100${N}  (${LEVEL})"
plain "${B}══════════════════════════════════════════════════════════════${N}"
plain ""

# ============================================================
# Save plain-text report if --output specified
# ============================================================
if [ -n "$OUTPUT_FILE" ]; then
    {
        echo "Web Security Audit Report"
        echo "Target:   $TARGET"
        echo "Date:     $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Score:    $FINAL_SCORE / 100 ($LEVEL)"
        echo "Duration: ${DURATION}s"
        echo ""
        echo "=== CRITICAL (${#FINDINGS_CRITICAL[@]}) ==="
        for f in "${FINDINGS_CRITICAL[@]}"; do echo "  >> $f"; done
        echo ""
        echo "=== HIGH (${#FINDINGS_HIGH[@]}) ==="
        for f in "${FINDINGS_HIGH[@]}"; do echo "  >> $f"; done
        echo ""
        echo "=== MEDIUM (${#FINDINGS_MEDIUM[@]}) ==="
        for f in "${FINDINGS_MEDIUM[@]}"; do echo "  >> $f"; done
        echo ""
        echo "=== LOW (${#FINDINGS_LOW[@]}) ==="
        for f in "${FINDINGS_LOW[@]}"; do echo "  >> $f"; done
        echo ""
        echo "=== INFO ==="
        for f in "${FINDINGS_INFO[@]}"; do echo "  * $f"; done
    } > "$OUTPUT_FILE"
    ok "Report saved to: $OUTPUT_FILE"
fi
