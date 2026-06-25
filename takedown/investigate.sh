#!/bin/bash

set -euo pipefail

# Get domain input
if [ -z "$1" ]; then
    echo "Usage: ./investigate.sh <domain>"
    echo "Example: ./investigate.sh sena-australia.com"
    read -p "Enter the domain to investigate: " DOMAIN
else
    DOMAIN="$1"
fi

# Empty input check
if [ -z "$DOMAIN" ]; then
    echo "Error: No domain entered."
    exit 1
fi

# Domain format validation
if ! echo "$DOMAIN" | grep -qE '^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$'; then
    echo "Error: Invalid domain format: $DOMAIN"
    exit 1
fi

# Use absolute paths to avoid cd dependency
WORK_DIR="$(pwd)"
OUTPUT_DIR="${WORK_DIR}/${DOMAIN}_investigation_$(date +%Y%m%d_%H%M%S)"

mkdir -p "$OUTPUT_DIR" || { echo "Error: Cannot create directory $OUTPUT_DIR"; exit 1; }

echo "========================================="
echo "  Fake Website Investigation Tool"
echo "  Target Domain: $DOMAIN"
echo "  Investigation Started: $(date)"
echo "========================================="
echo ""

# 02_dig_A.txt
echo "[1/11] Investigating A Record..."
{
    echo "=== A Record ==="
    dig "$DOMAIN" A +short
    echo ""
    dig "$DOMAIN" A
} > "$OUTPUT_DIR/02_dig_A.txt" 2>&1
echo "✓ Complete"
echo ""

# 03_dig_NS.txt
echo "[2/11] Investigating NS Record..."
{
    echo "=== NS Record ==="
    dig "$DOMAIN" NS +short
    echo ""
    dig "$DOMAIN" NS
} > "$OUTPUT_DIR/03_dig_NS.txt" 2>&1
echo "✓ Complete"
echo ""

# 04_dig_records.txt
# Query individual record types instead of ANY (better compatibility with modern DNS servers)
echo "[3/11] Investigating DNS Records (A, AAAA, MX, TXT, SOA, CNAME)..."
{
    echo "=== DNS Records by Type ==="
    for TYPE in A AAAA MX TXT SOA CNAME; do
        echo "--- $TYPE ---"
        dig "$DOMAIN" $TYPE +short
        echo ""
    done
} > "$OUTPUT_DIR/04_dig_records.txt" 2>&1
echo "✓ Complete"
echo ""

# 05_ip_whois.txt
echo "[4/11] Investigating WHOIS Information..."
{
    echo "=== Domain WHOIS ==="
    whois "$DOMAIN"
    echo ""
    # Filter to IP addresses only (exclude CNAME lines)
    IP=$(dig "$DOMAIN" A +short | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)
    if [ -n "$IP" ]; then
        echo "=== IP WHOIS for $IP ==="
        whois "$IP"
    fi
} > "$OUTPUT_DIR/05_ip_whois.txt" 2>&1
echo "✓ Complete"
echo ""

# 06_traceroute.txt
echo "[5/11] Running Traceroute... (max 30 seconds)"
{
    echo "=== Traceroute ==="
    timeout 30 traceroute -m 15 "$DOMAIN" 2>&1 || echo "Traceroute timed out or failed"
} > "$OUTPUT_DIR/06_traceroute.txt" 2>&1
echo "✓ Complete"
echo ""

# 07_ssl_cert.txt
echo "[6/11] Investigating SSL Certificate..."
{
    echo "=== SSL Certificate ==="
    echo | timeout 10 openssl s_client -showcerts -servername "$DOMAIN" -connect "$DOMAIN":443 2>/dev/null
    echo ""
    echo "=== Certificate Details ==="
    # Capture to variable first — safe in pipefail environment
    CERT_DATA=$(timeout 10 openssl s_client -connect "$DOMAIN":443 -servername "$DOMAIN" </dev/null 2>/dev/null)
    if [ -n "$CERT_DATA" ]; then
        echo "$CERT_DATA" | openssl x509 -text -noout 2>/dev/null || echo "SSL certificate parse failed"
    else
        echo "SSL certificate retrieval failed"
    fi
} > "$OUTPUT_DIR/07_ssl_cert.txt" 2>&1
echo "✓ Complete"
echo ""

# 08_curl_headers.txt
echo "[7/11] Investigating HTTP Headers..."
{
    # -L follows redirects
    echo "=== HTTPS Headers (with redirect follow) ==="
    curl -IL "https://$DOMAIN" --max-time 10 2>&1
    echo ""
    echo "=== HTTP Headers (with redirect follow) ==="
    curl -IL "http://$DOMAIN" --max-time 10 2>&1
} > "$OUTPUT_DIR/08_curl_headers.txt" 2>&1
echo "✓ Complete"
echo ""

# 09_curl_response_headers.txt
echo "[8/11] Investigating Detailed Response Headers..."
{
    echo "=== Verbose HTTPS Response (with redirect follow) ==="
    curl -vL "https://$DOMAIN" --max-time 10 2>&1 | grep -E '^(<|>)'
    echo ""
    curl -sSL -D - "https://$DOMAIN" --max-time 10 -o /dev/null 2>&1
} > "$OUTPUT_DIR/09_curl_response_headers.txt" 2>&1
echo "✓ Complete"
echo ""

# 10_source_code.html
echo "[9/11] Saving HTML Source Code..."
curl -sL "https://$DOMAIN" --max-time 10 > "$OUTPUT_DIR/10_source_code.html" 2>&1 \
    || echo "Failed to download source" > "$OUTPUT_DIR/10_source_code.html"
echo "✓ Complete"
echo ""

# 11_sitemap.txt
echo "[10/11] Checking Robots.txt & Sitemap..."
{
    echo "=== robots.txt ==="
    ROBOTS_CONTENT=$(curl -sL "https://$DOMAIN/robots.txt" --max-time 10 2>/dev/null)
    if [ -n "$ROBOTS_CONTENT" ]; then
        echo "$ROBOTS_CONTENT"
    else
        echo "robots.txt not found or empty"
    fi
    echo ""

    # Extract sitemap URLs from robots.txt
    SITEMAP_URLS=$(echo "$ROBOTS_CONTENT" | grep -i "^Sitemap:" | awk '{print $2}' | tr -d '\r')

    # Fall back to common sitemap paths if not found in robots.txt
    if [ -z "$SITEMAP_URLS" ]; then
        SITEMAP_URLS="https://$DOMAIN/sitemap.xml
https://$DOMAIN/sitemap_index.xml"
    fi

    echo "=== Sitemap ==="
    TOTAL_LINKS=0
    while IFS= read -r SITEMAP_URL; do
        [ -z "$SITEMAP_URL" ] && continue
        echo "--- $SITEMAP_URL ---"
        SITEMAP_CONTENT=$(curl -sL "$SITEMAP_URL" --max-time 10 2>/dev/null)
        if [ -n "$SITEMAP_CONTENT" ]; then
            echo "$SITEMAP_CONTENT"
            echo ""
            LINKS=$(echo "$SITEMAP_CONTENT" | grep -oE '<loc>[^<]+</loc>' | sed 's/<[^>]*>//g')
            LINK_COUNT=$(echo "$LINKS" | grep -c .)
            TOTAL_LINKS=$((TOTAL_LINKS + LINK_COUNT))
            echo "--- Extracted URLs ($LINK_COUNT found) ---"
            echo "$LINKS"
        else
            echo "No sitemap found at $SITEMAP_URL"
        fi
        echo ""
    done <<< "$SITEMAP_URLS"

    echo "=== Total URLs Found: $TOTAL_LINKS ==="
} > "$OUTPUT_DIR/11_sitemap.txt" 2>&1
echo "✓ Complete"
echo ""

# 12_summary.txt - Summary report
echo "[11/11] Generating Investigation Summary..."
cat > "$OUTPUT_DIR/12_summary.txt" << EOF
========================================
Fake Website Investigation Summary
========================================
Investigated Domain: $DOMAIN
Investigation Date: $(date)
Investigator: $(whoami)

== IP Address ==
$(dig "$DOMAIN" A +short 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$')

== Name Servers ==
$(dig "$DOMAIN" NS +short 2>/dev/null)

== Mail Servers ==
$(dig "$DOMAIN" MX +short 2>/dev/null)

== WHOIS Registrant ==
$(whois "$DOMAIN" 2>/dev/null | grep -i "Registrant\|Organization\|Registrar:" | head -5)

== Registrar ==
$(whois "$DOMAIN" 2>/dev/null | grep -i "Registrar:" | grep -iv "WHOIS\|URL\|Abuse\|IANA" | head -1 | sed 's/^ *//')

== Creation Date ==
$(whois "$DOMAIN" 2>/dev/null | grep -i "Creation Date:" | head -1)

== SSL Certificate Issuer ==
$(CERT=$(timeout 10 openssl s_client -showcerts -servername "$DOMAIN" -connect "$DOMAIN":443 </dev/null 2>/dev/null); \
  [ -n "$CERT" ] && echo "$CERT" | openssl x509 -noout -issuer 2>/dev/null || echo "Not available")

== Sitemap ==
$(grep "=== Total URLs Found:" "$OUTPUT_DIR/11_sitemap.txt" 2>/dev/null || echo "Not checked")
$(grep -A 50 "--- Extracted URLs" "$OUTPUT_DIR/11_sitemap.txt" 2>/dev/null | grep -v "^---" | head -20)

========================================
Reporting Channels:
1. Hosting Provider Abuse Email (see WHOIS)
2. Domain Registrar (see WHOIS)
3. Cloudflare/CDN Provider (if applicable)
4. National CERT/CSIRT
5. Local Law Enforcement Cybercrime Unit
6. IC3 (Internet Crime Complaint Center) - ic3.gov
7. APWG (Anti-Phishing Working Group) - reportphishing@apwg.org

Additional Evidence to Collect:
- Full page screenshots
- Transaction records (if any)
- Email/SMS communications
- Payment information (if applicable)
========================================
EOF
cat "$OUTPUT_DIR/12_summary.txt"
echo "✓ Complete"
echo ""

echo "========================================="
echo "  Investigation Complete!"
echo "  Results Saved in: $OUTPUT_DIR"
echo "========================================="
ls -lh "$OUTPUT_DIR"
echo ""
echo "Key Files:"
echo "  - 12_summary.txt      : Investigation summary"
echo "  - 05_ip_whois.txt     : Hosting/Registration info"
echo "  - 07_ssl_cert.txt     : SSL certificate"
echo "  - 10_source_code.html : Website source code"
echo "  - 11_sitemap.txt      : Robots.txt & Sitemap URLs"
echo "  - 04_dig_records.txt  : Full DNS records (A/AAAA/MX/TXT/SOA/CNAME)"
