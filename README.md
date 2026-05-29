# techcloudup.com — Cloud Security Demo

A collection of live, interactive demos showcasing real-world cloud security concepts using GCP and Cloudflare.

---

## Projects

### [waf.techcloudup.com](https://waf.techcloudup.com) — WAF Interactive Demo

Submit SQL Injection or XSS payloads through a web form and watch Cloudflare WAF block them in real time.

- Attack payload → WAF detects → `403 Forbidden`
- Normal input → passes backend → "Safe request" response

**Stack:** GCP e2-micro · Nginx + Python Flask · Cloudflare WAF (OWASP CRS + Custom Rules)

→ See [waf-techcloudup.md](waf-techcloudup.md) for full tech spec and implementation details.

---

### [ids.techcloudup.com](https://ids.techcloudup.com) — IDS Live Alert Dashboard

A near-real-time dashboard that visualizes Suricata IDS alerts and network protocol activity detected on the server.

- Suricata monitors live traffic → cron forwarder → n8n → Flask API → browser (30s polling)
- **Alerts tab:** intrusion detection events (signature, source IP, action)
- **Network Activity tab:** DNS / HTTP / TLS / SSH protocol logs

**Stack:** Suricata · n8n · Python Flask · Cloudflare DNS

→ See [ids-techcloudup.md](ids-techcloudup.md) for full tech spec and implementation details.

---

### [takedown.techcloudup.com](https://takedown.techcloudup.com) — Domain Takedown Investigator

On-demand passive investigation tool for suspected phishing or brand-impersonation domains.

- Enter a domain → real-time terminal streams the full investigation (11 steps)
- Collects DNS records, WHOIS, SSL certificate, HTTP headers, robots.txt, and sitemap
- Download all evidence files as a ZIP when complete

**Stack:** Bash (investigate.sh) · Python Flask SSE · Nginx · GCP e2-micro

→ See [takedown-techcloudup.md](takedown-techcloudup.md) for full tech spec and implementation details.

---

## Architecture Overview

```
[GCP e2-micro — Shared VM]
 ├─ Suricata (IDS engine)          → /var/log/suricata/eve.json
 ├─ cron                           → forward_alerts.py / forward_network.py (every 1 min)
 ├─ Nginx
 │    ├─ waf.techcloudup.com       → Flask echo server (WAF demo)
 │    ├─ ids.techcloudup.com       → Static dashboard + Flask API (IDS demo)
 │    └─ takedown.techcloudup.com  → Static form + Flask SSE API (Takedown tool)
 └─ Flask / Gunicorn (port 5000)
      ├─ /echo, /health
      ├─ /api/ingest, /api/alerts
      ├─ /api/network-events
      └─ /api/investigate/stream, /api/investigate/download/<token>

[n8n VM]  n8n.techcloudup.com  →  Suricata alert automation

[Cloudflare]  DNS proxy + WAF Managed Ruleset (OWASP CRS)
```

---

## Quick Test

```bash
# WAF — expect 403 (SQL Injection blocked)
curl -i "https://waf.techcloudup.com/echo?q=' OR 1=1 --"

# WAF — expect 200 (normal input)
curl -i "https://waf.techcloudup.com/echo?q=hello"

# IDS — fetch latest alerts
curl https://ids.techcloudup.com/api/alerts

# IDS — fetch latest network events
curl https://ids.techcloudup.com/api/network-events

# Takedown — validate domain format check
curl https://takedown.techcloudup.com/api/investigate/stream?domain=invalid
```

---

> Built on Cloudflare free tier + GCP free tier (e2-micro, us-central1).
