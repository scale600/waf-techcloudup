# techcloudup.com — Cloud Security Demo Portfolio

A collection of live, interactive demos showcasing real-world cloud security concepts using GCP and Cloudflare.

---

## Projects

### [waf.techcloudup.com](https://waf.techcloudup.com) — WAF Interactive Demo

Submit SQL Injection or XSS payloads through a web form and watch Cloudflare WAF block them in real time.

- Attack payload → WAF detects → `403 Forbidden`
- Normal input → passes backend → "Safe request" response

**Stack:** GCP e2-micro · Nginx + Python Flask · Cloudflare WAF (OWASP CRS)

→ See [waf-techcloudup.md](waf-techcloudup.md) for full tech spec and implementation details.

---

### [ids.techcloudup.com](https://ids.techcloudup.com) — IDS Live Alert Dashboard *(in progress)*

A near-real-time dashboard that visualizes Suricata IDS alerts detected on the server.

- Suricata monitors live traffic → alerts forwarded via n8n → displayed in browser table
- Auto-refreshes every 30 seconds

**Stack:** Suricata · n8n · Python Flask · Cloudflare DNS

→ See [ids-techcloudup.md](ids-techcloudup.md) for full tech spec and implementation details.

---

## Architecture Overview

```
[GCP e2-micro — Shared VM]
 ├─ Suricata (IDS engine)
 ├─ Nginx
 │    ├─ waf.techcloudup.com  →  Flask echo server (WAF demo)
 │    └─ ids.techcloudup.com  →  Static dashboard + Flask API (IDS demo)
 └─ Flask (Gunicorn)

[n8n VM]  n8n.techcloudup.com  →  alert automation & Slack notifications

[Cloudflare]  DNS proxy + WAF Managed Ruleset (OWASP CRS)
```

---

## Quick Test

```bash
# WAF Demo — expect 403 (SQL Injection blocked)
curl -i "https://waf.techcloudup.com/echo?q=' OR 1=1 --"

# WAF Demo — expect 200 (normal input)
curl -i "https://waf.techcloudup.com/echo?q=hello"

# IDS Demo — fetch latest alerts
curl https://ids.techcloudup.com/api/alerts
```

---

> Built on Cloudflare free tier + GCP free tier (e2-micro, us-central1).
