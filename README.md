# WAF Interactive Demo — waf.techcloudup.com

An interactive demo where anyone can submit SQL Injection or XSS payloads through a simple web form, and watch Cloudflare WAF detect and block them in real time.

- **Attack payload** → WAF detects → returns `403 Forbidden` with a custom block page
- **Normal input** → passes through backend → returns "Safe request" response

---

## Architecture

```
User Browser
    │
    │  1. https://waf.techcloudup.com
    ▼
[Cloudflare Edge]
    │
    │  2. Inspect request with WAF Ruleset
    │
    ├─ [Attack detected] ──────────────────► 403 Block Page (never reaches origin)
    │   e.g. ' OR 1=1 --  /  <script>alert(1)</script>
    │
    └─ [Clean request] ────────────────────► Origin Server
                                              │
                                              ▼
                                        Nginx + Flask
                                        "Safe request" response
```

---

## Tech Stack

| Layer | Technology | Notes |
|-------|-----------|-------|
| Domain / DNS | `waf.techcloudup.com` | Cloudflare DNS — Orange Cloud (proxy ON) |
| WAF Engine | Cloudflare WAF (Managed Ruleset) | OWASP CRS — SQLi / XSS / RCE rules enabled |
| Origin Server | GCP Compute Engine (e2-micro) | Ubuntu 22.04, us-central1 |
| Web Server | Nginx + Python Flask (Gunicorn) | Echo server — returns input as-is |
| Frontend | HTML + CSS + JavaScript | Form → `fetch` API → display response |
| Test Tools | `curl` / Browser DevTools | Inspect headers and status codes directly |

---

## Test Payloads

### SQL Injection (blocked)
```
' OR 1=1 --
' UNION SELECT null, table_name FROM information_schema.tables --
admin'--
```

### XSS — Cross-Site Scripting (blocked)
```
<script>alert('xss')</script>
"><img src=x onerror=alert(1)>
javascript:alert(document.cookie)
```

### Normal Input (allowed)
```
hello world
test@example.com
2024-01-01
```

---

## Quick Test with curl

```bash
# Should return 403 — SQL Injection
curl -i "https://waf.techcloudup.com/echo?q=' OR 1=1 --"

# Should return 200 — Normal input
curl -i "https://waf.techcloudup.com/echo?q=hello"
```

---

> Built with Cloudflare WAF (Free tier) + GCP e2-micro free tier.
