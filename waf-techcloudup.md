# waf.techcloudup.com — WAF Interactive Demo

## Goal

An interactive demo where anyone can submit SQL Injection or XSS payloads through a simple web form, and watch Cloudflare WAF detect and block them in real time.

- **Attack payload** → WAF detects and blocks → browser receives `403 Forbidden` or custom block page
- **Normal input** → passes backend → returns "Safe request" response

---

## Overview

| Item | Detail |
|------|--------|
| Role | Interactive demo of WAF detection and blocking |
| User Experience | Enter an attack payload in the form → see WAF block result |
| Backend | Minimal web server (Python Flask) — simple echo, no real DB queries |
| WAF Layer | Cloudflare (proxy mode) + Managed Ruleset (OWASP CRS) |

---

## Tech Stack

| Layer | Technology | Notes |
|-------|------------|-------|
| Domain / DNS | `waf.techcloudup.com` | Cloudflare DNS — Orange Cloud (proxy ON) |
| WAF Engine | Cloudflare WAF (Managed Ruleset) | OWASP CRS — SQLi / XSS / RCE rules enabled |
| Origin Server | GCP Compute Engine (e2-micro, free tier) | Ubuntu 22.04 |
| Web Server | Nginx + Python Flask (Gunicorn) | Echo server — returns input as-is |
| Frontend | HTML + CSS + JavaScript | Form → `fetch` API → display response |
| Test Tools | `curl` / Browser DevTools | Inspect headers and status codes directly |

> **Note:** Cloudflare free plan supports a subset of OWASP CRS and Rate Limiting.
> Fine-grained rule tuning is limited, but sufficient for demo purposes.

---

## Request Flow

```
User Browser
    │
    │  1. https://waf.techcloudup.com
    ▼
[Cloudflare Edge]
    │
    │  2. Inspect request with WAF Ruleset
    │
    ├─ [Attack detected] ──────────────────────────────► 403 Block Page (never reaches origin)
    │   e.g. ' OR 1=1 --  /  <script>alert(1)</script>
    │
    └─ [Clean request] ────────────────────────────────► Origin Server
                                                          │
                                                          ▼
                                                    Nginx + Flask
                                                    "Safe request" response
```

---

## Test Scenarios

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

## Implementation Checklist

### Phase 1 — GCP Infrastructure
- [x] GCP e2-micro instance (Ubuntu 22.04, us-central1)
- [x] GCP Firewall Rule — allow inbound HTTP(80) / HTTPS(443)
- [x] GCP Firewall Rule — restrict to Cloudflare IP ranges only (block direct origin access)

### Phase 2 — Backend Server
- [x] Backend: Python Flask (chosen for low memory footprint on e2-micro)
- [x] Nginx + Flask (Gunicorn) — echo endpoint implemented
- [x] Nginx CORS headers (`Access-Control-Allow-Origin`)

### Phase 3 — Cloudflare Setup
- [x] `waf.techcloudup.com` A record in Cloudflare DNS (Orange Cloud ON)
- [x] HTTPS certificate (auto-provisioned by Cloudflare)
- [x] Origin SSL certificate — Let's Encrypt via certbot (expires 2026-08-26, auto-renew enabled)

### Phase 4 — WAF Configuration
- [x] Cloudflare WAF Managed Ruleset enabled (SQLi / XSS rules ON)
- [x] Custom block page — handled via 403 detection in frontend (Free plan limitation)

### Phase 5 — Frontend & Testing
- [x] Frontend HTML form page built and deployed
- [x] Frontend distinguishes 403 (blocked) vs 200 (allowed) with UI feedback
- [x] `curl` test — 403 confirmed (9/9 passed)
