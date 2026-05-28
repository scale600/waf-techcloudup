# ids.techcloudup.com — IDS Live Alert Dashboard

## Goal

Visualize suspicious traffic alerts detected by Suricata in a near-real-time dashboard.

- Browse recent alerts in a table (timestamp, attack type, source IP, etc.)
- Keep the dashboard populated with simulated alerts via cron when no real attacks occur

---

## Overview

| Item | Detail |
|------|--------|
| Role | IDS detection result visualization and active monitoring demo |
| Data Flow | Suricata log → cron forwarder → n8n → Flask API → Frontend |
| Update Interval | Every 1 minute (polling, no WebSocket) |

---

## Tech Stack

| Layer | Technology | Notes |
|-------|------------|-------|
| Domain / DNS | `ids.techcloudup.com` | Cloudflare DNS (proxy ON) — same IP as WAF VM |
| IDS Engine | Suricata 6.x+ | Installed on WAF VM (`waf.techcloudup.com`) — outputs `eve.json` |
| Ruleset | Default + Emerging Threats (free) | Managed via `suricata-update` |
| Log Forwarder | cron (Python script, every 1 min) | WAF VM — parses new alerts, POSTs to n8n webhook |
| Automation | n8n at `n8n.techcloudup.com` (existing) | Webhook → Slack alert → POST `/api/ingest` to Flask |
| Backend API | Python Flask (extended from WAF app) | `POST /api/ingest` (store alerts) / `GET /api/alerts` (serve to browser) |
| Frontend | Static HTML / CSS / JS | Served by Nginx — 30-second polling, table rendering |
| Simulated Alerts | cron + Python inject script | Appends mock events directly to `eve.json` (no nmap/hping3) |

---

## Infrastructure

```
[GCP e2-micro — WAF VM]
 ├─ Suricata        → /var/log/suricata/eve.json
 ├─ cron (1 min)    → parse eve.json → POST to n8n webhook
 ├─ Nginx
 │    ├─ waf.techcloudup.com  →  Gunicorn (Flask, existing)
 │    └─ ids.techcloudup.com  →  Static HTML + proxy /api/*
 └─ Flask (extended from WAF app)
      ├─ /echo             (WAF demo — existing)
      ├─ POST /api/ingest  (n8n → save to alerts.json, API key required)
      └─ GET  /api/alerts  (browser polling)

[n8n VM — existing]
 └─ n8n.techcloudup.com
      └─ Workflow: Webhook → Slack notification → POST /api/ingest

[Cloudflare]
 ├─ waf.techcloudup.com  →  WAF VM IP (existing)
 └─ ids.techcloudup.com  →  WAF VM IP (new A record)
```

---

## Dashboard Layout

| Element | Detail |
|---------|--------|
| Title | Suricata IDS Live Alerts |
| Table Columns | Timestamp / Signature (attack name) / Source IP / Destination IP / Action |
| Auto Refresh | Every 30 seconds |
| Optional | Alert count chart for the last 1 hour |

---

## Data Flow

```
1. Suricata    →  writes alert events to eve.json on WAF VM
2. cron        →  every 1 min: parse eve.json for new events
                    └─ POST new alerts to n8n webhook (n8n.techcloudup.com)
3. n8n         →  receives alert
                    ├─ sends Slack channel notification
                    └─ POST /api/ingest → WAF VM Flask (with API key)
4. Flask       →  updates alerts.json (keeps latest 50 entries)
5. Browser     →  GET /api/alerts every 30s → refresh table
```

---

## Security Considerations

| Item | Measure |
|------|---------|
| `/api/ingest` protection | API key header validation (n8n → Flask leg) |
| Flask port exposure | GCP firewall: Cloudflare IP ranges only (same policy as WAF VM) |
| `alerts.json` staleness | Include `last_updated` timestamp in API response — frontend shows elapsed time |

---

## Implementation Checklist

### Phase 1 — Suricata Installation (WAF VM)
- [x] `apt install suricata`, configure `eve.json` output
- [x] Download Emerging Threats ruleset via `suricata-update`
- [x] Enable and verify systemd service

### Phase 2 — Log Forwarder (WAF VM)
- [ ] cron script: parse `eve.json` for new alerts → POST to n8n webhook (every 1 min)
- [ ] Mock alert inject script (appends synthetic events directly to `eve.json`)

### Phase 3 — Flask Extension (WAF VM)
- [ ] `POST /api/ingest` route (API key validation + save to alerts.json, max 50 entries)
- [ ] `GET /api/alerts` route (include `last_updated` timestamp)

### Phase 4 — Nginx Update (WAF VM)
- [ ] Add `ids.techcloudup.com` server block (static HTML + `/api/*` reverse proxy)

### Phase 5 — n8n Workflow (existing VM: n8n.techcloudup.com)
- [ ] Webhook node → Slack node → HTTP Request node (`POST /api/ingest`)

### Phase 6 — Frontend
- [ ] Static HTML/JS dashboard (30s polling, staleness indicator from `last_updated`)
- [ ] (Optional) Alert count chart for the last 1 hour

### Phase 7 — Cloudflare & Final Steps
- [ ] Add `ids.techcloudup.com` A record (same IP as WAF VM)
- [ ] Register mock alert cron schedule
