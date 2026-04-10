# VulnAssess — Web Vulnerability Scanner

A production-grade web application vulnerability scanner built as a final-year academic project.
Full-stack: FastAPI backend, React web frontend, React Native mobile app.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                             │
│  ┌──────────────────────┐    ┌──────────────────────────────┐  │
│  │   React Web (Netlify)│    │  React Native / Expo (Mobile)│  │
│  │   vulnassess.netlify │    │  iOS + Android               │  │
│  └──────────┬───────────┘    └──────────────┬───────────────┘  │
└─────────────┼────────────────────────────────┼─────────────────┘
              │ HTTPS / REST API               │
┌─────────────▼────────────────────────────────▼─────────────────┐
│                    BACKEND LAYER (Render)                       │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  FastAPI  ·  Python 3.11  ·  Uvicorn async server        │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────┐  │  │
│  │  │  /auth   │ │  /scans  │ │  /reports  │ │  /admin  │  │  │
│  │  └──────────┘ └──────────┘ └────────────┘ └──────────┘  │  │
│  │               BackgroundTasks ──► run_scan()              │  │
│  └──────────────────────┬───────────────────────────────────┘  │
│                         │                                       │
│  ┌──────────────────────▼───────────────────────────────────┐  │
│  │               SCAN ENGINE (engine.py)                     │  │
│  │  RateLimiter · StatisticalBaseline · WafEvasion           │  │
│  │  AuthenticatedSession · ScanCancellation                  │  │
│  │  22 Modules: SQLi · XSS · CMDi · SSRF · XXE · Auth ···   │  │
│  └──────────────────────┬───────────────────────────────────┘  │
└─────────────────────────┼───────────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────────┐
│              DATA LAYER  (MongoDB Atlas M0)                     │
│   Collections: scans · users · modules · schedules · logs      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Layer | Technology | Version | Hosting |
|---|---|---|---|
| Backend API | FastAPI + Uvicorn | Python 3.11 | Render (free tier) |
| Database | MongoDB Atlas | M0 (512 MB) | ap-south-1 |
| Web Frontend | React 18 | Node 18 | Netlify |
| Mobile App | React Native + Expo | SDK 50 | EAS Build |
| AI Remediation | Anthropic Claude | claude-opus-4-5 | API |
| PDF Reports | ReportLab | 4.x | Backend |
| HTTP Client (scan) | httpx (async) | 0.27 | Backend |
| HTML Parsing | BeautifulSoup4 | 4.x | Backend |

---

## Scan Engine — 22 Modules

### Phase 1 — Core
| Module | Description |
|---|---|
| `auth_test` | Auth bypass, forced browsing, protected paths |

### Phase 2 — Injection
| Module | Description |
|---|---|
| `sql_injection` | Error-based, boolean-blind, UNION, time-based |
| `xss` | Reflected, DOM-based sink detection |
| `command_injection` | Linux/Windows OS command injection |

### Phase 3 — Protocol
| Module | Description |
|---|---|
| `ssrf` | Internal URL probing, metadata endpoints |
| `xxe` | XML external entity via file:// |
| `auth_test` | Login bypass payloads, CSRF token extraction |

### Phase 4 — Application
| Module | Description |
|---|---|
| `path_traversal` | LFI, PHP wrappers, Windows path traversal |
| `idor` | Numeric ID increment, object reference testing |
| `open_redirect` | Unvalidated redirect parameter detection |
| `file_upload` | Bypass detection with safe payloads (no live shells) |
| `csrf` | Token absence + cross-origin POST acceptance |
| `security_headers` | 7 missing headers, server version disclosure |
| `ssl_tls` | HTTP vs HTTPS, redirect enforcement |
| `cors_check` | ACAO wildcard, credentials + reflected origin |
| `cookie_security` | HttpOnly, Secure, SameSite flag checks |
| `clickjacking` | X-Frame-Options + CSP frame-ancestors |
| `info_disclosure` | 20 sensitive paths, secret patterns in responses |
| `rate_limiting` | Brute force protection, header bypass |

### Phase 5 — Modern APIs
| Module | Description |
|---|---|
| `graphql` | Introspection enabled, BOLA object access |
| `api_key_leakage` | AWS, Stripe, GitHub, Google, JWT patterns in JS |
| `jwt` | None-algorithm attack, weak secret brute force |
| `rate_limit` | IP spoofing header bypass (X-Forwarded-For etc.) |

---

## Engine v2 Features

### RateLimiter
- Max 10 requests/second, minimum 0.15s gap between requests
- 500 request cap per scan with warning in results
- Prevents accidental DoS against target

### StatisticalBaseline (False Positive Mitigation)
- Sends 3 identical baseline requests per parameter
- Calculates mean and std of response length and time
- Uses z-score > 2.5 to flag anomalies
- Dramatically reduces false positives from dynamic content (ads, timestamps, session IDs)

### WafEvasion (7 Techniques)
- URL encoding (`%27` for `'`)
- Double encoding (`%2527`)
- HTML entity encoding (`&#x27;`)
- Case shuffling (`AdMiN`)
- SQL comment insertion (`SE/**/LECT`)
- Whitespace substitution (tabs, newlines)
- Randomly samples 2 extra techniques per payload

### AuthenticatedSession
- Detects login forms by `input[type=password]`
- Extracts CSRF tokens automatically
- Maps username/password to correct field names
- Verifies session success via redirect/cookie check
- Persists cookies for all subsequent requests

### Safe File Upload
All upload payloads are detection-only — no live shells:
```python
".php"  → b"<?php echo 'VULNASSESS_UPLOAD_TEST_' . md5('safe'); die(); ?>"
".asp"  → b'<% Response.Write("VULNASSESS_UPLOAD_TEST") %>'
".jsp"  → b'<% out.println("VULNASSESS_UPLOAD_TEST"); %>'
```
Confirms RCE only if the detection marker appears in the fetched response.

### Scan Cancellation
- `cancel_flags` dict shared between `scans.py` and `engine.py`
- Checked after every module and before crawling
- Sets status to `"cancelled"` with partial results preserved

---

## Benchmark Results

Tested against DVWA (Damn Vulnerable Web Application) v1.10 and OWASP Juice Shop v15.

### DVWA Results

| Module | True Positives | False Positives | False Negatives | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| SQL Injection (Error) | 19 | 1 | 1 | 95% | 95% | 0.95 |
| SQL Injection (Boolean) | 17 | 2 | 3 | 89% | 85% | 0.87 |
| Reflected XSS | 22 | 1 | 1 | 96% | 96% | 0.96 |
| Command Injection | 14 | 0 | 2 | 100% | 88% | 0.93 |
| Path Traversal / LFI | 18 | 1 | 2 | 95% | 90% | 0.92 |
| CSRF | 12 | 2 | 1 | 86% | 92% | 0.89 |
| Security Headers | 32 | 0 | 0 | 100% | 100% | 1.00 |
| Open Redirect | 8 | 1 | 1 | 89% | 89% | 0.89 |
| File Upload | 9 | 0 | 1 | 100% | 90% | 0.95 |
| **Overall** | **151** | **8** | **12** | **95%** | **92.6%** | **0.94** |

### OWASP Juice Shop Results

| Module | Precision | Recall | F1 |
|---|---|---|---|
| XSS | 91% | 94% | 0.93 |
| SQL Injection | 88% | 86% | 0.87 |
| Security Headers | 100% | 100% | 1.00 |
| CORS | 93% | 90% | 0.91 |
| API Key Leakage | 85% | 88% | 0.86 |
| **Overall** | **91.4%** | **91.6%** | **0.91** |

> *Results generated using `scripts/benchmark.py` against Dockerised test targets.*

---

## API Reference

### Authentication
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/auth/register` | Create account |
| POST | `/api/auth/login` | Login, returns JWT |
| POST | `/api/auth/logout` | Invalidate token |
| GET  | `/api/auth/me` | Get current user |

### Scans
| Method | Endpoint | Description |
|---|---|---|
| POST | `/api/scans` | Start a new scan |
| GET  | `/api/scans` | List all user scans |
| GET  | `/api/scans/{id}` | Get scan details + vulnerabilities |
| POST | `/api/scans/{id}/cancel` | Cancel a running scan |
| DELETE | `/api/scans/{id}` | Delete scan (password required) |

### Reports
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/reports/{id}/pdf` | Download PDF report |
| GET | `/api/reports/{id}/ai-remediation` | Get AI fix recommendations |
| GET | `/api/reports/{id}/ai-remediation/pdf` | Download AI report PDF |
| GET | `/api/reports/ai-test` | Test Anthropic API key (admin) |

### Admin
| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/admin/users` | List all users |
| PUT | `/api/admin/users/{id}/role` | Change user role |
| PUT | `/api/admin/users/{id}/toggle` | Enable/disable user |
| GET | `/api/admin/stats` | Platform statistics |
| GET | `/api/admin/scans` | All scans (admin view) |

---

## Setup Instructions

### Backend (Local)
```bash
# Clone
git clone https://github.com/charanbhargav6/vulnassess.git
cd vulnassess

# Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# Install dependencies
pip install -r requirements.txt

# Set environment variables
set MONGODB_URL=mongodb+srv://<user>:<pass>@vulnassess.xxx.mongodb.net/vulnassess
set SECRET_KEY=your-secret-key
set CREDENTIALS_ENCRYPTION_KEY=your-generated-fernet-key
set APP_ENV=production
set ANTHROPIC_API_KEY=sk-ant-...

# Run
uvicorn main:app --reload
```

### Web Frontend (Local)
```bash
cd ../web
npm install
npm start
```

### Mobile App (Local)
```bash
cd ../mobile
npm install
npx expo start
```

### Running Benchmark
```bash
# Start DVWA with Docker first
docker run -d -p 4280:80 vulnerables/web-dvwa

# Run benchmark
cd vulnassess/backend
..\.venv\Scripts\python.exe scripts\benchmark.py --target http://localhost:4280 --output results.json
```

---

## Environment Variables (Render)

| Variable | Description |
|---|---|
| `MONGODB_URL` | MongoDB Atlas connection string |
| `SECRET_KEY` | JWT signing secret (min 32 chars) |
| `CREDENTIALS_ENCRYPTION_KEY` | Fernet key used to encrypt scheduled scan credentials |
| `APP_ENV` | Set to `production` in deployed environments |
| `ANTHROPIC_API_KEY` | Claude API key for AI remediation |
| `FRONTEND_URL` | Primary frontend origin for CORS |

---

## Deployment

- **Backend** → Render (auto-deploys on push to `main`)
- **Web** → Netlify (auto-deploys on push to `main`)
- **Mobile** → EAS Build → App stores

---

## Legal & Ethics

> ⚠️ VulnAssess must only be used against systems you own or have **explicit written permission** to test.
> Unauthorized scanning is illegal under the Computer Misuse Act 1990 (UK), CFAA (USA), and equivalent laws globally.

All file upload payloads are detection-only (no live shells). The scanner includes a 500-request cap and 10 RPS rate limit to prevent denial-of-service conditions.

---

## Screenshots

| Login | Dashboard | Scan Progress |
|---|---|---|
| Light/dark mode, Midnight Blue theme | Stats overview, severity breakdown | Real-time progress bar |

| Report | AI Remediation | Mobile |
|---|---|---|
| Expandable vulnerability list | Claude AI fix steps with code examples | React Native (iOS + Android) |

---

*Built by Charan Bhargav · Final Year Project · 2025*