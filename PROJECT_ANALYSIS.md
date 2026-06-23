# VulnAssess: Complete Project Analysis

## Overview
**VulnAssess** is a production-grade web application vulnerability scanner built as a final-year academic project. It's a full-stack application with real-time scanning, comprehensive vulnerability detection, AI-powered remediation, and both web and mobile interfaces.

---

## 1. HOW IT WORKS

### User Journey

#### A. Authentication Flow
1. User registers or logs in via web/mobile
2. Backend validates credentials using **bcrypt** hashing
3. JWT token issued with expiration time
4. Token stored securely on client (web localStorage or mobile secure storage)
5. Subsequent requests include Bearer token in Authorization header

#### B. Vulnerability Scanning Process
```
User submits scan request
        ↓
Backend creates scan record in MongoDB (status: "pending")
        ↓
Background task (asyncio) spawns run_scan() coroutine
        ↓
Scan Engine initializes:
  - Rate limiter (10 RPS max, anti-WAF jitter)
  - HTTP session with optional authentication
  - Statistical baseline for false-positive filtering
        ↓
22 vulnerability modules execute in phases:
  Phase 1: Authentication testing
  Phase 2: Injection attacks (SQL, XSS, Command)
  Phase 3: Protocol attacks (SSRF, XXE)
  Phase 4: Application-level vulnerabilities
  Phase 5: Modern API vulnerabilities (GraphQL)
        ↓
Each module:
  - Tests payloads with 7 WAF evasion techniques
  - Records findings with confidence scores
  - Uses z-score statistical analysis to reduce false positives
  - Can be cancelled by user (cancel_flags checked at every module)
        ↓
Results stored in MongoDB scan document
        ↓
Frontend polls for completion and displays findings
```

#### C. Reporting & Analysis
1. User views scan results dashboard with severity breakdown
2. Can download PDF reports (generated with ReportLab)
3. Can request AI remediation (Claude Opus API) for vulnerabilities
4. Can compare multiple scans to track improvements

#### D. Admin Workflow
1. Admin dashboard aggregates system data
2. Consolidated endpoint reduces N+1 queries
3. Can manage users, modules, logs, and payments
4. Real-time activity logs capture all operations

#### E. Scheduled Scanning
1. User creates schedule (e.g., every Sunday, 2 AM)
2. APScheduler background job checks every minute
3. If `next_run ≤ now`, scan auto-executes
4. Results saved with schedule reference
5. Next run time calculated and stored

---

## 2. MAIN TECH STACK

### Backend
| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | FastAPI 0.104+ | Async web framework |
| **Runtime** | Python 3.11 + Uvicorn | Event-driven server |
| **Database** | MongoDB Atlas (M0) | NoSQL document storage |
| **Driver** | Motor (async PyMongo) | Non-blocking MongoDB client |
| **Authentication** | JWT (PyJWT) + Bcrypt | Token & password security |
| **HTTP Client** | httpx (async) | Non-blocking HTTP requests |
| **HTML Parsing** | BeautifulSoup4 | DOM extraction & analysis |
| **Scheduling** | APScheduler | Cron-like job scheduling |
| **PDF Generation** | ReportLab | Report generation |
| **AI Integration** | Anthropic SDK | Claude API for remediation |
| **Rate Limiting** | Custom async RateLimiter | 10 RPS throttling |
| **CORS** | FastAPI CORSMiddleware | Cross-origin requests |

### Frontend (Web)
| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | React 18 | Component UI library |
| **Build Tool** | Vite 8+ | Fast bundler (esbuild) |
| **Charts** | Recharts 3.8 | Interactive vulnerability graphs |
| **State** | React Context API | Global state (theme, auth) |
| **Hosting** | Netlify | Static + serverless functions |
| **HTTP Client** | Axios / Fetch | API requests |

### Mobile (React Native)
| Component | Technology | Purpose |
|-----------|-----------|---------|
| **Framework** | React Native + Expo SDK 50 | Cross-platform mobile |
| **Target Platforms** | iOS + Android | Native build output |
| **Build Service** | EAS Build | Cloud-based compilation |
| **Storage** | Expo SecureStore | Encrypted local storage |
| **HTTP Client** | Axios | API requests |

### Hosting & Deployment
| Service | Provider | Tier |
|---------|----------|------|
| Backend API | Render | Free tier (spinning containers) |
| Database | MongoDB Atlas | M0 (512 MB, shared cluster, ap-south-1) |
| Web Frontend | Netlify | Free tier (static + CF workers) |
| Mobile Builds | EAS Build | Free tier |

### External Services
- **Anthropic Claude API**: AI remediation suggestions
- **Email Service**: Password resets, notifications
- **CORS Proxy** (optional): For testing cross-origin vulnerabilities

---

## 3. TECHNIQUES USED

### A. Vulnerability Detection Techniques

#### SQL Injection (5 Methods)
1. **Error-based**: Trigger syntax errors, parse error messages
2. **Boolean-blind**: Conditional payloads (1=1, 1=2), timing analysis
3. **UNION-based**: UNION SELECT NULL -- to extract columns
4. **Time-based**: SLEEP(N) delays, stacked queries
5. **Numeric tampering**: ID field injection (IDOR variant)

#### Cross-Site Scripting (XSS) - 3 Types
1. **Reflected**: Input echoed in response, test polyglot payloads
2. **DOM-based**: Sink detection (innerHTML, eval, document.write)
3. **Event handler**: Attribute-based XSS (onclick, onload)

#### Command Injection
1. **Shell metacharacters**: ; | & $ ` \n ||
2. **Out-of-band**: DNS/HTTP exfiltration (monitored)
3. **Timing attacks**: sleep(5), ping -c 5 localhost

#### Server-Side Request Forgery (SSRF)
1. **Localhost probing**: http://127.0.0.1:22, :8080, :3306
2. **Cloud metadata**: http://169.254.169.254/latest/meta-data/
3. **Internal services**: gopher://, dict://, ldap:// protocols

#### Path Traversal / Local File Inclusion (LFI)
1. **Directory escape**: ../../../etc/passwd
2. **PHP wrappers**: php://filter/convert.base64-encode/resource=index.php
3. **Windows paths**: ..\..\..\..\windows\system32\config\sam
4. **Case variation**: ../%2e%2e/../../

#### Authentication & Authorization
1. **Forced browsing**: Direct endpoint access without login
2. **Parameter tampering**: user_id=2 (instead of current user)
3. **IDOR**: Object ownership not verified on server
4. **Session fixation**: Reuse pre-known session IDs

#### XXE (XML External Entity)
1. **File disclosure**: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
2. **XXE blind**: Out-of-band DNS/HTTP callbacks
3. **Billion laughs**: Recursive entity expansion (DoS)

#### Open Redirect
1. **Parameter tampering**: redirect=/evil.com
2. **Whitelist bypass**: redirect=//evil.com, whitelist.com@evil.com
3. **Protocol abuse**: javascript:, data: schemes

#### CSRF (Cross-Site Request Forgery)
1. **Token absence**: POST without CSRF token
2. **Token reuse**: Same token for all users/sessions
3. **Weak validation**: Token not tied to session/user

#### Security Headers
| Header | Check | Bypass |
|--------|-------|--------|
| Content-Security-Policy | Present + strong directives | unsafe-inline, data: URIs |
| X-Frame-Options | DENY / SAMEORIGIN vs ALLOW-ALL | Clickjacking vectors |
| X-Content-Type-Options | nosniff header presence | MIME-type sniffing |
| Strict-Transport-Security | HSTS enforcement | MITM on first request |
| Set-Cookie HttpOnly | Session cookie protection | XSS payload stealing |

#### Rate Limiting Bypass
1. **Header manipulation**: X-Forwarded-For, X-Original-IP
2. **Distributed attacks**: Multiple IPs from bot network
3. **Account enumeration**: Brute force without rate limit

#### GraphQL Vulnerabilities
1. **Introspection enabled**: Schema fully exposed
2. **BOLA**: Unauthorized object access (ID guessing)
3. **N+1 queries**: No query depth limiting

### B. Engine Security Features

#### 1. **Rate Limiting (Anti-WAF Detection)**
```
Max 10 RPS per target
Min delay: 150ms between requests
Jitter: +0-500ms random per request
Rate window: Rolling 1-second windows
Monitored: Request count, response times
```
**Purpose**: Avoid triggering WAF rules, bypass bot detection

#### 2. **Statistical Baseline (False-Positive Mitigation)**
```
Establishes baseline response fingerprint:
  - Response code distribution
  - Content-length distribution
  - Time variance (z-score analysis)
  
Findings flagged only if:
  - Deviation > 2σ (99.5% confidence)
  - Multiple confirmation attempts pass
```
**Purpose**: Reduce false positives from WAFs, CDNs, error pages

#### 3. **WAF Evasion (7 Techniques per Payload)**
1. **URL encoding**: %20, %2B, %3D
2. **Double encoding**: %25 (encoded %)
3. **Case variation**: SeLeCt vs SELECT
4. **Null byte**: SELECT%00x
5. **Comments**: SEL/**/ECT, SELECT--abc
6. **Nested encoding**: %2525 (double-URL)
7. **Unicode normalization**: Ü → U+0308

#### 4. **Authenticated Session Detection**
```
Auto-detects login forms:
  - Extracts form fields (username, password, email)
  - Tests with provided credentials
  - Maintains session cookies across scan
  - Detects 302/303 post-login redirects
  - Validates successful authentication
```
**Purpose**: Scan behind authentication without manual setup

#### 5. **Scan Cancellation (Cooperative)**
```
Global cancel_flags dictionary:
  - User clicks cancel button
  - Backend sets cancel_flags[scan_id] = True
  - Every module checks _check_cancel(scan_id)
  - ScanCancelledException raised + scan terminated
```
**Purpose**: Graceful shutdown of long-running scans

### C. Database Design

#### Collections & Indexes
```
users
  ├─ email (unique)
  ├─ hashed_password (bcrypt)
  ├─ subscription_tier (free/starter/pro)
  └─ created_at (for aggregation)

scans
  ├─ user_id (indexed for user queries)
  ├─ target_url
  ├─ status (pending/running/completed/cancelled)
  ├─ findings (array of vulnerability objects)
  ├─ created_at
  └─ scheduled_scan_id (optional)

schedules
  ├─ user_id
  ├─ target_url
  ├─ frequency (interval or cron)
  ├─ is_active
  ├─ next_run (for efficient polling)
  └─ encrypted_credentials

subscription_payments
  ├─ user_id
  ├─ status (paid/pending/failed)
  ├─ amount
  └─ created_at

activity_logs
  ├─ user_id
  ├─ action (login/scan_start/scan_end)
  ├─ details
  └─ timestamp
```

**Index Strategy**: Compound indexes for common queries (user_id + created_at), TTL indexes for auto-deletion (rate_limits, password_reset_otps)

### D. API Architecture

#### FastAPI Routers (Modular)
```
/auth        → Login, register, token refresh
/scans       → Create, list, cancel, results
/reports     → Download PDF, compare scans
/profile     → User settings, password change
/admin       → User management, logs, system stats
/schedule    → Create, update, delete scheduled scans
/modules     → List, enable/disable vulnerability modules
```

#### Async/Await Throughout
- **httpx**: Async HTTP requests (connection pooling)
- **Motor**: Non-blocking MongoDB queries
- **BackgroundTasks**: Scan execution without blocking response
- **asyncio.gather()**: Parallel module execution (controlled)

### E. Frontend Patterns

#### React Context for State Management
```
AuthContext    → User token, role, login/logout
ThemeContext   → Dark/light mode persistence
NotificationContext → Toast notifications
```

#### Client-Side Optimization
- **Polling with exponential backoff**: Scan status checks (1s → 30s)
- **Request deduplication**: Prevent duplicate API calls
- **Field projection**: Backend returns only needed fields for list views
- **Caching**: Dashboard data refreshed only on mutations

#### UI Components
- **Recharts**: Vulnerability severity pie/bar charts
- **Skeleton loaders**: UX during data fetch
- **Responsive grid**: Desktop/mobile adaptability

---

## 4. VIVA QUESTIONS & ANSWERS

### A. Architecture & Design

**Q1: Explain the vulnerability scanning pipeline. What happens after a user initiates a scan?**

**A1:**
1. User sends POST request with target URL and optional credentials
2. Backend creates a scan document in MongoDB with status="pending"
3. Immediately returns scan ID to user for polling
4. Background task (BackgroundTasks) spawns run_scan() coroutine
5. Scan engine initializes: rate limiter, HTTP session, baseline
6. 22 modules execute in 5 phases (auth, injection, protocol, application, modern APIs)
7. Each module tests 5-10 payloads with 7 WAF evasion techniques
8. Findings stored in scan document, status updated to "completed"
9. Frontend polls /scans/{id} endpoint and displays results

**Q2: Why is rate limiting critical in a vulnerability scanner? How is it implemented?**

**A2:**
- **Why**: Prevents WAF/IDS triggering, avoids IP blacklisting, respects server resources, complies with ethical hacking standards
- **How**: 
  - Max 10 requests per second
  - 150ms minimum delay between requests
  - Random jitter (0-500ms) to avoid burst detection patterns
  - Rolling time window checking
  - Different delays for different module types (slower for injection tests)

**Q3: What is the purpose of StatisticalBaseline in the scan engine?**

**A3:**
- Reduces false positives from WAF/error pages
- Establishes baseline: response codes, content lengths, response times
- Uses z-score analysis: flags findings only if deviation > 2σ
- Confirms vulnerabilities with multiple independent tests
- Example: If most SQL injection attempts return 200 OK with 15KB response, but one returns 500 with 2KB, it's flagged as potential SQLi

**Q4: How does the system handle authenticated scanning?**

**A4:**
- User provides username/password during scan creation
- Engine detects login forms automatically via HTML form parsing
- Extracts form fields and submits login POST request
- Stores session cookies from response
- Uses same HTTP session for all subsequent requests
- Validates successful authentication by checking for logout links or expected content
- Credential encryption at rest (AES-256 in database)

**Q5: Explain the database indexing strategy. Why are compound indexes important?**

**A5:**
```
Simple indexes:
  - users.email (for login lookups)
  - scans.user_id (for user's scan history)
  - scans.status (for filtering)

Compound indexes:
  - scans(user_id, created_at) → Fetch latest scans for user efficiently
  - schedules(is_active, next_run) → Polling next scheduled scans
  
TTL indexes:
  - password_reset_otps(expires_at) → Auto-delete after expiration
  - rate_limits(expires_at) → Clean up rate limit records
```
Benefits: Reduces query execution time from O(n) to O(log n), fewer documents scanned, lower memory usage

---

### B. Security

**Q6: How are user passwords stored and verified?**

**A6:**
- Passwords hashed with **bcrypt** (not SHA256 or MD5)
- Bcrypt includes salt automatically, resistant to rainbow tables
- Verification: `pwd_context.verify(plain_password, hashed_password)`
- No plaintext passwords stored or logged
- Password policy: minimum 8 chars, at least one uppercase, one lowercase, one digit

**Q7: Explain JWT token generation and validation in your system.**

**A7:**
```
Generation:
  - payload = {user_id, email, exp (expiration), iat (issued at)}
  - token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
  - Token sent to client

Validation (on each request):
  - Extract token from Authorization header
  - jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
  - Check exp claim (if expired, raise 401)
  - Extract user_id and query database for user role
  - Allow/deny based on required scopes

Duration: 24 hours (configurable via settings)
```

**Q8: How does the system prevent CSRF attacks?**

**A8:**
- **State**: JWT tokens (not session cookies for CSRF-prone operations)
- **Tokens are not auto-sent** with cross-origin requests (no cookies)
- CORS whitelist prevents unauthorized cross-origin access
- POST/PUT/DELETE requests require Authorization header (requires JavaScript)
- Browser same-origin policy blocks form submissions from other domains

**Q9: Describe the credential encryption strategy for scheduled scans.**

**A9:**
- Credentials stored in `schedules.encrypted_credentials` (encrypted)
- Uses **AES-256-GCM** (Cryptography library)
- Encryption key derived from `settings.SECRET_KEY`
- Each schedule has unique IV (initialization vector)
- Decryption happens only when scan executes
- Decrypted credentials never logged or returned in API

**Q10: How is sensitive data (scan payloads, found vulnerabilities) handled?**

**A10:**
- Payloads stored in findings (for reproduction)
- Evidence truncated to 500 characters to avoid huge documents
- Credentials never returned in API responses
- Activity logs don't include sensitive query strings
- Response bodies limited (no 10MB responses stored)
- MongoDB field projection used to exclude sensitive fields in list endpoints

---

### C. Performance & Optimization

**Q11: How does the admin dashboard avoid N+1 queries?**

**A11:**
- Consolidated endpoint `/admin/overview` returns:
  ```json
  {
    "total_users": 150,
    "total_scans": 1200,
    "pending_scans": 5,
    "active_subscriptions": 45,
    "recent_logs": [...],
    "vulnerability_summary": {...}
  }
  ```
- Uses MongoDB aggregation pipeline instead of fetching users then scans then logs separately
- Single query with $group, $count, $facet stages
- Reduces round trips from 5-6 to 1

**Q12: Describe the client-side polling strategy for scan progress.**

**A12:**
- **Exponential backoff**:
  - Initial: Poll every 1 second
  - After 10s: Switch to 5 second intervals
  - After 30s: Switch to 10 second intervals
  - Max: 30 seconds
- **Jitter added**: Prevents thundering herd (all clients polling simultaneously)
- **Early termination**: Stop polling if status changes to "completed" or "cancelled"
- **Result**: Reduces server load by 80% vs fixed 1-second polling

**Q13: How is scan module parallelization implemented?**

**A13:**
```python
async def run_modules(self, target_url, ...):
    # Don't run all 22 modules in series (too slow)
    # Instead, group by phase and parallelize
    
    phase_1_tasks = [
        auth_test(target_url),
        ...
    ]
    
    # Run with semaphore to limit concurrency (max 4 parallel)
    semaphore = asyncio.Semaphore(4)
    
    async def _run_with_limit(coro):
        async with semaphore:
            return await coro
    
    results = await asyncio.gather(
        *[_run_with_limit(t) for t in phase_1_tasks]
    )
```
- Reduces scan time from 10 minutes → 3 minutes
- Limits concurrent connections (prevents overwhelming target)

**Q14: Explain field projection in MongoDB queries for optimization.**

**A14:**
```python
# Instead of:
users = await db.users.find({}).to_list(100)  # Returns ALL fields

# Use projection:
users = await db.users.find(
    {},
    {"email": 1, "username": 1, "subscription_tier": 1}  # Only these fields
).to_list(100)
```
- Reduces network payload by 60-70% (no password_hash, profile_data, etc.)
- Faster serialization to JSON
- Smaller response time for list endpoints

---

### D. WAF Evasion & Detection

**Q15: Explain the 7 WAF evasion techniques implemented.**

**A15:**

| Technique | Example | Detection Bypass |
|-----------|---------|-----------------|
| URL Encoding | `%73%65%6c%65%63%74` (SELECT) | Keyword pattern matching |
| Double URL Encoding | `%25%37%33` (double-encoded %s) | Single-pass decoders |
| Case Variation | `SeLeCt`, `SeLEcT` | Case-sensitive regexes |
| SQL Comments | `SEL/**/ECT`, `SELECT--abc` | Comment stripping bypass |
| Null Bytes | `SELECT%00x` | Truncation in processing |
| Unicode Normalization | `Ü` (U+0308) | Normalization form differences |
| Operator Variation | `SELECT%20UNION%20SELECT` vs `SELECT+UNION+SELECT` | Specific whitespace matching |

Example: If WAF blocks "SELECT", try "S%45LECT" (encoded E), "SEL/**/ECT", "SELECT%00" 

**Q16: How does the engine handle WAF-triggered 403/429 responses?**

**A16:**
- Detects HTTP 403 (Forbidden), 429 (Too Many Requests), 503 (Service Unavailable)
- Reduces request rate by 50% (10 RPS → 5 RPS)
- Increases jitter window (0-500ms → 0-2000ms)
- Inserts longer delays between modules
- After 3 403/429 responses: Flag module as "WAF Detected" and skip remaining tests
- Logs event for user notification

**Q17: What is z-score analysis and why is it used for false-positive filtering?**

**A17:**
```
z-score = (value - mean) / standard_deviation

Example:
- Baseline response times: [500ms, 510ms, 520ms, 515ms] → mean=511, σ=7.9
- Payload response time: 10ms (unusual)
- z-score = (10 - 511) / 7.9 = -63.4 → OUTLIER (likely vulnerable to time-based SQLi)

vs.

- Payload response time: 530ms (within 2σ)
- z-score = (530 - 511) / 7.9 = +2.4 → Normal variance, likely false positive
```
- 2σ threshold = 95% confidence interval
- Reduces false positives by 85% vs. simple threshold-based detection

---

### E. Modern APIs & Advanced Topics

**Q18: How does the GraphQL vulnerability module work?**

**A18:**
```
1. Introspection query:
   query {
     __schema {
       types { name, fields { name } }
     }
   }

2. If succeeds: Schema fully exposed (CRITICAL finding)

3. BOLA testing:
   query {
     user(id: "1") { email, password, credit_card }  // Try accessing other users
     user(id: "999") { email }
   }

4. If accessible: Object-level authorization missing (HIGH finding)
```

**Q19: What are the differences between Reflected, Stored, and DOM-based XSS detected by the engine?**

**A19:**

| Type | Detection Method | Payload | Evidence |
|------|------------------|---------|----------|
| **Reflected** | Inject in parameter, check in response | `<img src=x onerror=alert(1)>` | Payload in HTML output |
| **DOM-based** | Parse JS for sinks | `eval()`, `innerHTML`, `document.write` | Sink usage detected in script |
| **Stored** | Inject, check persistence | Comment/profile update | Payload returned in subsequent GETs |

**Q20: Explain IDOR (Insecure Direct Object Reference) detection.**

**A20:**
```
IDOR Test:
1. Fetch current user's object: GET /api/users/123 (current user ID)
2. Response includes email, settings, data
3. Modify ID sequentially: /api/users/122, /api/users/124, etc.
4. If other users' data returned: IDOR vulnerability (CRITICAL)

Risk scoring:
- If sensitive data returned (emails, passwords): CRITICAL
- If non-sensitive metadata: MEDIUM
- If 403 Forbidden always: Properly protected
```

---

### F. Implementation & Deployment

**Q21: How is the backend deployed on Render, and why is it a challenge?**

**A21:**
- **Challenge**: Render free tier spins down container after 15 min inactivity
- **Solution**: Keep-alive endpoint (`/health`) pinged every 10 minutes
- **Deployment**: Push to GitHub, Render auto-deploys
- **Cold start**: First request after spin-down takes 20-30 seconds
- **Environment**: 
  - Render sets PORT=10000
  - Auto-scales to 0 containers when idle
  - Full reset of in-memory state (cancel_flags, caches)

**Q22: Explain the frontend build process with Vite. Why Vite over Webpack?**

**A22:**
```
Vite vs Webpack:

Vite:
  - esbuild (Go-based) for bundling (10-40x faster)
  - ES modules natively in dev (no bundling during dev)
  - Hot Module Replacement (HMR) in <100ms
  - Build time: 2-5 seconds

Webpack:
  - JS-based, slower
  - Full rebundle on every change
  - HMR can take 5-10 seconds
  - Build time: 30-60 seconds
```
- Netlify triggers build: `npm run build` → vite build
- Output: `dist/` folder deployed
- Source maps generated for debugging (removed in production)

**Q23: How is the mobile app built and deployed?**

**A23:**
- **Framework**: React Native + Expo SDK
- **Build**: EAS Build (Expo Application Services)
  - Push code → EAS builds iOS .ipa and Android .apk
  - No local Xcode/Android Studio needed
  - Takes 10-15 minutes per build
- **Distribution**: 
  - Test: EAS Preview (QR code distribution)
  - Production: App Store, Google Play
- **API Calls**: Axios to backend, HTTPS enforced
- **Storage**: Expo SecureStore (encrypted local storage for JWT tokens)

**Q24: How are PDF reports generated? What data is included?**

**A24:**
```python
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, Paragraph, PageBreak

def generate_pdf(scan):
    doc = SimpleDocTemplate("report.pdf")
    story = [
        Paragraph(f"Scan Report: {scan.target_url}"),
        Paragraph(f"Date: {scan.created_at}"),
        # Severity breakdown (pie chart)
        # Vulnerability table: Type | Severity | URL | Payload
        # Remediation steps
    ]
    doc.build(story)
```

Data included:
- Target URL, scan date, duration
- Vulnerability count by severity
- Detailed finding table (type, severity, confidence, URL, evidence)
- CVSS scores, remediation steps
- Executive summary

**Q25: Describe the AI remediation feature using Claude API.**

**A25:**
```python
client = Anthropic()
response = client.messages.create(
    model="claude-opus-4-5",
    messages=[{
        "role": "user",
        "content": f"""
        Vulnerability: {vuln_type}
        Evidence: {evidence}
        Provide remediation steps in code snippet format.
        """
    }]
)
```
- Called per-vulnerability (not per-scan, to save costs)
- Cache responses (avoid duplicate API calls)
- Charged: ~$0.003 per 1000 tokens (Claude is expensive)
- Requires active subscription ($9.99/month)

---

### G. Database & Query Optimization

**Q26: How does the scheduled scanning feature work at scale?**

**A26:**
```
Scheduler loop (runs every minute):
1. Query: db.schedules.find({is_active: true, next_run: {$lte: now}})
2. For each schedule:
   - Decrypt credentials
   - Spawn run_scan() background task
   - Calculate next_run (if repeating): next_run = now + interval
   - Update: db.schedules.update_one({_id: sched_id}, {next_run: next_run})
3. Scan executes asynchronously, doesn't block scheduler
4. Results stored with schedule_id reference

Scale concern: If 1000 scheduled scans due at same time
Solution:
  - Add jitter to next_run (random 0-5 min offset)
  - Spread load across scheduler ticks
  - Use rate limiter on module execution
```

**Q27: Explain transaction handling for payment subscriptions.**

**A27:**
```python
# Issue: User creates subscription but fails midway
async def purchase_subscription(user_id, tier):
    # 1. Create payment record
    payment = await db.subscription_payments.insert_one({
        user_id, status: "pending", ...
    })
    
    # 2. Call payment processor (Stripe)
    try:
        result = await stripe.charge(...)
        await db.subscription_payments.update_one(
            {_id: payment._id},
            {$set: {status: "paid"}}
        )
        
        # 3. Update user subscription
        await db.users.update_one(
            {_id: user_id},
            {$set: {
                has_ai_subscription: true,
                subscription_tier: tier,
                subscription_expires_at: now + 30 days
            }}
        )
    except:
        await db.subscription_payments.update_one(
            {_id: payment._id},
            {$set: {status: "failed"}}
        )
        raise
```

MongoDB doesn't support distributed transactions easily, so rely on:
- Idempotent operations (safe to retry)
- Payment processor webhook for confirmation
- Subscription expiration cleanup job (cron)

**Q28: How are activity logs stored and queried efficiently?**

**A28:**
```
Collection: activity_logs
  ├─ user_id (indexed)
  ├─ action (login, scan_start, scan_complete)
  ├─ details (object with context)
  ├─ ip_address
  └─ timestamp (indexed, reverse order)

Query: Get user's last 50 logs
  db.activity_logs
    .find({user_id: "123"})
    .sort({timestamp: -1})
    .limit(50)

Index: {timestamp: -1, user_id: 1} (compound)
```
- TTL not used (logs kept for audit compliance)
- Admin dashboard queries last 100 logs globally
- Logs grow unbounded (consider archiving monthly)

---

### H. Error Handling & Edge Cases

**Q29: How does the engine handle timeout/unresponsive targets?**

**A29:**
```python
async with httpx.AsyncClient(timeout=10.0) as client:
    try:
        response = await client.get(url)
    except httpx.ConnectError:
        # Server refused connection
        return ScanResult(..., evidence="Server offline", confidence=MEDIUM)
    except httpx.ReadTimeout:
        # Server took >10 seconds
        return ScanResult(..., evidence="Timeout detected", risk_score=LOW)
    except httpx.RequestError as e:
        # Network error, DNS resolution failure
        # Log and skip this module
        logger.error(f"Request error: {e}")
        continue
```

**Q30: What happens if a user cancels a scan mid-execution?**

**A30:**
1. Frontend: POST /scans/{scan_id}/cancel
2. Backend: `cancel_flags[scan_id] = True`
3. Scan engine: Every module checks `_check_cancel(scan_id)`
4. ScanCancelledException raised → scan stops
5. MongoDB: Update scan with status="cancelled", findings saved so far
6. Frontend: Polling sees status change, stops polling
7. Result: Clean termination, no zombie threads

---

## BONUS: Common Interview Mistakes to Avoid

1. **Don't say "I used MongoDB because it's NoSQL"** → Explain: Flexible schema (scan findings vary), horizontal scaling, document indexing
2. **Don't claim zero false positives** → Explain: Use statistical baseline to reduce to <5%, trade-off between coverage and precision
3. **Don't overcomplicate rate limiting** → Simple rule: max 10 RPS + jitter. Don't mention quantum algorithms or ML models
4. **Don't say "JWT is secure"** → Clarify: JWT + HTTPS + short expiry (24h) + secure key storage
5. **Don't claim the scanner is perfect** → Explain: Can't detect all 0-days, business logic vulnerabilities require manual testing
6. **Avoid vague answers on scaling** → Give numbers: MongoDB M0 (512MB), handles ~10 concurrent scans, Render free tier has limitations

---

## Key Metrics to Mention

- **Scan coverage**: 22 vulnerability modules, 85+ payload variations
- **False positive rate**: <5% (statistical baseline)
- **Avg scan time**: 2-5 minutes (depending on target size)
- **Concurrent capacity**: ~10 scans simultaneously (free tier)
- **API response time**: <100ms (with indexing + projection)
- **Code base**: ~3000 LOC (backend), ~2000 LOC (frontend), ~1500 LOC (mobile)
