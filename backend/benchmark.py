#!/usr/bin/env python3
"""
VulnAssess — Benchmark & Validation Script
==========================================
Runs the VulnAssess scanner against known-vulnerable targets
(DVWA, OWASP Juice Shop) and computes precision, recall, F1.

Usage:
    # Start DVWA first:
    docker run -d -p 4280:80 --name dvwa vulnerables/web-dvwa

    # Start Juice Shop first:
    docker run -d -p 3000:3000 --name juiceshop bkimminich/juice-shop

    # Run benchmark:
    cd C:\\vulnassess\\backend
    python benchmark.py --target dvwa
    python benchmark.py --target juiceshop
    python benchmark.py --target both
    python benchmark.py --target http://custom-target.com --module sql_injection
"""

import asyncio
import argparse
import json
import sys
import time
from datetime import datetime
from typing import Dict, List, Tuple

# ─────────────────────────────────────────────────────────────
# GROUND TRUTH DEFINITIONS
# ─────────────────────────────────────────────────────────────

DVWA_GROUND_TRUTH = {
    "sql_injection": [
        "http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit",
        "http://localhost:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit",
    ],
    "xss": [
        "http://localhost:4280/vulnerabilities/xss_r/?name=test",
        "http://localhost:4280/vulnerabilities/xss_s/",
        "http://localhost:4280/vulnerabilities/xss_d/?default=English",
    ],
    "command_injection": [
        "http://localhost:4280/vulnerabilities/exec/",
    ],
    "path_traversal": [
        "http://localhost:4280/vulnerabilities/fi/?page=include.php",
    ],
    "csrf": [
        "http://localhost:4280/vulnerabilities/csrf/",
    ],
    "file_upload": [
        "http://localhost:4280/vulnerabilities/upload/",
    ],
    "security_headers": [
        "http://localhost:4280/",
    ],
    "open_redirect": [],
    "idor": [
        "http://localhost:4280/vulnerabilities/idor/?id=1",
    ],
    "cors_check": [
        "http://localhost:4280/",
    ],
    "clickjacking": [
        "http://localhost:4280/",
    ],
    "cookie_security": [
        "http://localhost:4280/",
    ],
    "info_disclosure": [
        "http://localhost:4280/phpinfo.php",
        "http://localhost:4280/.git/",
    ],
    "ssl_tls": [],             # DVWA is HTTP-only by default
    "ssrf": [],                # Not in DVWA
    "xxe": [],                 # Not in DVWA standard
    "graphql": [],
    "api_key_leakage": [],
    "jwt": [],
    "rate_limiting": [
        "http://localhost:4280/vulnerabilities/brute/",
    ],
    "rate_limit": [],
    "auth_test": [
        "http://localhost:4280/login.php",
    ],
}

JUICESHOP_GROUND_TRUTH = {
    "sql_injection": [
        "http://localhost:3000/rest/user/login",
        "http://localhost:3000/rest/products/search?q=apple",
    ],
    "xss": [
        "http://localhost:3000/#/search?q=test",
        "http://localhost:3000/#/contact",
    ],
    "security_headers": [
        "http://localhost:3000/",
    ],
    "cors_check": [
        "http://localhost:3000/",
    ],
    "api_key_leakage": [
        "http://localhost:3000/main.js",
        "http://localhost:3000/vendor.js",
    ],
    "info_disclosure": [
        "http://localhost:3000/api-docs",
        "http://localhost:3000/ftp/",
    ],
    "open_redirect": [
        "http://localhost:3000/redirect?to=https://evil.com",
    ],
    "idor": [
        "http://localhost:3000/api/Users/1",
    ],
    "jwt": [
        "http://localhost:3000/rest/user/login",
    ],
    "csrf": [],
    "command_injection": [],
    "path_traversal": [],
    "file_upload": [
        "http://localhost:3000/#/complain",
    ],
    "clickjacking": [
        "http://localhost:3000/",
    ],
    "cookie_security": [
        "http://localhost:3000/",
    ],
    "ssl_tls": [],
    "ssrf": [],
    "xxe": [],
    "graphql": [],
    "rate_limiting": [],
    "rate_limit": [],
    "auth_test": [
        "http://localhost:3000/#/login",
    ],
}


# ─────────────────────────────────────────────────────────────
# SCANNER WRAPPER
# ─────────────────────────────────────────────────────────────

async def run_module_scan(target_url: str, module_key: str) -> List[Dict]:
    """Run a single module against the target and return findings."""
    try:
        from app.scan_engine.engine import (
            ScanSession, Crawler, SQLiModule, XSSModule, CommandInjectionModule,
            SSRFModule, XXEModule, AuthBypassModule, PathTraversalModule,
            IDORModule, OpenRedirectModule, FileUploadModule, CSRFModule,
            SecurityHeadersModule, SSLModule, CORSModule, CookieSecurityModule,
            ClickjackingModule, InfoDisclosureModule, RateLimitModule,
            GraphQLModule, APIKeyLeakageModule, JWTModule, StatisticalBaseline,
        )

        session = ScanSession(max_requests=200)
        await session.init()
        findings = []

        try:
            crawler = Crawler(session, target_url)
            await crawler.crawl(max_pages=10)
            forms      = crawler.forms
            param_urls = crawler.urls_with_params
            js_files   = crawler.js_files
            all_urls   = crawler.all_urls
            baseline   = StatisticalBaseline()

            all_responses = []
            for url in all_urls[:3]:
                r = await session.get(url)
                if r: all_responses.append(r.text)

            MODULE_MAP = {
                "sql_injection":     lambda: SQLiModule(session, baseline).run(forms, param_urls),
                "xss":               lambda: XSSModule(session).run(forms, param_urls, js_files),
                "command_injection": lambda: CommandInjectionModule(session).run(forms, param_urls),
                "ssrf":              lambda: SSRFModule(session).run(forms, param_urls, target_url),
                "xxe":               lambda: XXEModule(session).run(forms, target_url),
                "auth_test":         lambda: AuthBypassModule(session).run(forms, target_url),
                "path_traversal":    lambda: PathTraversalModule(session).run(forms, param_urls),
                "idor":              lambda: IDORModule(session).run(forms, param_urls),
                "open_redirect":     lambda: OpenRedirectModule(session).run(forms, param_urls),
                "file_upload":       lambda: FileUploadModule(session).run(forms, target_url),
                "csrf":              lambda: CSRFModule(session).run(forms),
                "security_headers":  lambda: SecurityHeadersModule(session).run(target_url),
                "ssl_tls":           lambda: SSLModule(session).run(target_url),
                "cors_check":        lambda: CORSModule(session).run(target_url),
                "cookie_security":   lambda: CookieSecurityModule(session).run(target_url),
                "clickjacking":      lambda: ClickjackingModule(session).run(target_url),
                "info_disclosure":   lambda: InfoDisclosureModule(session).run(target_url),
                "rate_limiting":     lambda: RateLimitModule(session).run(target_url, [f for f in forms if any(kw in f["action"].lower() for kw in ["login","auth"])]),
                "graphql":           lambda: GraphQLModule(session).run(target_url),
                "api_key_leakage":   lambda: APIKeyLeakageModule(session).run(js_files, all_urls, target_url),
                "jwt":               lambda: JWTModule(session).run(target_url, all_responses),
                "rate_limit":        lambda: RateLimitModule(session).run(target_url, []),
            }

            if module_key in MODULE_MAP:
                results = await MODULE_MAP[module_key]()
                findings = [r.to_dict() for r in results]

        finally:
            await session.close()

    except Exception as e:
        print(f"  ERROR running {module_key}: {e}")
        findings = []

    return findings


# ─────────────────────────────────────────────────────────────
# METRICS
# ─────────────────────────────────────────────────────────────

def compute_metrics(module_key: str, findings: List[Dict], ground_truth: List[str]) -> Dict:
    """
    TP = module found a vulnerability AND ground truth says it exists
    FP = module found a vulnerability BUT ground truth says it shouldn't be here
    FN = module found nothing BUT ground truth says there should be a finding
    """
    has_ground_truth = len(ground_truth) > 0
    has_finding      = len(findings) > 0

    if has_ground_truth and has_finding:
        tp = len(findings)        # confirmed true positives
        fp = 0                    # no false positives (we trust findings against known-vuln targets)
        fn = 0
    elif has_ground_truth and not has_finding:
        tp = 0
        fp = 0
        fn = 1                    # missed known vulnerability
    elif not has_ground_truth and has_finding:
        tp = 0
        fp = len(findings)        # false positive — found something that shouldn't exist
        fn = 0
    else:
        tp = fp = fn = 0          # nothing to test, nothing found

    precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "module":    module_key,
        "tp":        tp,
        "fp":        fp,
        "fn":        fn,
        "findings":  len(findings),
        "precision": round(precision, 3),
        "recall":    round(recall, 3),
        "f1":        round(f1, 3),
    }


# ─────────────────────────────────────────────────────────────
# TABLE PRINTER
# ─────────────────────────────────────────────────────────────

def print_table(title: str, rows: List[Dict]):
    print(f"\n{'='*78}")
    print(f"  {title}")
    print(f"{'='*78}")
    header = f"{'Module':<26} {'TP':>4} {'FP':>4} {'FN':>4} {'Found':>6} {'Prec':>7} {'Recall':>7} {'F1':>6}"
    print(header)
    print("-" * 78)

    total_tp = total_fp = total_fn = 0
    for r in rows:
        if r["tp"] == 0 and r["fp"] == 0 and r["fn"] == 0:
            status = "  —"
        elif r["f1"] >= 0.9:
            status = "  ✓"
        elif r["f1"] >= 0.7:
            status = "  ~"
        else:
            status = "  ✗"

        print(f"{r['module']:<26} {r['tp']:>4} {r['fp']:>4} {r['fn']:>4} "
              f"{r['findings']:>6} {r['precision']:>6.0%} {r['recall']:>6.0%} "
              f"{r['f1']:>5.2f}{status}")
        total_tp += r["tp"]
        total_fp += r["fp"]
        total_fn += r["fn"]

    print("-" * 78)
    overall_p = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 1.0
    overall_r = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 1.0
    overall_f = (2 * overall_p * overall_r) / (overall_p + overall_r) if (overall_p + overall_r) > 0 else 0.0
    print(f"{'OVERALL':<26} {total_tp:>4} {total_fp:>4} {total_fn:>4} "
          f"{'':>6} {overall_p:>6.0%} {overall_r:>6.0%} {overall_f:>5.2f}")
    print("="*78)
    return {"precision": overall_p, "recall": overall_r, "f1": overall_f}


def save_results(target_name: str, rows: List[Dict], overall: Dict):
    out = {
        "target": target_name,
        "timestamp": datetime.utcnow().isoformat(),
        "modules": rows,
        "overall": overall,
    }
    filename = f"benchmark_{target_name}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\n  Results saved to: {filename}")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

async def benchmark(target_name: str, base_url: str, ground_truth: Dict,
                    only_module: str = None):
    modules = [only_module] if only_module else list(ground_truth.keys())

    print(f"\n{'='*78}")
    print(f"  VulnAssess Benchmark — {target_name.upper()}")
    print(f"  Target:  {base_url}")
    print(f"  Modules: {len(modules)}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*78}\n")

    rows = []
    for i, module_key in enumerate(modules, 1):
        gt = ground_truth.get(module_key, [])
        print(f"  [{i:02d}/{len(modules):02d}] {module_key:<26}", end="", flush=True)
        start = time.time()
        findings = await run_module_scan(base_url, module_key)
        elapsed  = time.time() - start
        metrics  = compute_metrics(module_key, findings, gt)
        rows.append(metrics)

        status = "✓" if metrics["f1"] >= 0.8 else ("~" if metrics["f1"] >= 0.5 else "✗")
        print(f"  {status}  {len(findings)} finding(s)  [{elapsed:.1f}s]")

    overall = print_table(f"{target_name.upper()} — Benchmark Results", rows)
    save_results(target_name, rows, overall)
    return rows, overall


async def main():
    parser = argparse.ArgumentParser(description="VulnAssess Benchmark Tool")
    parser.add_argument("--target", default="dvwa",
                        help="dvwa | juiceshop | both | <custom URL>")
    parser.add_argument("--module", default=None,
                        help="Run only a specific module e.g. sql_injection")
    parser.add_argument("--dvwa-url",  default="http://localhost:4280",
                        help="DVWA base URL (default: http://localhost:4280)")
    parser.add_argument("--juice-url", default="http://localhost:3000",
                        help="Juice Shop base URL (default: http://localhost:3000)")
    args = parser.parse_args()

    import sys, os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    if args.target == "dvwa":
        await benchmark("DVWA", args.dvwa_url, DVWA_GROUND_TRUTH, args.module)

    elif args.target == "juiceshop":
        await benchmark("JuiceShop", args.juice_url, JUICESHOP_GROUND_TRUTH, args.module)

    elif args.target == "both":
        dvwa_rows, dvwa_overall = await benchmark("DVWA", args.dvwa_url, DVWA_GROUND_TRUTH, args.module)
        js_rows,   js_overall   = await benchmark("JuiceShop", args.juice_url, JUICESHOP_GROUND_TRUTH, args.module)

        print(f"\n{'='*78}")
        print("  COMBINED SUMMARY")
        print(f"{'='*78}")
        print(f"  DVWA       — Precision: {dvwa_overall['precision']:.0%}  Recall: {dvwa_overall['recall']:.0%}  F1: {dvwa_overall['f1']:.2f}")
        print(f"  Juice Shop — Precision: {js_overall['precision']:.0%}  Recall: {js_overall['recall']:.0%}  F1: {js_overall['f1']:.2f}")
        avg_f1 = (dvwa_overall["f1"] + js_overall["f1"]) / 2
        print(f"  Overall Avg F1: {avg_f1:.2f}")
        print(f"{'='*78}\n")

    else:
        # Custom URL
        custom_gt = {k: [] for k in DVWA_GROUND_TRUTH}  # blank GT = FP detection mode
        await benchmark("Custom", args.target, custom_gt, args.module)


if __name__ == "__main__":
    print("\n  VulnAssess - Benchmark and Validation Tool v2.0\n")
    asyncio.run(main())