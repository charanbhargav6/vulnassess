from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.db.database import connect_db, get_database
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.admin import router as admin_router, modules_router
from app.api.reports import router as reports_router
from app.api.profile import router as profile_router
from app.api.compare import router as compare_router
from app.api.schedule import router as schedule_router
from app.core.config import settings
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from datetime import datetime, timedelta
import asyncio
import time
from urllib.parse import urlparse

scheduler = AsyncIOScheduler()
MAX_REQUEST_BODY_BYTES = 1_048_576  # 1 MiB


async def ensure_indexes(db):
    await db.users.create_index([("email", 1)])
    await db.users.create_index([("created_at", -1)])

    await db.password_reset_otps.create_index([("email", 1), ("created_at", -1)])
    await db.password_reset_otps.create_index([("expires_at", 1)], expireAfterSeconds=0)

    await db.scans.create_index([("user_id", 1)])
    await db.scans.create_index([("created_at", -1)])
    await db.scans.create_index([("status", 1), ("created_at", -1)])
    await db.scans.create_index([("target_url", 1)])

    await db.schedules.create_index([("user_id", 1)])
    await db.schedules.create_index([("is_active", 1), ("next_run", 1)])

    await db.subscription_payments.create_index([("user_id", 1), ("created_at", -1)])
    await db.activity_logs.create_index([("timestamp", -1)])
    await db.rate_limits.create_index([("expires_at", 1)], expireAfterSeconds=0)


async def revoke_expired_subscriptions():
    try:
        db = get_database()
        now = datetime.utcnow()
        result = await db.users.update_many(
            {
                "has_ai_subscription": True,
                "subscription_expires_at": {"$ne": None, "$lte": now},
            },
            {
                "$set": {
                    "has_ai_subscription": False,
                    "subscription_tier": None,
                    "subscription_status": "inactive",
                    "subscription_expires_at": None,
                }
            },
        )
        if result.modified_count:
            print(f"Subscription cleanup: revoked {result.modified_count} expired subscriptions")
    except Exception as e:
        print(f"Subscription cleanup error: {e}")


async def run_scheduled_scans():
    try:
        db = get_database()
        from app.services.credential_crypto import decrypt_secret
        now = datetime.utcnow()
        async for schedule in db.schedules.find({
            "is_active": True,
            "next_run": {"$lte": now}
        }):
            from app.scan_engine.engine import run_scan

            username = None
            password = None
            if schedule.get("auth_enabled"):
                try:
                    username = decrypt_secret(schedule.get("auth_username_enc"))
                    password = decrypt_secret(schedule.get("auth_password_enc"))
                except Exception as exc:
                    print(f"Scheduler auth decrypt failed for schedule {schedule.get('_id')}: {exc}")
                    username = None
                    password = None

            scan_data = {
                "user_id": schedule["user_id"],
                "target_url": schedule["target_url"],
                "status": "pending",
                "created_at": now,
                "total_risk_score": 0.0,
                "vulnerabilities": [],      # use correct field name from engine
                "scheduled": True,
                "schedule_id": str(schedule["_id"])
            }
            result = await db.scans.insert_one(scan_data)
            scan_id = str(result.inserted_id)

            asyncio.create_task(run_scan(
                scan_id,
                schedule["target_url"],
                username,
                password,
            ))

            hours = schedule["interval_hours"]
            next_run = now + timedelta(hours=hours)
            await db.schedules.update_one(
                {"_id": schedule["_id"]},
                {"$set": {
                    "last_run": now,
                    "next_run": next_run,
                    "run_count": schedule.get("run_count", 0) + 1
                }}
            )
    except Exception as e:
        print(f"Scheduler error: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    await connect_db()
    db = get_database()
    await ensure_indexes(db)

    # Module defaults — keys match engine.py exactly
    default_modules = [
        {"module_key": "auth_test",        "name": "Authentication Testing",     "enabled": True,  "order": 1,  "fixed": True},
        {"module_key": "sql_injection",    "name": "SQL Injection",              "enabled": True,  "order": 2,  "fixed": False},
        {"module_key": "xss",              "name": "Cross-Site Scripting (XSS)", "enabled": True,  "order": 3,  "fixed": False},
        {"module_key": "csrf",             "name": "CSRF Protection",            "enabled": True,  "order": 4,  "fixed": False},
        {"module_key": "path_traversal",   "name": "Path Traversal",             "enabled": True,  "order": 5,  "fixed": False},
        {"module_key": "security_headers", "name": "Security Headers",           "enabled": True,  "order": 6,  "fixed": False},
        {"module_key": "ssl_tls",          "name": "SSL/TLS Analysis",           "enabled": True,  "order": 7,  "fixed": False},
        {"module_key": "open_redirect",    "name": "Open Redirect",              "enabled": True,  "order": 8,  "fixed": False},
        {"module_key": "info_disclosure",  "name": "Information Disclosure",     "enabled": True,  "order": 9,  "fixed": False},
        {"module_key": "cors_check",       "name": "CORS Misconfiguration",      "enabled": True,  "order": 10, "fixed": False},
        {"module_key": "cookie_security",  "name": "Cookie Security",            "enabled": True,  "order": 11, "fixed": False},
        {"module_key": "rate_limiting",    "name": "Rate Limiting Check",        "enabled": True,  "order": 12, "fixed": False},
        {"module_key": "file_upload",      "name": "File Upload Vulnerabilities","enabled": True,  "order": 13, "fixed": False},
        {"module_key": "clickjacking",     "name": "Clickjacking Protection",    "enabled": True,  "order": 14, "fixed": False},
        {"module_key": "ssrf",             "name": "SSRF Testing",               "enabled": True,  "order": 15, "fixed": False},
        {"module_key": "xxe",              "name": "XXE Injection",              "enabled": True,  "order": 16, "fixed": False},
        {"module_key": "command_injection","name": "Command Injection",          "enabled": True,  "order": 17, "fixed": False},
        {"module_key": "idor",             "name": "IDOR Testing",               "enabled": True,  "order": 18, "fixed": False},
        {"module_key": "graphql",          "name": "GraphQL Security",           "enabled": False, "order": 19, "fixed": False},
        {"module_key": "api_key_leakage",  "name": "API Key Leakage",            "enabled": True,  "order": 20, "fixed": False},
        {"module_key": "jwt",              "name": "JWT Security",               "enabled": True,  "order": 21, "fixed": False},
    ]
    for module in default_modules:
        await db.modules.update_one(
            {"module_key": module["module_key"]},
            {"$setOnInsert": module},
            upsert=True
        )

    # Patch old users without is_verified
    await db.users.update_many(
        {"is_verified": {"$exists": False}},
        {"$set": {"is_verified": True}}
    )

    # Backfill subscription and proxy fields for existing users
    await db.users.update_many(
        {"has_ai_subscription": {"$exists": False}},
        {
            "$set": {
                "has_ai_subscription": False,
                "subscription_tier": None,
                "subscription_status": "inactive",
                "subscription_expires_at": None,
            }
        }
    )
    await db.users.update_many(
        {"proxy_enabled": {"$exists": False}},
        {
            "$set": {
                "proxy_enabled": False,
                "proxy_url": None,
                "proxy_type": "http",
            }
        }
    )
    await db.users.update_many(
        {"token_version": {"$exists": False}},
        {"$set": {"token_version": 1}},
    )

    # Backfill payment method metadata for existing payment records
    await db.subscription_payments.update_many(
        {"payment_method": {"$exists": False}},
        {"$set": {"payment_method": "upi"}}
    )
    await db.subscription_payments.update_many(
        {"payment_meta": {"$exists": False}},
        {"$set": {"payment_meta": {}}}
    )

    # Start scheduler — check every minute
    scheduler.add_job(
        run_scheduled_scans,
        "interval",
        minutes=1,
        id="scheduled_scans",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.add_job(
        revoke_expired_subscriptions,
        "interval",
        minutes=10,
        id="subscription_cleanup",
        replace_existing=True,
        coalesce=True,
        max_instances=1,
    )
    scheduler.start()

    # Run cleanup once at startup too.
    await revoke_expired_subscriptions()

    print("✅ Connected to MongoDB:", settings.DATABASE_NAME)
    print("✅ Modules seeded")
    print("✅ Scheduler started")

    yield

    # ── Shutdown ──
    scheduler.shutdown(wait=False)


app = FastAPI(
    title="VulnAssess API",
    version="2.0.0",
    description="Advanced Web Vulnerability Assessment Platform",
    lifespan=lifespan,
)

# CORS — restrict to known origins in production
allowed_origins = [
    settings.FRONTEND_URL,
    "https://vulnassess.netlify.app",
    "http://localhost:3000",
    "http://localhost:8081",
    "http://localhost:8082",
    "http://localhost:8083",
    "http://localhost:19006",  # Expo web dev
]

csrf_trusted_origins = {
    origin.rstrip("/").lower()
    for origin in allowed_origins
    if origin
}
csrf_trusted_origins.update(
    {
        origin.strip().rstrip("/").lower()
        for origin in settings.CSRF_TRUSTED_ORIGINS.split(",")
        if origin.strip()
    }
)


def _is_trusted_browser_origin(value: str) -> bool:
    candidate = (value or "").strip()
    if not candidate:
        return False

    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False

    origin = f"{parsed.scheme}://{parsed.netloc}".rstrip("/").lower()
    if origin in csrf_trusted_origins:
        return True

    host = parsed.hostname.lower()
    return host in {"localhost", "127.0.0.1"}

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
        except ValueError:
            return JSONResponse(
                status_code=400,
                content={"detail": "Invalid Content-Length header"},
            )

    return await call_next(request)


@app.middleware("http")
async def csrf_cookie_guard(request: Request, call_next):
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        auth_header = (request.headers.get("Authorization") or "").strip().lower()
        has_bearer_header = auth_header.startswith("bearer ")
        has_session_cookie = bool((request.cookies.get(settings.AUTH_COOKIE_NAME) or "").strip())

        # Protect cookie-authenticated browser requests against cross-site mutation.
        if has_session_cookie and not has_bearer_header:
            requested_with = (request.headers.get("X-Requested-With") or "").strip()
            if requested_with != "XMLHttpRequest":
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF protection: missing request marker"},
                )

            origin = (request.headers.get("Origin") or "").strip()
            referer = (request.headers.get("Referer") or "").strip()
            source = origin or referer
            if not source or not _is_trusted_browser_origin(source):
                return JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF protection: untrusted request origin"},
                )

    return await call_next(request)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")

    if request.url.scheme == "https":
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

    if request.url.path.startswith("/api/auth") or request.url.path.startswith("/api/profile"):
        response.headers.setdefault("Cache-Control", "no-store")

    return response


@app.middleware("http")
async def log_slow_requests(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    duration = time.perf_counter() - start

    if duration >= 1.0:
        print(
            f"SLOW REQUEST: {request.method} {request.url.path} "
            f"status={response.status_code} duration={duration:.3f}s"
        )

    return response

app.include_router(auth_router,    prefix="/api")
app.include_router(scans_router,   prefix="/api")
app.include_router(admin_router,   prefix="/api")
app.include_router(modules_router, prefix="/api")
app.include_router(reports_router, prefix="/api")
app.include_router(profile_router, prefix="/api")
app.include_router(compare_router, prefix="/api")
app.include_router(schedule_router, prefix="/api")


@app.get("/")
async def root():
    return {
        "message": "VulnAssess API Running",
        "version": "2.0.0",
        "docs": "/docs",
    }


@app.get("/health")
async def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}