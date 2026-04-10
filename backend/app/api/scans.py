from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from app.db.database import get_database
from app.schemas.schemas import ScanCreate, TargetVerifyRequest
from app.core.security import verify_token, verify_password as verify_pwd, create_access_token
from app.core.auth_utils import get_authenticated_user, get_authenticated_db_user
from app.core.config import settings
from app.services.url_security import normalize_target_url, validate_scan_target
from app.scan_engine.engine import run_scan
from typing import Optional
from datetime import datetime, timedelta
from bson import ObjectId
from pydantic import BaseModel
from urllib.parse import urlparse
import httpx
import re
import logging

router = APIRouter()
logger = logging.getLogger(__name__)

# Cancel flags stored in memory (scan_id -> True means cancel requested)
cancel_flags = {}


def _host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower().strip()


def _blocked_hosts() -> set:
    return {h.strip().lower() for h in settings.BLOCKED_SCAN_HOSTS.split(",") if h.strip()}


def _protected_hosts() -> set:
    return {h.strip().lower() for h in settings.PROTECTED_OWN_HOSTS.split(",") if h.strip()}


def _is_blocked_host(host: str) -> bool:
    blocked = _blocked_hosts()
    return host in blocked


def _is_protected_host(host: str) -> bool:
    protected = _protected_hosts()
    if host in protected:
        return True
    return host.endswith(".vulnassess.netlify.app") or host.endswith(".onrender.com")


def _extract_title(html: str) -> str:
    if not html:
        return ""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:120]


async def get_current_user(request: Request):
    return await get_authenticated_user(request)


@router.post("/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str, request: Request):
    payload = await get_current_user(request)
    db = get_database()
    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    user_id = payload.get("sub")
    role = payload.get("role")
    if role != "admin" and scan["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    if scan["status"] != "running":
        raise HTTPException(status_code=400, detail="Scan is not running")

    cancel_flags[scan_id] = True
    return {"message": "Cancellation requested"}


class DeleteVerifyRequest(BaseModel):
    password: str


@router.post("/scans/verify-target")
async def verify_target_url(data: TargetVerifyRequest, request: Request):
    payload = await get_current_user(request)
    normalized_url, _ = validate_scan_target(data.target_url, is_admin=(payload.get("role") == "admin"))

    candidate_urls = [normalized_url]
    parsed = urlparse(normalized_url)
    if parsed.scheme == "http":
        candidate_urls.append(normalized_url.replace("http://", "https://", 1))
    elif parsed.scheme == "https":
        candidate_urls.append(normalized_url.replace("https://", "http://", 1))

    response = None
    final_candidate = normalized_url
    failure_reason = "url not found"
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as client:
            for candidate in candidate_urls:
                try:
                    check = await client.get(
                        candidate,
                        headers={"User-Agent": "VulnAssess URL Verifier/2.0"},
                    )
                    if check.status_code < 500:
                        response = check
                        final_candidate = candidate
                        break
                    failure_reason = f"target returned status {check.status_code}"
                except httpx.ConnectTimeout:
                    failure_reason = "connection timed out from scanner server"
                    continue
                except httpx.ReadTimeout:
                    failure_reason = "target response timed out"
                    continue
                except httpx.ConnectError:
                    failure_reason = "target host is unreachable from scanner server"
                    continue
                except Exception:
                    failure_reason = "url not found"
                    continue
    except Exception:
        response = None

    if response is None:
        logger.warning("Target verification failed for %s: %s", normalized_url, failure_reason)
        return {
            "verified": False,
            "message": failure_reason,
        }

    if response.status_code >= 400:
        return {
            "verified": False,
            "message": "url not found",
        }

    final_url = str(response.url or final_candidate)
    final_url, final_host = validate_scan_target(final_url, is_admin=(payload.get("role") == "admin"))

    verification_token = create_access_token(
        {
            "sub": payload["sub"],
            "purpose": "scan_verify",
            "target_url": final_url.rstrip("/"),
        },
        expires_delta=timedelta(minutes=20),
    )

    return {
        "verified": True,
        "normalized_url": final_url,
        "title": _extract_title(response.text[:12000]),
        "favicon_url": f"https://www.google.com/s2/favicons?domain={final_host}&sz=128",
        "verification_token": verification_token,
        "message": "verified",
    }


@router.delete("/scans/{scan_id}/verify-delete")
async def delete_scan_with_password(scan_id: str, data: DeleteVerifyRequest, request: Request):
    payload = await get_current_user(request)
    db = get_database()

    user = await get_authenticated_db_user(request)

    if not verify_pwd(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if payload.get("role") != "admin" and scan["user_id"] != payload["sub"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.scans.delete_one({"_id": ObjectId(scan_id)})
    return {"message": "Scan deleted successfully"}


@router.post("/scans")
async def create_scan(scan: ScanCreate, request: Request, background_tasks: BackgroundTasks):
    payload = await get_current_user(request)
    db = get_database()

    user = await get_authenticated_db_user(request)

    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated")

    target_url, _ = validate_scan_target(scan.target_url, is_admin=(payload.get("role") == "admin"))

    if not scan.verify_token:
        raise HTTPException(status_code=400, detail="Please verify target URL first")

    verify_payload = verify_token(scan.verify_token)
    if not verify_payload:
        raise HTTPException(status_code=401, detail="Target verification expired. Please verify again")

    token_target = (verify_payload.get("target_url") or "").rstrip("/")
    requested_target = target_url.rstrip("/")
    if (
        verify_payload.get("purpose") != "scan_verify"
        or verify_payload.get("sub") != payload.get("sub")
        or token_target != requested_target
    ):
        raise HTTPException(status_code=403, detail="Target URL must be verified before scanning")

    scan_count = await db.scans.count_documents({"user_id": str(user["_id"])})
    scan_limit = user.get("scan_limit", 100)
    if scan_count >= scan_limit:
        raise HTTPException(
            status_code=429,
            detail=f"Scan limit reached ({scan_limit}). Contact admin to increase your limit."
        )

    new_scan = {
        "user_id": str(user["_id"]),
        "target_url": target_url,
        "proxy_enabled": user.get("proxy_enabled", False),
        "proxy_url": user.get("proxy_url"),
        "proxy_type": user.get("proxy_type", "http"),
        "status": "pending",
        "steps": [],
        "vulnerabilities": [],
        "total_risk_score": 0.0,
        "progress": 0,
        "current_step": "Queued",
        "created_at": datetime.utcnow(),
    }
    result = await db.scans.insert_one(new_scan)
    scan_id = str(result.inserted_id)

    background_tasks.add_task(
        run_scan,
        scan_id,
        target_url,
        scan.username,
        scan.password,
        user.get("proxy_enabled", False),
        user.get("proxy_url"),
        user.get("proxy_type", "http")
    )

    return {"scan_id": scan_id, "status": "pending"}


@router.get("/scans")
async def get_scans(
    request: Request,
    status: Optional[str] = None,
    risk_level: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    search: Optional[str] = None,
    fields: Optional[str] = None,
):
    payload = await get_current_user(request)
    db = get_database()

    user = await get_authenticated_db_user(request)

    query = {}
    if user.get("role") != "admin":
        query["user_id"] = str(user["_id"])

    if status and status != "all":
        query["status"] = status

    if risk_level and risk_level != "all":
        if risk_level == "critical":
            query["total_risk_score"] = {"$gte": 9.0}
        elif risk_level == "high":
            query["total_risk_score"] = {"$gte": 7.0, "$lt": 9.0}
        elif risk_level == "medium":
            query["total_risk_score"] = {"$gte": 4.0, "$lt": 7.0}
        elif risk_level == "low":
            query["total_risk_score"] = {"$lt": 4.0}

    if date_from or date_to:
        date_query = {}
        if date_from:
            date_query["$gte"] = datetime.fromisoformat(date_from)
        if date_to:
            date_query["$lte"] = datetime.fromisoformat(date_to)
        query["created_at"] = date_query

    if search:
        cleaned_search = search.strip()
        if cleaned_search:
            escaped = re.escape(cleaned_search)
            pattern = f"^{escaped}" if cleaned_search.startswith(("http://", "https://")) else escaped
            query["target_url"] = {"$regex": pattern, "$options": "i"}

    default_fields = [
        "target_url",
        "status",
        "total_risk_score",
        "created_at",
        "progress",
        "current_step",
        "total_vulnerabilities",
        "severity_counts",
    ]
    allowed_fields = set(default_fields)
    requested_fields = default_fields
    if fields:
        parsed = [f.strip() for f in fields.split(",") if f.strip()]
        filtered = [f for f in parsed if f in allowed_fields]
        if filtered:
            requested_fields = filtered

    projection = {"_id": 1}
    for field in requested_fields:
        projection[field] = 1

    scans = []
    async for scan in db.scans.find(query, projection=projection, sort=[("created_at", -1)]):
        scan_item = {"id": str(scan["_id"])}
        for field in requested_fields:
            if field == "created_at":
                created = scan.get("created_at")
                scan_item[field] = created.isoformat() if created else None
            elif field == "target_url":
                scan_item[field] = scan.get("target_url", "")
            elif field == "status":
                scan_item[field] = scan.get("status", "pending")
            elif field == "total_risk_score":
                scan_item[field] = scan.get("total_risk_score", 0)
            elif field == "progress":
                scan_item[field] = scan.get("progress", 0)
            elif field == "current_step":
                scan_item[field] = scan.get("current_step", "")
            elif field == "total_vulnerabilities":
                scan_item[field] = scan.get("total_vulnerabilities", 0)
            elif field == "severity_counts":
                scan_item[field] = scan.get("severity_counts", {})
        scans.append(scan_item)

    return scans


@router.get("/scans/{scan_id}")
async def get_scan(scan_id: str, request: Request):
    payload = await get_current_user(request)
    db = get_database()

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["user_id"] != payload["sub"] and payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    return {
        "id": str(scan["_id"]),
        "target_url": scan["target_url"],
        "status": scan["status"],
        "created_at": scan["created_at"],
        "total_risk_score": scan.get("total_risk_score", 0.0),
        "progress": scan.get("progress", 0),
        "current_step": scan.get("current_step", ""),
        "vulnerabilities": scan.get("vulnerabilities", []),
        "total_vulnerabilities": scan.get("total_vulnerabilities", 0),
        "severity_counts": scan.get("severity_counts", {}),
        "pages_crawled": scan.get("pages_crawled", 0),
        "requests_made": scan.get("requests_made", 0),
        "steps": scan.get("steps", []),
        "completed_at": scan.get("completed_at"),
    }


@router.delete("/scans/{scan_id}")
async def delete_scan(scan_id: str, request: Request):
    payload = await get_current_user(request)
    db = get_database()

    scan = await db.scans.find_one({"_id": ObjectId(scan_id)})
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan["user_id"] != payload["sub"] and payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.scans.delete_one({"_id": ObjectId(scan_id)})
    return {"message": "Scan deleted"}