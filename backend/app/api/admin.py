from fastapi import APIRouter, HTTPException, Request
from app.db.database import get_database
from app.core.auth_utils import get_authenticated_user, get_authenticated_db_user, require_admin_user
from app.schemas.schemas import RoleUpdate, ModuleUpdate, PaymentStatusUpdate
from app.core.config import settings
from bson import ObjectId
from datetime import datetime, timedelta
import ipaddress
from urllib.parse import urlparse
import httpx

router = APIRouter()
modules_router = APIRouter()

ADMIN_STATS_CACHE_TTL_SECONDS = 30
_admin_stats_cache = {
    "expires_at": None,
    "value": None,
}


def _invalidate_admin_stats_cache():
    _admin_stats_cache["expires_at"] = None
    _admin_stats_cache["value"] = None

async def get_admin_user(request: Request, db):
    admin = await require_admin_user(request)
    db_user = await get_authenticated_db_user(request)
    if not db_user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Admin account is deactivated")
    return admin


async def _apply_verified_subscription(db, user_id: str, plan: str):
    now = datetime.utcnow()
    duration_days = settings.SUBSCRIPTION_YEAR_DAYS if plan == "yearly" else settings.SUBSCRIPTION_MONTH_DAYS
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$set": {
                "has_ai_subscription": True,
                "subscription_tier": plan,
                "subscription_status": "active",
                "subscription_expires_at": now + timedelta(days=duration_days),
            }
        },
    )


def _is_safe_receipt_url(receipt_url: str) -> bool:
    parsed = urlparse(receipt_url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False

    if parsed.username or parsed.password:
        return False

    host = parsed.hostname.lower().strip()
    blocked_hosts = {
        "localhost",
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "metadata.google.internal",
    }
    if host in blocked_hosts or host.endswith(".local"):
        return False

    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
            return False
    except ValueError:
        pass

    return True


async def _auto_verify_payment(payment: dict):
    tx_id = (payment.get("transaction_id") or "").strip()
    if len(tx_id) < 8:
        return False, "Transaction id must be at least 8 characters"
    if float(payment.get("amount") or 0) <= 0:
        return False, "Invalid amount"

    receipt_url = (payment.get("receipt_url") or "").strip()
    if not receipt_url:
        return False, "Receipt URL is required for auto verification"
    if not _is_safe_receipt_url(receipt_url):
        return False, "Receipt URL must be a valid public HTTPS URL"

    try:
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=True) as client:
            resp = await client.get(receipt_url)
        if 200 <= resp.status_code < 400:
            return True, "Receipt URL verified"
        return False, f"Receipt URL check failed ({resp.status_code})"
    except Exception:
        return False, "Receipt URL unreachable"

# --- User Management ---
@router.get("/admin/users")
async def get_all_users(request: Request):
    db = get_database()
    await get_admin_user(request, db)
    pipeline = [
        {
            "$lookup": {
                "from": "scans",
                "let": {"uid": {"$toString": "$_id"}},
                "pipeline": [
                    {"$match": {"$expr": {"$eq": ["$user_id", "$$uid"]}}},
                    {"$count": "count"},
                ],
                "as": "scan_info",
            }
        },
        {
            "$project": {
                "id": {"$toString": "$_id"},
                "email": 1,
                "role": 1,
                "created_at": 1,
                "scan_count": {
                    "$ifNull": [{"$arrayElemAt": ["$scan_info.count", 0]}, 0]
                },
                "scan_limit": {"$ifNull": ["$scan_limit", 100]},
                "is_active": {"$ifNull": ["$is_active", True]},
                "has_ai_subscription": {"$ifNull": ["$has_ai_subscription", False]},
                "subscription_status": {"$ifNull": ["$subscription_status", "inactive"]},
                "subscription_tier": {"$ifNull": ["$subscription_tier", None]},
            }
        },
    ]
    return await db.users.aggregate(pipeline).to_list(length=None)


@router.get("/admin/payments")
async def get_all_payments(request: Request):
    db = get_database()
    await get_admin_user(request, db)
    payments = []
    async for p in db.subscription_payments.find(sort=[("created_at", -1)]):
        payments.append({
            "id": str(p["_id"]),
            "user_id": p.get("user_id"),
            "plan": p.get("plan"),
            "amount": p.get("amount"),
            "currency": p.get("currency", "USD"),
            "amount_usd": p.get("amount_usd"),
            "status": p.get("status", "pending"),
            "transaction_id": p.get("transaction_id"),
            "receipt_url": p.get("receipt_url"),
            "payment_method": p.get("payment_method", "upi"),
            "payment_meta": p.get("payment_meta", {}),
            "created_at": p.get("created_at"),
            "verified_at": p.get("verified_at"),
            "verified_by": p.get("verified_by"),
            "auto_verify_note": p.get("auto_verify_note"),
        })
    return payments


@router.post("/admin/payments/{payment_id}/auto-verify")
async def auto_verify_payment(payment_id: str, request: Request):
    db = get_database()
    admin = await get_admin_user(request, db)
    payment = await db.subscription_payments.find_one({"_id": ObjectId(payment_id)})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    verified, note = await _auto_verify_payment(payment)
    update = {
        "auto_verify_note": note,
        "verified_by": admin["sub"] if verified else None,
        "verified_at": datetime.utcnow() if verified else None,
        "status": "verified" if verified else "pending",
    }
    await db.subscription_payments.update_one({"_id": ObjectId(payment_id)}, {"$set": update})
    if verified:
        await _apply_verified_subscription(db, payment["user_id"], payment.get("plan", "monthly"))

    _invalidate_admin_stats_cache()

    return {
        "status": update["status"],
        "auto_verify_note": note,
    }


@router.put("/admin/payments/{payment_id}/status")
async def update_payment_status(payment_id: str, data: PaymentStatusUpdate, request: Request):
    db = get_database()
    admin = await get_admin_user(request, db)
    payment = await db.subscription_payments.find_one({"_id": ObjectId(payment_id)})
    if not payment:
        raise HTTPException(status_code=404, detail="Payment not found")

    status = (data.status or "").lower().strip()
    if status not in {"pending", "verified", "rejected"}:
        raise HTTPException(status_code=400, detail="Status must be pending, verified, or rejected")

    await db.subscription_payments.update_one(
        {"_id": ObjectId(payment_id)},
        {
            "$set": {
                "status": status,
                "verified_at": datetime.utcnow() if status == "verified" else None,
                "verified_by": admin["sub"] if status == "verified" else admin["sub"],
                "admin_note": data.admin_note,
            }
        }
    )

    if status == "verified":
        await _apply_verified_subscription(db, payment["user_id"], payment.get("plan", "monthly"))
    elif status == "rejected":
        await db.users.update_one(
            {"_id": ObjectId(payment["user_id"])},
            {
                "$set": {
                    "has_ai_subscription": False,
                    "subscription_tier": None,
                    "subscription_status": "inactive",
                    "subscription_expires_at": None,
                }
            }
        )

    _invalidate_admin_stats_cache()

    return {"message": f"Payment marked as {status}"}

@router.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, request: Request):
    db = get_database()
    admin = await get_admin_user(request, db)
    result = await db.users.delete_one({"_id": ObjectId(user_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    # Log activity
    await db.activity_logs.insert_one({
        "action": "delete_user",
        "target_id": user_id,
        "performed_by": admin["sub"],
        "timestamp": datetime.utcnow()
    })
    _invalidate_admin_stats_cache()
    return {"message": "User deleted"}

@router.put("/admin/users/{user_id}/role")
async def update_role(user_id: str, role_update: RoleUpdate, request: Request):
    db = get_database()
    admin = await get_admin_user(request, db)
    if role_update.role not in ["user", "admin"]:
        raise HTTPException(status_code=400, detail="Role must be user or admin")
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"role": role_update.role}}
    )
    await db.activity_logs.insert_one({
        "action": "update_role",
        "target_id": user_id,
        "new_role": role_update.role,
        "performed_by": admin["sub"],
        "timestamp": datetime.utcnow()
    })
    _invalidate_admin_stats_cache()
    return {"message": "Role updated"}

@router.put("/admin/users/{user_id}/limit")
async def update_scan_limit(user_id: str, request: Request):
    db = get_database()
    await get_admin_user(request, db)
    body = await request.json()
    limit = body.get("scan_limit", 100)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"scan_limit": limit}}
    )
    _invalidate_admin_stats_cache()
    return {"message": f"Scan limit updated to {limit}"}

@router.put("/admin/users/{user_id}/toggle")
async def toggle_user(user_id: str, request: Request):
    db = get_database()
    await get_admin_user(request, db)
    user = await db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    new_status = not user.get("is_active", True)
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {"$set": {"is_active": new_status}}
    )
    _invalidate_admin_stats_cache()
    return {"message": f"User {'activated' if new_status else 'deactivated'}"}

@router.get("/admin/scans")
async def get_all_scans(request: Request):
    db = get_database()
    await get_admin_user(request, db)
    scans = []
    projection = {
        "user_id": 1,
        "target_url": 1,
        "status": 1,
        "created_at": 1,
        "total_risk_score": 1,
    }
    async for scan in db.scans.find({}, projection=projection, sort=[("created_at", -1)]):
        scans.append({
            "id": str(scan["_id"]),
            "user_id": scan["user_id"],
            "target_url": scan["target_url"],
            "status": scan["status"],
            "created_at": scan["created_at"],
            "total_risk_score": scan.get("total_risk_score", 0.0)
        })
    return scans

@router.delete("/admin/scans/{scan_id}")
async def admin_delete_scan(scan_id: str, request: Request):
    db = get_database()
    await get_admin_user(request, db)
    result = await db.scans.delete_one({"_id": ObjectId(scan_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Scan not found")
    _invalidate_admin_stats_cache()
    return {"message": "Scan deleted"}


@router.get("/admin/overview")
async def get_admin_overview(request: Request):
    db = get_database()
    await get_admin_user(request, db)

    users_pipeline = [
        {
            "$lookup": {
                "from": "scans",
                "let": {"uid": {"$toString": "$_id"}},
                "pipeline": [
                    {"$match": {"$expr": {"$eq": ["$user_id", "$$uid"]}}},
                    {"$count": "count"},
                ],
                "as": "scan_info",
            }
        },
        {
            "$project": {
                "id": {"$toString": "$_id"},
                "email": 1,
                "role": 1,
                "created_at": 1,
                "scan_count": {
                    "$ifNull": [{"$arrayElemAt": ["$scan_info.count", 0]}, 0]
                },
                "scan_limit": {"$ifNull": ["$scan_limit", 100]},
                "is_active": {"$ifNull": ["$is_active", True]},
                "has_ai_subscription": {"$ifNull": ["$has_ai_subscription", False]},
                "subscription_status": {"$ifNull": ["$subscription_status", "inactive"]},
                "subscription_tier": {"$ifNull": ["$subscription_tier", None]},
            }
        },
    ]
    users = await db.users.aggregate(users_pipeline).to_list(length=None)

    modules = []
    async for module in db.modules.find(sort=[("order", 1)]):
        modules.append({
            "name": module["name"],
            "module_key": module["module_key"],
            "enabled": module["enabled"],
            "order": module["order"],
            "fixed": module.get("fixed", False),
        })

    scans = []
    scan_projection = {
        "user_id": 1,
        "target_url": 1,
        "status": 1,
        "created_at": 1,
        "total_risk_score": 1,
    }
    async for scan in db.scans.find({}, projection=scan_projection, sort=[("created_at", -1)]):
        scans.append({
            "id": str(scan["_id"]),
            "user_id": scan.get("user_id"),
            "target_url": scan.get("target_url"),
            "status": scan.get("status"),
            "created_at": scan.get("created_at"),
            "total_risk_score": scan.get("total_risk_score", 0.0),
        })

    stats = await get_stats(request)

    logs = []
    log_projection = {
        "action": 1,
        "target_id": 1,
        "performed_by": 1,
        "timestamp": 1,
        "details": 1,
    }
    async for log in db.activity_logs.find({}, projection=log_projection, sort=[("timestamp", -1)], limit=50):
        logs.append({
            "action": log.get("action"),
            "target_id": log.get("target_id"),
            "performed_by": log.get("performed_by"),
            "timestamp": log.get("timestamp"),
            "details": log.get("details", {}),
        })

    payments = []
    async for p in db.subscription_payments.find(sort=[("created_at", -1)]):
        payments.append({
            "id": str(p["_id"]),
            "user_id": p.get("user_id"),
            "plan": p.get("plan"),
            "amount": p.get("amount"),
            "currency": p.get("currency", "USD"),
            "amount_usd": p.get("amount_usd"),
            "status": p.get("status", "pending"),
            "transaction_id": p.get("transaction_id"),
            "receipt_url": p.get("receipt_url"),
            "payment_method": p.get("payment_method", "upi"),
            "payment_meta": p.get("payment_meta", {}),
            "created_at": p.get("created_at"),
            "verified_at": p.get("verified_at"),
            "verified_by": p.get("verified_by"),
            "auto_verify_note": p.get("auto_verify_note"),
        })

    return {
        "users": users,
        "modules": modules,
        "scans": scans,
        "stats": stats,
        "logs": logs,
        "payments": payments,
    }

@router.get("/admin/stats")
async def get_stats(request: Request):
    db = get_database()
    await get_admin_user(request, db)

    now = datetime.utcnow()
    expires_at = _admin_stats_cache.get("expires_at")
    cached_value = _admin_stats_cache.get("value")
    if cached_value and expires_at and now < expires_at:
        return cached_value

    total_users = await db.users.count_documents({})
    total_scans = await db.scans.count_documents({})
    completed_scans = await db.scans.count_documents({"status": "completed"})
    failed_scans = await db.scans.count_documents({"status": "failed"})

    # High risk scans
    high_risk = await db.scans.count_documents({"total_risk_score": {"$gte": 7}})

    # Recent activity - last 7 days
    from datetime import timedelta
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_scans = await db.scans.count_documents({"created_at": {"$gte": week_ago}})
    recent_users = await db.users.count_documents({"created_at": {"$gte": week_ago}})

    # Scans per day last 7 days
    scans_per_day = []
    for i in range(6, -1, -1):
        day = datetime.utcnow() - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day.replace(hour=23, minute=59, second=59)
        count = await db.scans.count_documents({
            "created_at": {"$gte": day_start, "$lte": day_end}
        })
        scans_per_day.append({
            "date": day.strftime("%m/%d"),
            "count": count
        })

    response = {
        "total_users": total_users,
        "total_scans": total_scans,
        "completed_scans": completed_scans,
        "failed_scans": failed_scans,
        "high_risk_scans": high_risk,
        "recent_scans": recent_scans,
        "recent_users": recent_users,
        "scans_per_day": scans_per_day
    }
    _admin_stats_cache["value"] = response
    _admin_stats_cache["expires_at"] = now + timedelta(seconds=ADMIN_STATS_CACHE_TTL_SECONDS)
    return response

@router.get("/admin/logs")
async def get_activity_logs(request: Request):
    db = get_database()
    await get_admin_user(request, db)
    logs = []
    projection = {
        "action": 1,
        "target_id": 1,
        "performed_by": 1,
        "timestamp": 1,
        "details": 1,
    }
    async for log in db.activity_logs.find({}, projection=projection, sort=[("timestamp", -1)], limit=50):
        logs.append({
            "action": log["action"],
            "target_id": log.get("target_id"),
            "performed_by": log.get("performed_by"),
            "timestamp": log["timestamp"],
            "details": log.get("details", {})
        })
    return logs

# --- Module Management ---
@modules_router.get("/modules")
async def get_modules(request: Request):
    await get_authenticated_user(request)
    db = get_database()
    modules = []
    async for module in db.modules.find(sort=[("order", 1)]):
        modules.append({
            "name": module["name"],
            "module_key": module["module_key"],
            "enabled": module["enabled"],
            "order": module["order"],
            "fixed": module.get("fixed", False)
        })
    return modules

@modules_router.put("/modules/{module_key}")
async def update_module(module_key: str, update: ModuleUpdate, request: Request):
    db = get_database()
    await get_admin_user(request, db)
    module = await db.modules.find_one({"module_key": module_key})
    if module and module.get("fixed"):
        raise HTTPException(status_code=400, detail="This module cannot be disabled")
    await db.modules.update_one(
        {"module_key": module_key},
        {"$set": {"enabled": update.enabled}}
    )
    return {"message": "Module updated"}

@modules_router.put("/modules/{module_key}/order")
async def update_module_order(module_key: str, request: Request):
    db = get_database()
    await get_admin_user(request, db)
    body = await request.json()
    new_order = body.get("order")
    await db.modules.update_one(
        {"module_key": module_key},
        {"$set": {"order": new_order}}
    )
    return {"message": "Order updated"}

@modules_router.post("/modules/restore-defaults")
async def restore_default_order(request: Request):
    db = get_database()
    await get_admin_user(request, db)
    defaults = [
        ("auth_module", 1), ("recon", 2), ("sqli", 3),
        ("nosqli", 4), ("xss", 5), ("csrf", 6),
        ("path_traversal", 7), ("cmd_injection", 8),
        ("broken_access", 9), ("idor", 10),
        ("mass_assignment", 11), ("sec_headers", 12),
        ("rate_limit_check", 13), ("ssl_tls", 14), ("port_scan", 15)
    ]
    for key, order in defaults:
        await db.modules.update_one(
            {"module_key": key},
            {"$set": {"order": order, "enabled": True}}
        )
    return {"message": "Defaults restored"}