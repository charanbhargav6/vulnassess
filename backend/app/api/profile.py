from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import ipaddress
import re
from urllib.parse import urlparse
from bson import ObjectId
from app.db.database import get_database
from app.core.security import get_password_hash, verify_password
from app.core.auth_utils import get_authenticated_user, revoke_user_sessions
from app.core.config import settings
from app.services.url_security import validate_proxy_url
from app.schemas.schemas import ProxySettingsUpdate, SubscriptionRequestCreate

router = APIRouter()

PLAN_PRICES = {
    "monthly": 5.0,
    "yearly": 50.0,
}

CURRENCY_RATES = {
    "USD": 1.0,
    "INR": 83.0,
}

VALID_PAYMENT_METHODS = {"upi", "debit_card", "crypto"}


def _normalize_currency(currency: Optional[str]) -> str:
    value = (currency or "USD").strip().upper()
    if value not in CURRENCY_RATES:
        raise HTTPException(status_code=400, detail="Currency must be USD or INR")
    return value


def _expected_plan_amount(plan: str, currency: str) -> float:
    usd_amount = PLAN_PRICES[plan]
    return round(usd_amount * CURRENCY_RATES[currency], 2)

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class UpdateProfile(BaseModel):
    full_name: Optional[str] = None


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
        # Hostname is not an IP literal.
        pass

    return True


async def _normalize_subscription_state(db, user: dict) -> dict:
    """Downgrade expired subscriptions automatically when user data is read."""
    expires_at = user.get("subscription_expires_at")
    is_active_subscription = bool(user.get("has_ai_subscription", False))
    expired = bool(expires_at and expires_at <= datetime.utcnow())

    if is_active_subscription and expired:
        await db.users.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "has_ai_subscription": False,
                    "subscription_tier": None,
                    "subscription_status": "inactive",
                    "subscription_expires_at": None,
                }
            },
        )
        user["has_ai_subscription"] = False
        user["subscription_tier"] = None
        user["subscription_status"] = "inactive"
        user["subscription_expires_at"] = None

    return user


def _extract_payment_meta(data: SubscriptionRequestCreate) -> dict:
    meta = {}
    method = (data.payment_method or "upi").strip().lower()

    if method == "upi" and data.upi_id:
        meta["upi_id"] = data.upi_id
    elif method == "debit_card" and data.card_last4:
        meta["card_last4"] = data.card_last4
    elif method == "crypto":
        if data.crypto_network:
            meta["crypto_network"] = data.crypto_network
        if data.crypto_wallet:
            meta["crypto_wallet"] = data.crypto_wallet

    return meta


def _validate_payment_method_fields(data: SubscriptionRequestCreate, currency: str) -> None:
    method = (data.payment_method or "upi").strip().lower()
    if method not in VALID_PAYMENT_METHODS:
        raise HTTPException(status_code=400, detail="Unsupported payment method")

    if method == "upi" and currency != "INR":
        raise HTTPException(status_code=400, detail="UPI payments are supported only for INR")

    if method == "upi" and data.upi_id:
        if not re.match(r"^[a-z0-9._-]{2,}@[a-z]{2,}$", data.upi_id):
            raise HTTPException(status_code=400, detail="UPI ID format is invalid")

    if method == "debit_card":
        if not data.card_last4 or not re.match(r"^\d{4}$", data.card_last4):
            raise HTTPException(status_code=400, detail="Debit card requires valid last 4 digits")

    if method == "crypto":
        if not data.crypto_network:
            raise HTTPException(status_code=400, detail="Crypto network is required")
        if not data.crypto_wallet or len(data.crypto_wallet.strip()) < 8:
            raise HTTPException(status_code=400, detail="Crypto wallet address is invalid")

@router.get("/profile")
async def get_profile(request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user = await _normalize_subscription_state(db, user)

    # Get scan stats
    total_scans = await db.scans.count_documents({"user_id": str(user["_id"])})
    completed_scans = await db.scans.count_documents({
        "user_id": str(user["_id"]),
        "status": "completed"
    })
    high_risk_scans = await db.scans.count_documents({
        "user_id": str(user["_id"]),
        "total_risk_score": {"$gte": 7}
    })

    # Get last scan
    last_scan = await db.scans.find_one(
        {"user_id": str(user["_id"])},
        sort=[("created_at", -1)]
    )

    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "full_name": user.get("full_name", ""),
        "role": user.get("role", "user"),
        "created_at": user.get("created_at", datetime.utcnow()).isoformat(),
        "is_verified": user.get("is_verified", False),
        "scan_limit": user.get("scan_limit", 100),
        "proxy_settings": {
            "proxy_enabled": user.get("proxy_enabled", False),
            "proxy_url": user.get("proxy_url"),
            "proxy_type": user.get("proxy_type", "http"),
        },
        "subscription": {
            "has_ai_subscription": user.get("has_ai_subscription", False),
            "subscription_tier": user.get("subscription_tier"),
            "subscription_status": user.get("subscription_status", "inactive"),
            "subscription_expires_at": user.get("subscription_expires_at"),
        },
        "stats": {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "high_risk_scans": high_risk_scans,
            "last_scan": last_scan["created_at"].isoformat() if last_scan else None,
            "last_scan_target": last_scan.get("target_url", "") if last_scan else ""
        }
    }


@router.put("/profile/proxy")
async def update_proxy_settings(data: ProxySettingsUpdate, request: Request):
    payload = await get_authenticated_user(request)

    if data.proxy_enabled and not (data.proxy_url or "").strip():
        raise HTTPException(status_code=400, detail="Proxy URL is required when proxy is enabled")

    sanitized_proxy_url = None
    if data.proxy_enabled:
        sanitized_proxy_url = validate_proxy_url(data.proxy_url or "", data.proxy_type or "http")

    db = get_database()
    await db.users.update_one(
        {"_id": ObjectId(payload["sub"])} ,
        {
            "$set": {
                "proxy_enabled": data.proxy_enabled,
                "proxy_url": sanitized_proxy_url,
                "proxy_type": data.proxy_type or "http",
            }
        }
    )
    return {"message": "Proxy settings updated"}


@router.get("/profile/subscription")
async def get_subscription_status(request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user = await _normalize_subscription_state(db, user)

    payments = []
    async for payment in db.subscription_payments.find({"user_id": payload["sub"]}, sort=[("created_at", -1)], limit=20):
        payments.append({
            "id": str(payment["_id"]),
            "plan": payment.get("plan"),
            "amount": payment.get("amount"),
            "currency": payment.get("currency", "USD"),
            "amount_usd": payment.get("amount_usd"),
            "status": payment.get("status", "pending"),
            "created_at": payment.get("created_at"),
            "verified_at": payment.get("verified_at"),
            "transaction_id": payment.get("transaction_id"),
            "payment_method": payment.get("payment_method", "upi"),
            "payment_meta": payment.get("payment_meta", {}),
            "auto_verify_note": payment.get("auto_verify_note"),
        })

    return {
        "has_ai_subscription": user.get("has_ai_subscription", False),
        "subscription_tier": user.get("subscription_tier"),
        "subscription_status": user.get("subscription_status", "inactive"),
        "subscription_expires_at": user.get("subscription_expires_at"),
        "payments": payments,
    }


@router.post("/profile/subscription/request")
async def request_subscription(data: SubscriptionRequestCreate, request: Request):
    payload = await get_authenticated_user(request)

    plan = (data.plan or "monthly").lower().strip()
    if plan not in PLAN_PRICES:
        raise HTTPException(status_code=400, detail="Plan must be monthly or yearly")

    currency = _normalize_currency(data.currency)
    expected_amount = _expected_plan_amount(plan, currency)
    tolerance = 0.01 if currency == "USD" else 1.0
    if abs(float(data.amount or 0) - expected_amount) > tolerance:
        raise HTTPException(
            status_code=400,
            detail=f"Amount must match selected plan price ({expected_amount:.2f} {currency})",
        )

    tx_id = (data.transaction_id or "").strip()
    if len(tx_id) < 8:
        raise HTTPException(status_code=400, detail="Transaction ID must be at least 8 characters")

    receipt_url = (data.receipt_url or "").strip()
    if not receipt_url:
        raise HTTPException(status_code=400, detail="Receipt URL is required for payment submission")

    if not _is_safe_receipt_url(receipt_url):
        raise HTTPException(status_code=400, detail="Receipt URL must be a valid public HTTPS URL")

    _validate_payment_method_fields(data, currency)
    payment_method = (data.payment_method or "upi").strip().lower()
    payment_meta = _extract_payment_meta(data)

    db = get_database()
    payment = {
        "user_id": payload["sub"],
        "plan": plan,
        "amount": expected_amount,
        "currency": currency,
        "amount_usd": PLAN_PRICES[plan],
        "fx_rate": CURRENCY_RATES[currency],
        "transaction_id": tx_id,
        "receipt_url": receipt_url,
        "payment_method": payment_method,
        "payment_meta": payment_meta,
        "status": "pending",
        "created_at": datetime.utcnow(),
        "verified_at": None,
        "verified_by": None,
        "auto_verify_note": "Pending admin verification",
    }

    result = await db.subscription_payments.insert_one(payment)
    payment_id = str(result.inserted_id)

    return {
        "id": payment_id,
        "status": payment["status"],
        "message": "Payment submitted for admin review",
        "auto_verify_note": payment["auto_verify_note"],
    }

@router.put("/profile")
async def update_profile(data: UpdateProfile, request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    await db.users.update_one(
        {"_id": ObjectId(payload["sub"])},
        {"$set": {"full_name": data.full_name}}
    )
    return {"message": "Profile updated"}

@router.put("/profile/change-password")
async def change_password(data: ChangePassword, request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(data.current_password, user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    if len(data.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")

    await db.users.update_one(
        {"_id": ObjectId(payload["sub"])},
        {"$set": {"password_hash": get_password_hash(data.new_password)}}
    )
    await revoke_user_sessions(payload["sub"])
    return {"message": "Password changed successfully"}