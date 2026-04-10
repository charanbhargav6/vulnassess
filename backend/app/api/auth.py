from fastapi import APIRouter, HTTPException, Response, Request
from datetime import timedelta, datetime
from app.db.database import get_database
from app.core.security import (
    verify_password, get_password_hash,
    create_access_token, validate_password
)
from app.core.auth_utils import (
    clear_auth_cookie,
    get_authenticated_user,
    revoke_user_sessions,
    set_auth_cookie,
)
from app.core.config import settings
from app.services.rate_limit_service import enforce_rate_limit
from app.schemas.schemas import (
    UserRegister,
    UserLogin,
    Token,
    EmailCheckRequest,
    ForgotPasswordRequest,
    VerifyOtpRequest,
    ResetPasswordWithOtpRequest,
)
from bson import ObjectId
from pydantic import BaseModel

router = APIRouter()

# Track failed login attempts in memory
failed_attempts = {}
BLOCK_THRESHOLD = 5
BLOCK_DURATION_MINUTES = 15


async def normalize_subscription_state(db, user: dict) -> dict:
    expires_at = user.get("subscription_expires_at")
    expired = bool(expires_at and expires_at <= datetime.utcnow())
    if user.get("has_ai_subscription", False) and expired:
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

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def is_blocked(ip: str) -> bool:
    if ip not in failed_attempts:
        return False
    data = failed_attempts[ip]
    if data["count"] >= BLOCK_THRESHOLD:
        block_until = data["blocked_until"]
        if block_until and datetime.utcnow() < block_until:
            return True
        else:
            # Block expired — reset
            failed_attempts.pop(ip, None)
            return False
    return False

def record_failed_attempt(ip: str):
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 0, "blocked_until": None}
    failed_attempts[ip]["count"] += 1
    if failed_attempts[ip]["count"] >= BLOCK_THRESHOLD:
        failed_attempts[ip]["blocked_until"] = (
            datetime.utcnow() + timedelta(minutes=BLOCK_DURATION_MINUTES)
        )

def reset_attempts(ip: str):
    failed_attempts.pop(ip, None)

def get_remaining_attempts(ip: str) -> int:
    if ip not in failed_attempts:
        return BLOCK_THRESHOLD
    return max(0, BLOCK_THRESHOLD - failed_attempts[ip]["count"])

@router.post("/auth/register")
async def register(user: UserRegister, request: Request):
    await enforce_rate_limit(request, "auth_register_ip", limit=10, window_seconds=900)
    ip = get_client_ip(request)

    if is_blocked(ip):
        data = failed_attempts.get(ip, {})
        block_until = data.get("blocked_until")
        minutes_left = 0
        if block_until:
            minutes_left = int((block_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {minutes_left} minutes."
        )

    db = get_database()

    existing = await db.users.find_one({"email": user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")

    if not validate_password(user.password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8+ chars with uppercase, lowercase and number"
        )

    new_user = {
        "email": user.email,
        "password_hash": get_password_hash(user.password),
        "role": "user",
        "created_at": datetime.utcnow(),
        "scan_limit": 100,
        "is_active": True,
        "is_verified": False,
        "has_ai_subscription": False,
        "subscription_tier": None,
        "subscription_status": "inactive",
        "subscription_expires_at": None,
        "proxy_enabled": False,
        "proxy_url": None,
        "proxy_type": "http",
        "token_version": 1,
    }
    result = await db.users.insert_one(new_user)
    user_id = str(result.inserted_id)

    # Send verification email
    from app.services.email_service import create_verification_token, send_verification_email
    token = await create_verification_token(user_id, user.email)
    mail_sent = await send_verification_email(user.email, token)

    return {
        "message": (
            "Account created! Please check your email to verify your account."
            if mail_sent
            else "Account created, but SMTP is not configured. Verification emails are currently disabled."
        ),
        "mail_sent": bool(mail_sent),
        "id": user_id
    }


@router.post("/auth/login")
async def login(user: UserLogin, request: Request, response: Response):
    await enforce_rate_limit(request, "auth_login_ip", limit=25, window_seconds=900)
    ip = get_client_ip(request)

    # Check if IP is blocked
    if is_blocked(ip):
        data = failed_attempts.get(ip, {})
        block_until = data.get("blocked_until")
        minutes_left = 0
        if block_until:
            minutes_left = int((block_until - datetime.utcnow()).total_seconds() / 60) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many failed attempts. Try again in {minutes_left} minutes."
        )

    db = get_database()

    # Find user
    db_user = await db.users.find_one({"email": user.email})
    if not db_user:
        record_failed_attempt(ip)
        remaining = get_remaining_attempts(ip)
        raise HTTPException(
            status_code=401,
            detail=f"Invalid email or password. {remaining} attempts remaining."
        )

    # Check if user is deactivated
    if not db_user.get("is_active", True):
        raise HTTPException(
            status_code=403,
            detail="Your account has been deactivated. Contact admin."
        )
    
    # Check if email is verified
    if not db_user.get("is_verified", False):
        raise HTTPException(
            status_code=403,
            detail="Please verify your email before logging in. Check your inbox."
        )

    # Check password
    if not verify_password(user.password, db_user["password_hash"]):
        record_failed_attempt(ip)
        remaining = get_remaining_attempts(ip)

        # Log failed attempt
        await db.activity_logs.insert_one({
            "action": "failed_login",
            "email": user.email,
            "ip": ip,
            "timestamp": datetime.utcnow()
        })

        raise HTTPException(
            status_code=401,
            detail=f"Invalid email or password. {remaining} attempts remaining."
        )

    # Check scan limit
    scan_count = await db.scans.count_documents({"user_id": str(db_user["_id"])})
    scan_limit = db_user.get("scan_limit", 100)

    # Success — reset failed attempts
    reset_attempts(ip)

    # Log successful login
    await db.activity_logs.insert_one({
        "action": "login",
        "user_id": str(db_user["_id"]),
        "email": user.email,
        "ip": ip,
        "timestamp": datetime.utcnow()
    })

    token_version = int(db_user.get("token_version", 1))
    if "token_version" not in db_user:
        await db.users.update_one({"_id": db_user["_id"]}, {"$set": {"token_version": 1}})

    token = create_access_token(
        data={"sub": str(db_user["_id"]), "role": db_user["role"], "ver": token_version},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    set_auth_cookie(response, token, request)

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": db_user["role"],
        "email": db_user["email"],
        "scan_count": scan_count,
        "scan_limit": scan_limit
    }


@router.post("/auth/check-email")
async def check_email(data: EmailCheckRequest, request: Request):
    await enforce_rate_limit(request, "auth_check_email_ip", limit=40, window_seconds=600)

    db = get_database()
    email = data.email.strip().lower()
    user = await db.users.find_one({"email": email})
    if not user:
        return {"exists": False, "is_verified": False}
    return {
        "exists": True,
        "is_verified": bool(user.get("is_verified", False)),
        "is_active": bool(user.get("is_active", True)),
    }


@router.post("/auth/forgot-password/send-otp")
async def send_forgot_password_otp(data: ForgotPasswordRequest, request: Request):
    db = get_database()
    email = data.email.strip().lower()

    await enforce_rate_limit(request, "forgot_send_otp_ip", limit=6, window_seconds=600)
    await enforce_rate_limit(request, "forgot_send_otp_email", limit=5, window_seconds=600, subject=f"email:{email}")

    user = await db.users.find_one({"email": email})
    if not user:
        return {"message": "If the email is registered, a reset code has been sent."}

    from app.services.email_service import (
        create_password_reset_otp,
        send_password_reset_otp_email,
    )

    otp = await create_password_reset_otp(str(user["_id"]), email)
    await send_password_reset_otp_email(email, otp)
    return {"message": "If the email is registered, a reset code has been sent."}


@router.post("/auth/forgot-password/verify-otp")
async def verify_forgot_password_otp(data: VerifyOtpRequest, request: Request):
    from app.services.email_service import verify_password_reset_otp

    email = data.email.strip().lower()
    otp = (data.otp or "").strip()

    await enforce_rate_limit(request, "forgot_verify_otp_ip", limit=20, window_seconds=600)
    await enforce_rate_limit(request, "forgot_verify_otp_email", limit=15, window_seconds=600, subject=f"email:{email}")

    if not otp or len(otp) != 6 or not otp.isdigit():
        raise HTTPException(status_code=400, detail="OTP must be a 6-digit code")

    is_valid = await verify_password_reset_otp(email, otp)
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    return {"valid": True}


@router.post("/auth/forgot-password/reset")
async def reset_password_with_otp(data: ResetPasswordWithOtpRequest, request: Request):
    db = get_database()
    email = data.email.strip().lower()
    otp = (data.otp or "").strip()

    await enforce_rate_limit(request, "forgot_reset_ip", limit=10, window_seconds=900)
    await enforce_rate_limit(request, "forgot_reset_email", limit=8, window_seconds=900, subject=f"email:{email}")

    if not validate_password(data.new_password):
        raise HTTPException(
            status_code=400,
            detail="Password must be 8+ chars with uppercase, lowercase and number",
        )
    if not otp or len(otp) != 6 or not otp.isdigit():
        raise HTTPException(status_code=400, detail="OTP must be a 6-digit code")

    user = await db.users.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    from app.services.email_service import consume_password_reset_otp

    consumed = await consume_password_reset_otp(email, otp)
    if not consumed:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP")

    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {
                "password_hash": get_password_hash(data.new_password),
                "is_active": True,
                "is_verified": True,
            },
            "$inc": {"token_version": 1},
        },
    )

    return {"message": "Password reset successful. Please login with your new password."}


@router.get("/auth/me")
async def get_me(request: Request):
    db = get_database()
    payload = await get_authenticated_user(request)

    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user = await normalize_subscription_state(db, user)

    scan_count = await db.scans.count_documents({"user_id": str(user["_id"])})

    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "role": user["role"],
        "scan_count": scan_count,
        "scan_limit": user.get("scan_limit", 100),
        "is_active": user.get("is_active", True),
        "has_ai_subscription": user.get("has_ai_subscription", False),
        "subscription_status": user.get("subscription_status", "inactive"),
        "subscription_expires_at": user.get("subscription_expires_at"),
    }


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    db = get_database()
    user_payload = None
    try:
        user_payload = await get_authenticated_user(request, require_active=False)
    except HTTPException:
        user_payload = None

    if user_payload:
        await revoke_user_sessions(user_payload["sub"])
        await db.activity_logs.insert_one({
            "action": "logout",
            "user_id": user_payload["sub"],
            "timestamp": datetime.utcnow()
        })

    clear_auth_cookie(response, request)
    return {"message": "Logged out successfully"}

@router.get("/auth/verify")
async def verify_email(token: str):
    from app.services.email_service import verify_token
    result = await verify_token(token)
    if result["success"]:
        return {"message": f"Email verified! You can now login.", "success": True}
    raise HTTPException(status_code=400, detail=result["message"])


@router.post("/auth/resend-verification")
async def resend_verification_email(data: EmailCheckRequest, request: Request):
    db = get_database()
    email = data.email.strip().lower()

    await enforce_rate_limit(request, "resend_verification_ip", limit=6, window_seconds=900)
    await enforce_rate_limit(request, "resend_verification_email", limit=5, window_seconds=900, subject=f"email:{email}")

    user = await db.users.find_one({"email": email})
    if not user:
        return {
            "message": "If the email is registered, verification instructions have been sent.",
            "mail_sent": False,
        }
    if user.get("is_verified", False):
        return {
            "message": "If the email is registered, verification instructions have been sent.",
            "mail_sent": False,
        }

    from app.services.email_service import create_verification_token, send_verification_email

    token = await create_verification_token(str(user["_id"]), email)
    mail_sent = await send_verification_email(email, token)
    return {
        "message": "If the email is registered, verification instructions have been sent.",
        "mail_sent": bool(mail_sent),
    }

class VerifyPasswordRequest(BaseModel):
    password: str

@router.post("/auth/verify-password")
async def verify_password_endpoint(data: VerifyPasswordRequest, request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    return {"valid": True}


@router.delete("/auth/delete-account")
async def delete_account(data: VerifyPasswordRequest, request: Request):
    payload = await get_authenticated_user(request)

    db = get_database()
    user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not verify_password(data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    user_id = str(user["_id"])
    # Delete all user scans
    await db.scans.delete_many({"user_id": user_id})
    # Delete all user schedules
    await db.schedules.delete_many({"user_id": user_id})
    # Delete user
    await db.users.delete_one({"_id": ObjectId(payload["sub"])})

    return {"message": "Account deleted successfully"}