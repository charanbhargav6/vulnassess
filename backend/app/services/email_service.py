import secrets
import logging
import hashlib
from datetime import datetime, timedelta
from app.db.database import get_database
from app.core.config import settings

logger = logging.getLogger(__name__)

async def create_verification_token(user_id: str, email: str) -> str:
    db = get_database()
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=24)

    await db.verification_tokens.insert_one({
        "user_id": user_id,
        "email": email,
        "token": token,
        "expires_at": expires_at,
        "used": False
    })
    return token

async def send_verification_email(email: str, token: str):
    verify_url = f"{settings.FRONTEND_URL}/verify?token={token}"

    # Try to send real email if configured
    if settings.MAIL_USERNAME and settings.MAIL_PASSWORD:
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Verify your VulnAssess account'
            msg['From'] = settings.MAIL_FROM or settings.MAIL_USERNAME
            msg['To'] = email

            html = f"""
            <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1D6FEB; padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">VulnAssess</h1>
                <p style="color: rgba(255,255,255,0.8);">Web Vulnerability Scanner</p>
            </div>
            <div style="padding: 30px; background: #f9fafb;">
                <h2 style="color: #1F2937;">Verify your email address</h2>
                <p style="color: #6B7280;">Click the button below to verify your account:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verify_url}"
                       style="background: #1D6FEB; color: white; padding: 14px 32px;
                              border-radius: 8px; text-decoration: none; font-weight: bold;">
                        Verify Email
                    </a>
                </div>
                <p style="color: #9CA3AF; font-size: 12px;">
                    This link expires in 24 hours.<br>
                    If you didn't register, ignore this email.
                </p>
                <p style="color: #9CA3AF; font-size: 11px; word-break: break-all;">
                    Or copy this link: {verify_url}
                </p>
            </div>
            </body></html>
            """

            msg.attach(MIMEText(html, 'html'))

            with smtplib.SMTP(settings.MAIL_SERVER, settings.MAIL_PORT) as server:
                server.starttls()
                server.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)
                server.sendmail(
                    settings.MAIL_FROM or settings.MAIL_USERNAME,
                    email,
                    msg.as_string()
                )
            logger.info(f"Verification email sent to {email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email: {e}")

    # Fallback — keep dev output non-sensitive.
    logger.info("[DEV MODE] Verification email not sent for %s because SMTP is not configured", email)
    print(f"\n{'='*60}")
    print(f"[DEV] Email verification queued for: {email}")
    print("[DEV] SMTP is not configured, so no verification link was sent.")
    print(f"{'='*60}\n")
    return False

async def verify_token(token: str) -> dict:
    db = get_database()
    record = await db.verification_tokens.find_one({
        "token": token,
        "used": False
    })

    if not record:
        return {"success": False, "message": "Invalid or expired token"}

    if datetime.utcnow() > record["expires_at"]:
        return {"success": False, "message": "Token has expired. Please register again."}

    # Mark token as used
    await db.verification_tokens.update_one(
        {"token": token},
        {"$set": {"used": True}}
    )

    # Mark user as verified
    from bson import ObjectId
    await db.users.update_one(
        {"_id": ObjectId(record["user_id"])},
        {"$set": {"is_verified": True}}
    )

    return {"success": True, "email": record["email"]}


def _hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


async def create_password_reset_otp(user_id: str, email: str) -> str:
    db = get_database()
    otp = f"{secrets.randbelow(1000000):06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=10)

    await db.password_reset_otps.update_many(
        {"email": email, "used": False},
        {"$set": {"used": True}},
    )
    await db.password_reset_otps.insert_one(
        {
            "user_id": user_id,
            "email": email,
            "otp_hash": _hash_otp(otp),
            "expires_at": expires_at,
            "used": False,
            "attempts": 0,
            "created_at": datetime.utcnow(),
        }
    )
    return otp


async def send_password_reset_otp_email(email: str, otp: str):
    if settings.MAIL_USERNAME and settings.MAIL_PASSWORD:
        try:
            import smtplib
            from email.mime.multipart import MIMEMultipart
            from email.mime.text import MIMEText

            msg = MIMEMultipart("alternative")
            msg["Subject"] = "VulnAssess password reset OTP"
            msg["From"] = settings.MAIL_FROM or settings.MAIL_USERNAME
            msg["To"] = email

            html = f"""
            <html><body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: #1D6FEB; padding: 30px; text-align: center;">
                <h1 style="color: white; margin: 0;">VulnAssess</h1>
                <p style="color: rgba(255,255,255,0.8);">Password reset request</p>
            </div>
            <div style="padding: 30px; background: #f9fafb;">
                <h2 style="color: #1F2937;">Use this OTP to reset your password</h2>
                <p style="color: #6B7280;">Enter this code in the app to continue:</p>
                <div style="font-size: 30px; letter-spacing: 6px; font-weight: bold; color: #1D6FEB; margin: 20px 0;">
                    {otp}
                </div>
                <p style="color: #9CA3AF; font-size: 12px;">This OTP expires in 10 minutes.</p>
                <p style="color: #9CA3AF; font-size: 12px;">If you did not request a password reset, you can ignore this email.</p>
            </div>
            </body></html>
            """

            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(settings.MAIL_SERVER, settings.MAIL_PORT) as server:
                server.starttls()
                server.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)
                server.sendmail(
                    settings.MAIL_FROM or settings.MAIL_USERNAME,
                    email,
                    msg.as_string(),
                )

            logger.info(f"Password reset OTP sent to {email}")
            return True
        except Exception as e:
            logger.error(f"Failed to send password reset OTP email: {e}")

    logger.info("[DEV MODE] Password reset OTP not sent for %s because SMTP is not configured", email)
    print(f"\n{'='*60}")
    print(f"[DEV] Password reset OTP queued for: {email}")
    print("[DEV] SMTP is not configured, so no reset code was sent.")
    print(f"{'='*60}\n")
    return False


async def verify_password_reset_otp(email: str, otp: str) -> bool:
    db = get_database()
    record = await db.password_reset_otps.find_one(
        {"email": email, "used": False},
        sort=[("created_at", -1)],
    )
    if not record:
        return False
    if datetime.utcnow() > record["expires_at"]:
        return False
    if record.get("attempts", 0) >= 5:
        return False

    if _hash_otp(otp) != record.get("otp_hash"):
        await db.password_reset_otps.update_one(
            {"_id": record["_id"]},
            {"$inc": {"attempts": 1}},
        )
        return False

    return True


async def consume_password_reset_otp(email: str, otp: str) -> bool:
    db = get_database()
    record = await db.password_reset_otps.find_one(
        {"email": email, "used": False},
        sort=[("created_at", -1)],
    )
    if not record:
        return False
    if datetime.utcnow() > record["expires_at"]:
        return False
    if _hash_otp(otp) != record.get("otp_hash"):
        return False

    result = await db.password_reset_otps.update_one(
        {"_id": record["_id"], "used": False},
        {"$set": {"used": True}},
    )
    return bool(result.modified_count)