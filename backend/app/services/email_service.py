import secrets
import logging
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

    # Fallback — print to console (dev mode)
    logger.info(f"[DEV MODE] Verification token for {email}: {token}")
    logger.info(f"[DEV MODE] Verify URL: {verify_url}")
    print(f"\n{'='*60}")
    print(f"[DEV] Email verification for: {email}")
    print(f"[DEV] Open this URL to verify:")
    print(f"[DEV] {verify_url}")
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