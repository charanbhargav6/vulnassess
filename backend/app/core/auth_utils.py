from datetime import datetime
from typing import Dict

from bson import ObjectId
from fastapi import HTTPException, Request, Response

from app.core.config import settings
from app.core.security import verify_token
from app.db.database import get_database


def _read_bearer_token(request: Request) -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return ""


def extract_request_token(request: Request, allow_query_token: bool = False) -> str:
    token = _read_bearer_token(request)
    if token:
        return token

    cookie_token = (request.cookies.get(settings.AUTH_COOKIE_NAME) or "").strip()
    if cookie_token:
        return cookie_token

    if allow_query_token:
        return (request.query_params.get("token") or "").strip()

    return ""


def _resolve_cookie_security(request: Request) -> tuple[bool, str]:
    origin = (request.headers.get("origin") or "").lower().strip()
    secure_cookie = settings.AUTH_COOKIE_SECURE or origin.startswith("https://")

    same_site = (settings.AUTH_COOKIE_SAMESITE or "none").lower().strip()
    if same_site not in {"lax", "strict", "none"}:
        same_site = "none"

    if same_site == "none" and not secure_cookie:
        # Browsers reject SameSite=None cookies unless Secure=true.
        same_site = "lax"

    return secure_cookie, same_site


def set_auth_cookie(response: Response, token: str, request: Request) -> None:
    secure_cookie, same_site = _resolve_cookie_security(request)
    max_age = int(settings.ACCESS_TOKEN_EXPIRE_MINUTES) * 60
    cookie_domain = (settings.AUTH_COOKIE_DOMAIN or "").strip() or None

    response.set_cookie(
        key=settings.AUTH_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=secure_cookie,
        samesite=same_site,
        max_age=max_age,
        expires=max_age,
        path="/",
        domain=cookie_domain,
    )


def clear_auth_cookie(response: Response, request: Request) -> None:
    secure_cookie, same_site = _resolve_cookie_security(request)
    cookie_domain = (settings.AUTH_COOKIE_DOMAIN or "").strip() or None

    response.delete_cookie(
        key=settings.AUTH_COOKIE_NAME,
        path="/",
        domain=cookie_domain,
        secure=secure_cookie,
        httponly=True,
        samesite=same_site,
    )


async def revoke_user_sessions(user_id: str) -> None:
    db = get_database()
    await db.users.update_one(
        {"_id": ObjectId(user_id)},
        {
            "$inc": {"token_version": 1},
            "$set": {"last_token_revoked_at": datetime.utcnow()},
        },
    )


async def get_authenticated_user(
    request: Request,
    allow_query_token: bool = False,
    require_active: bool = True,
) -> Dict[str, str]:
    token = extract_request_token(request, allow_query_token=allow_query_token)
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    raw_user_id = payload.get("sub")
    if not raw_user_id:
        raise HTTPException(status_code=401, detail="Invalid authentication payload")

    try:
        user_id = ObjectId(raw_user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication payload")

    db = get_database()
    db_user = await db.users.find_one({"_id": user_id})
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")

    if require_active and not db_user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated")

    token_version = int(payload.get("ver", 1))
    user_token_version = int(db_user.get("token_version", 1))
    if token_version != user_token_version:
        raise HTTPException(status_code=401, detail="Session expired. Please login again")

    return {
        "sub": str(db_user["_id"]),
        "role": db_user.get("role", "user"),
        "email": db_user.get("email", ""),
    }


async def get_authenticated_db_user(
    request: Request,
    allow_query_token: bool = False,
    require_active: bool = True,
) -> Dict:
    cached_user = getattr(request.state, "_auth_db_user", None)
    if cached_user is not None:
        return cached_user

    token = extract_request_token(request, allow_query_token=allow_query_token)
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Not authenticated")

    raw_user_id = payload.get("sub")
    if not raw_user_id:
        raise HTTPException(status_code=401, detail="Invalid authentication payload")

    try:
        user_id = ObjectId(raw_user_id)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid authentication payload")

    db = get_database()
    db_user = await db.users.find_one({"_id": user_id})
    if not db_user:
        raise HTTPException(status_code=401, detail="User not found")

    if require_active and not db_user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated")

    token_version = int(payload.get("ver", 1))
    user_token_version = int(db_user.get("token_version", 1))
    if token_version != user_token_version:
        raise HTTPException(status_code=401, detail="Session expired. Please login again")

    request.state._auth_db_user = db_user
    return db_user


async def require_admin_user(request: Request) -> Dict[str, str]:
    user = await get_authenticated_user(request)
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
