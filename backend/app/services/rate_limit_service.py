from datetime import datetime, timedelta

from fastapi import HTTPException, Request
from pymongo import ReturnDocument

from app.db.database import get_database


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def enforce_rate_limit(
    request: Request,
    action: str,
    limit: int,
    window_seconds: int,
    subject: str | None = None,
):
    """Enforce a durable per-window limit using MongoDB atomic upserts."""
    db = get_database()
    now = datetime.utcnow()
    window_start = int(now.timestamp()) // window_seconds * window_seconds
    identity = subject or f"ip:{get_client_ip(request)}"
    key = f"{action}:{identity}:{window_start}"
    expires_at = datetime.utcfromtimestamp(window_start + window_seconds) + timedelta(minutes=5)

    doc = await db.rate_limits.find_one_and_update(
        {"_id": key},
        {
            "$setOnInsert": {
                "action": action,
                "identity": identity,
                "window_start": datetime.utcfromtimestamp(window_start),
                "expires_at": expires_at,
            },
            "$inc": {"count": 1},
        },
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )

    count = int(doc.get("count", 0)) if doc else 0
    if count > limit:
        retry_after = max(1, window_start + window_seconds - int(now.timestamp()))
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": str(retry_after)},
        )
