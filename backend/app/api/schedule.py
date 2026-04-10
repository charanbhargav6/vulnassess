from fastapi import APIRouter, HTTPException, Request
from app.db.database import get_database
from app.core.auth_utils import get_authenticated_user
from app.services.credential_crypto import encrypt_secret
from app.services.url_security import validate_scan_target
from bson import ObjectId
from datetime import datetime
from pydantic import BaseModel
from typing import Optional

router = APIRouter()

TIMEFRAMES = {
    "1hour": {"hours": 1, "label": "Every Hour"},
    "6hours": {"hours": 6, "label": "Every 6 Hours"},
    "12hours": {"hours": 12, "label": "Every 12 Hours"},
    "daily": {"hours": 24, "label": "Daily"},
    "weekly": {"hours": 168, "label": "Weekly"},
    "monthly": {"hours": 720, "label": "Monthly"},
}

class ScheduleCreate(BaseModel):
    target_url: str
    timeframe: str
    username: Optional[str] = None
    password: Optional[str] = None

class ScheduleUpdate(BaseModel):
    is_active: bool

async def get_user_from_token(request: Request):
    return await get_authenticated_user(request)

@router.get("/schedules")
async def get_schedules(request: Request):
    payload = await get_user_from_token(request)
    db = get_database()
    role = payload.get("role")
    user_id = payload.get("sub")

    query = {} if role == "admin" else {"user_id": user_id}
    schedules = []
    async for s in db.schedules.find(query).sort("created_at", -1):
        schedules.append({
            "id": str(s["_id"]),
            "target_url": s["target_url"],
            "timeframe": s["timeframe"],
            "timeframe_label": TIMEFRAMES.get(s["timeframe"], {}).get("label", s["timeframe"]),
            "auth_enabled": bool(s.get("auth_enabled", False)),
            "is_active": s.get("is_active", True),
            "last_run": s.get("last_run"),
            "next_run": s.get("next_run"),
            "run_count": s.get("run_count", 0),
            "created_at": s["created_at"],
            "user_id": s["user_id"],
        })
    return schedules

@router.post("/schedules")
async def create_schedule(data: ScheduleCreate, request: Request):
    payload = await get_user_from_token(request)
    db = get_database()
    user_id = payload.get("sub")

    if data.timeframe not in TIMEFRAMES:
        raise HTTPException(status_code=400, detail=f"Invalid timeframe. Choose from: {list(TIMEFRAMES.keys())}")

    username = (data.username or "").strip() or None
    password = (data.password or "").strip() or None
    if (username and not password) or (password and not username):
        raise HTTPException(status_code=400, detail="Provide both username and password for authenticated schedules")

    normalized_target, _ = validate_scan_target(
        data.target_url,
        is_admin=(payload.get("role") == "admin"),
    )

    encrypted_username = encrypt_secret(username)
    encrypted_password = encrypt_secret(password)

    # Check max 10 schedules per user
    count = await db.schedules.count_documents({"user_id": user_id})
    if count >= 10:
        raise HTTPException(status_code=400, detail="Maximum 10 schedules allowed per user")

    hours = TIMEFRAMES[data.timeframe]["hours"]
    now = datetime.utcnow()

    schedule = {
        "user_id": user_id,
        "target_url": normalized_target,
        "timeframe": data.timeframe,
        "interval_hours": hours,
        "auth_enabled": bool(username and password),
        "auth_username_enc": encrypted_username,
        "auth_password_enc": encrypted_password,
        "is_active": True,
        "run_count": 0,
        "last_run": None,
        "next_run": now,  # Run immediately on first time
        "created_at": now,
    }
    result = await db.schedules.insert_one(schedule)
    return {"id": str(result.inserted_id), "message": "Schedule created successfully"}

@router.put("/schedules/{schedule_id}")
async def toggle_schedule(schedule_id: str, data: ScheduleUpdate, request: Request):
    payload = await get_user_from_token(request)
    db = get_database()
    user_id = payload.get("sub")
    role = payload.get("role")

    schedule = await db.schedules.find_one({"_id": ObjectId(schedule_id)})
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if role != "admin" and schedule["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.schedules.update_one(
        {"_id": ObjectId(schedule_id)},
        {"$set": {"is_active": data.is_active}}
    )
    return {"message": "Schedule updated"}

@router.delete("/schedules/{schedule_id}")
async def delete_schedule(schedule_id: str, request: Request):
    payload = await get_user_from_token(request)
    db = get_database()
    user_id = payload.get("sub")
    role = payload.get("role")

    schedule = await db.schedules.find_one({"_id": ObjectId(schedule_id)})
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    if role != "admin" and schedule["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Not authorized")

    await db.schedules.delete_one({"_id": ObjectId(schedule_id)})
    return {"message": "Schedule deleted"}