import asyncio
import getpass
import os
import sys
from datetime import datetime

from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def main():
    print("WARNING: This will remove every user account in the database.")
    confirm = input("Type WIPE_USERS to continue: ").strip()
    if confirm != "WIPE_USERS":
        print("Cancelled.")
        return

    client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=8000)
    await client.admin.command("ping")
    db = client[settings.DATABASE_NAME]

    result = await db.users.delete_many({})
    print(f"Deleted {result.deleted_count} users.")

    email = (input("Fresh admin email [admin@vulnassess.com]: ").strip().lower() or "admin@vulnassess.com")
    password = getpass.getpass("Fresh admin password: ")
    if len(password) < 10:
        print("Password must be at least 10 characters.")
        client.close()
        return

    await db.users.insert_one({
        "email": email,
        "password_hash": pwd_context.hash(password),
        "role": "admin",
        "is_active": True,
        "is_verified": True,
        "full_name": "System Administrator",
        "created_at": datetime.utcnow(),
    })

    print("Created fresh admin account successfully.")
    print(f"Email: {email}")
    print("Password: (hidden)")
    client.close()


if __name__ == "__main__":
    asyncio.run(main())
