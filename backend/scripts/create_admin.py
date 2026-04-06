import asyncio
import sys
import getpass
import os
from datetime import datetime

# Insert parent directory so app imports resolve
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def create_admin():
    print("Connecting to MongoDB using configured environment settings...")
    try:
        client = AsyncIOMotorClient(settings.MONGODB_URL, serverSelectionTimeoutMS=5000)
        await client.admin.command('ping')
        db = client[settings.DATABASE_NAME]
    except Exception as e:
        print(f"❌ Failed to connect to database: {e}")
        return

    print("\n--- Create New Administrator ---")
    email = input("Enter new admin email: ").strip().lower()
    if not email:
        print("❌ Email cannot be empty.")
        client.close()
        return
    if "@" not in email:
        print("❌ Enter a valid email address.")
        client.close()
        return

    existing = await db.users.find_one({"email": email})
    if existing:
        print(f"❌ A user with the email '{email}' already exists.")
        client.close()
        return

    password = getpass.getpass("Enter new admin password: ")
    if not password:
        print("❌ Password cannot be empty.")
        client.close()
        return
    if len(password) < 10:
        print("❌ Password must be at least 10 characters.")
        client.close()
        return
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password) or not any(c.isdigit() for c in password):
        print("❌ Password must include uppercase, lowercase, and a number.")
        client.close()
        return

    print(f"Creating admin account {email}...")
    
    await db.users.insert_one({
        "email": email,
        "password_hash": pwd_context.hash(password),
        "role": "admin",
        "is_active": True,
        "is_verified": True,
        "full_name": "System Administrator",
        "created_at": datetime.utcnow()
    })
    
    print(f"✅ Success! Admin account '{email}' has been created.")
    client.close()

if __name__ == "__main__":
    asyncio.run(create_admin())
