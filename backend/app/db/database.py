from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

db_client = None
db = None

async def connect_db():
    global db_client, db

    async def _connect(url: str):
        client = AsyncIOMotorClient(
            url,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
        )
        await client.admin.command("ping")
        return client

    try:
        db_client = await _connect(settings.MONGODB_URL)
        db = db_client[settings.DATABASE_NAME]
        print(f"Connected to MongoDB: {settings.DATABASE_NAME}")
        return
    except Exception as primary_error:
        print(f"Failed to connect to MongoDB at configured URL: {primary_error}")
        raise primary_error

async def close_db():
    global db_client
    if db_client:
        db_client.close()
        print("Disconnected from MongoDB")

def get_database():
    return db