import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test():
    try:
        print("Testing connection...")
        client = AsyncIOMotorClient('mongodb+srv://admin:admin123m@vulnassess.kukw6dx.mongodb.net/?appName=vulnassess', serverSelectionTimeoutMS=5000)
        await client.admin.command('ping')
        print('SUCCESS! Connection works.')
    except Exception as e:
        print(f"FAILED: {e}")

asyncio.run(test())
