import asyncio
from motor.motor_asyncio import AsyncIOMotorClient

async def test_auth():
    uri = "mongodb+srv://admin:admin2005m@vulnassess.kukw6dx.mongodb.net/?authSource=admin&appName=vulnassess"
    print(f"Testing connection...")
    client = AsyncIOMotorClient(uri, serverSelectionTimeoutMS=5000)
    try:
        await client.admin.command('ping')
        print("Ping succeeded.")
        info = await client.server_info()
        print("Auth succeeded! Server version:", info.get("version"))
        db = client["vulnassess"]
        await db.test_collection.insert_one({"test": 1})
        print("Write succeeded!")
    except Exception as e:
        print("FAILED:", str(e))

if __name__ == "__main__":
    asyncio.run(test_auth())
