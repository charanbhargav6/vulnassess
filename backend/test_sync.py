import pymongo
import certifi

uri = "mongodb+srv://admin:admin2005m@vulnassess.kukw6dx.mongodb.net/?authSource=admin&appName=vulnassess"
print(f"Testing connection to: {uri}")
try:
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=10000, tlsCAFile=certifi.where())
    client.admin.command('ping')
    print("Ping successful!")
    print("Auth testing...")
    info = client.server_info()
    print("Auth successful! Server version:", info.get("version"))
except Exception as e:
    print("FAILED:", str(e))
