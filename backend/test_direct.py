import pymongo
import certifi

uri = "mongodb://app_user:app2005m@ac-mkl9b1w-shard-00-00.kukw6dx.mongodb.net:27017,ac-mkl9b1w-shard-00-01.kukw6dx.mongodb.net:27017,ac-mkl9b1w-shard-00-02.kukw6dx.mongodb.net:27017/?ssl=true&replicaSet=atlas-mkl9b1w-shard-0&authSource=admin&retryWrites=true&w=majority"

print(f"Testing direct connection...")
try:
    client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=5000, tlsCAFile=certifi.where())
    info = client.server_info()
    print("Auth successful! Server version:", info.get("version"))
except Exception as e:
    print("FAILED:", str(e))
