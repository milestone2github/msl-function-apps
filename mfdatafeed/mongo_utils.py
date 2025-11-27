from pymongo import MongoClient

from mfdatafeed.azure_utils import get_secret
from mfdatafeed.config import get_vault_name
from mfdatafeed.logger_utils import log_custom


def get_mongo_client():
  vault_name = get_vault_name()
  mongo_connection_string = get_secret(vault_name, "MongoDb-Connection-String")
  # print(f"MongoDB connection string ==> {mongo_connection_string}")
  
  # Initialize MongoDB
  MONGO_CLIENT = MongoClient(mongo_connection_string)
  if not MONGO_CLIENT:
    log_custom("critical", "Mongo Failed to established, critical error")
  db = MONGO_CLIENT["DataFeed"]["DataFeedLogs"]
  db.create_index([("messageId", 1)], unique=True)
  return MONGO_CLIENT, db