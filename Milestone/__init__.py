import logging
import azure.functions as func
import pymongo
import os
import json

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Fetch secrets
VAULT_URL = f"https://{os.environ['KEYVAULT_NAME']}.vault.azure.net"
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=VAULT_URL, credential=credential)

def get_secret_from_vault(secret_name: str) -> str:
  """Fetch secret value from Azure Key Vault."""
  try:
    secret = secret_client.get_secret(secret_name)
    return secret.value
  except Exception as e:
    logging.error(f"Failed to fetch secret '{secret_name}' from Key Vault: {str(e)}")
    return None

CONNECTIONSTRING = get_secret_from_vault("connection-string-mApi")

def main(req: func.HttpRequest) -> func.HttpResponse:
    try:
        # Parse request body
        req_body = req.get_json()

        # Extract operation type and data from the request
        collection = req_body.get("collection")
        operation = req_body.get("operation")
        data = req_body.get("data")

        # Connect to MongoDB Atlas
        client = pymongo.MongoClient(CONNECTIONSTRING)
        db = client["Milestone"]
        collection = db[collection]

        # Dynamically handle the operation
        if operation == "find":
            query = data.get("query", {})
            results = collection.find(query)
            return func.HttpResponse(
                json.dumps(list(results), default=str),  # Serialize results
                status_code=200,
            )
        elif operation == "insert":
            result = collection.insert_one(data)
            return func.HttpResponse(
                json.dumps({"inserted_id": str(result.inserted_id)}), status_code=201
            )
        elif operation == "update":
            query = data.get("query")
            new_values = {"$set": data.get("new_values")}
            result = collection.update_one(query, new_values)
            return func.HttpResponse(
                json.dumps({"modified_count": result.modified_count}), status_code=200
            )
        elif operation == "delete":
            query = data.get("query")
            result = collection.delete_one(query)
            return func.HttpResponse(
                json.dumps({"deleted_count": result.deleted_count}), status_code=200
            )
        elif operation == "upsert":
            query = data.get("query")
            new_values = {"$set": data.get("new_values")}
            result = collection.update_one(query, new_values, upsert=True)
            return func.HttpResponse(
                json.dumps({"upserted_id": str(result.upserted_id)}), status_code=200
            )
        elif operation == "bulk_insert":
            documents = data.get("documents")
            result = collection.insert_many(documents)
            return func.HttpResponse(
                json.dumps({"inserted_ids": [str(id) for id in result.inserted_ids]}),
                status_code=200,
            )
        elif operation == "bulk_upsert":
            requests = [
                pymongo.UpdateOne({"_id": doc["_id"]}, {"$set": doc}, upsert=True)
                for doc in data
            ]
            result = collection.bulk_write(requests)
            return func.HttpResponse(
                json.dumps({"modified_count": result.modified_count}), status_code=200
            )
        elif operation == "bulk_refresh":
            # Assuming bulk_refresh means replacing multiple documents entirely
            requests = [
                pymongo.ReplaceOne({"_id": doc["_id"]}, doc, upsert=True)
                for doc in data
            ]
            result = collection.bulk_write(requests)
            return func.HttpResponse(
                json.dumps({"modified_count": result.modified_count}), status_code=200
            )
        else:
            return func.HttpResponse("Unsupported operation", status_code=400)
    except Exception as e:
        return func.HttpResponse("Error: " + str(e), status_code=500)
