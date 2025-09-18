import azure.functions as func
from pymongo import MongoClient
from datetime import datetime, timedelta
import os
import logging
import requests
import json

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

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

# MongoDB connection string - Replace <database> with your actual database name
CONNECTIONSTRING = get_secret_from_vault("connection-string-mApi")


def generate_email_content(lists):
    html_content = "<div>"
    for list_name, clients in lists.items():
        html_content += f"<h3>{list_name}</h3><ul>"
        for client in clients:
            name = client.get("NAME", "No Name Provided")
            email = client.get("EMAIL", "No Email Provided")
            html_content += f"<li>{name} - {email}</li>"
        html_content += "</ul>"
    html_content += "</div>"
    return html_content


def send_email(email_content, recipients):
    # Zoho ZeptoMail API URL
    url = "https://api.zeptomail.com/v1.1/email"

    # Prepare the payload
    payload = json.dumps(
        {
            "from": {"address": "noreply@mnivesh.niveshonline.com"},
            "to": [{"email_address": recipient} for recipient in recipients],
            "subject": "Client List Update",
            "htmlbody": email_content,
        }
    )

    # Headers including your Zoho API key - Replace YOUR_API_KEY with your actual API key
    ZOHO_AUTH_KEY = get_secret_from_vault("zoho-auth-key-mApi")
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": ZOHO_AUTH_KEY,
    }

    # Send the request
    response = requests.request("POST", url, data=payload, headers=headers)

    logging.info(f"Email send response: {response.text}")


def main(mytimer: func.TimerRequest) -> None:
    mongo_client = MongoClient(CONNECTIONSTRING)
    db = mongo_client["Milestone"]
    collection = db["MintDb"]

    logging.info("Script started and MongoDB connection established.")

    # Calculate yesterday's date range
    yesterday = datetime.now() - timedelta(days=1)
    start_of_yesterday_str = yesterday.strftime("%Y-%m-%d 00:00:00")
    end_of_yesterday_str = yesterday.strftime("%Y-%m-%d 23:59:59")

    # Fetch clients imported yesterday
    query = {
        "First Imported Date": {
            "$gte": start_of_yesterday_str,
            "$lte": end_of_yesterday_str,
        }
    }
    clients_yesterday = list(collection.find(query))
    logging.info(
        f"Total clients with 'First Imported Date' as yesterday: {len(clients_yesterday)}"
    )

    # Aggregate PAN counts for yesterday's clients
    pan_counts = collection.aggregate(
        [
            {"$match": query},
            {"$group": {"_id": "$PAN", "count": {"$sum": 1}}},
            {"$project": {"PAN": "$_id", "count": 1, "_id": 0}},
        ]
    )
    pan_count_dict = {doc["PAN"]: doc["count"] for doc in pan_counts if doc["PAN"]}

    # Initialize lists to hold categorized clients
    duplicates, no_pan, unique_with_aum, unique_without_aum = [], [], [], []

    # Process each client
    for client in clients_yesterday:
        pan = client.get("PAN")
        aum = client.get("AUM", 0)
        if pan:
            if pan in pan_count_dict and pan_count_dict[pan] == 1:  # PAN is unique
                if aum > 0:
                    unique_with_aum.append(client)
                else:
                    unique_without_aum.append(client)
            else:
                duplicates.append(client)
        else:
            no_pan.append(client)

    # Logging the results
    logging.info(f"Duplicate PAN entries: {len(duplicates)}")
    logging.info(f"No PAN entries: {len(no_pan)}")
    logging.info(f"Unique PAN with AUM: {len(unique_with_aum)}")
    logging.info(f"Unique PAN without AUM: {len(unique_without_aum)}")

    # Generate email content
    lists = {
        "Duplicates": duplicates,
        "No PAN": no_pan,
        "Unique with AUM": unique_with_aum,
        "Unique without AUM": unique_without_aum,
    }
    email_content = generate_email_content(lists)

    # Define your recipients
    recipients_list_raw = get_secret_from_vault("new-client-recipients-mApi")
    recipients = json.loads(recipients_list_raw)

    # Send the email
    send_email(email_content, recipients)

    mongo_client.close()
