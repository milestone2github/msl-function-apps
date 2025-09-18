import logging
import json
import requests
from datetime import datetime
import azure.functions as func

import os
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

# Zoho CRM configuration
zoho_creds = json.loads(get_secret_from_vault("zoho-credentials-mApi"))
ZOHO_CLIENT_ID = zoho_creds.get("client_id", "")
ZOHO_CLIENT_SECRET = zoho_creds.get("client_secret", "")
ZOHO_REFRESH_TOKEN = zoho_creds.get("refresh_token", "")

def update_zoho_crm_record(record_id, access_token):
    HEADERS = {
        "Authorization": f"Zoho-oauthtoken {access_token}",
        "Content-Type": "application/json",
    }

    try:
        current_date = datetime.today().strftime("%Y-%m-%d")

        zoho_record = {
            "data": [
                {
                    "Accounts_Release": True,
                    "Accounts_Release_Date": current_date,
                    "id": record_id,
                }
            ],
            "duplicate_check_fields": ["id"],
        }

        response = requests.put(
            "https://www.zohoapis.com/crm/v5/Insurance_Leads",
            json=zoho_record,
            headers=HEADERS,
        )

        return response.json()
    except Exception as e:
        logging.error(f"Failed to update Zoho CRM record: {str(e)}")
        raise


def get_access_token():
    TOKEN_ENDPOINT = "https://accounts.zoho.com/oauth/v2/token"
    payload = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }

    response = requests.post(TOKEN_ENDPOINT, data=payload)
    if response.status_code == 200:
        zoho_access_token = response.json().get("access_token")
        return zoho_access_token
    else:
        logging.error("Failed to get access token.")
        raise Exception("Failed to get access token.")


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    try:
        access_token = get_access_token()
        data = req.get_json()

        record_ids = data.get("record_ids")
        if not record_ids:
            logging.warning("No record IDs provided")
            return func.HttpResponse("No record IDs provided", status_code=400)

        responses = []
        for record_id in record_ids:
            logging.info(record_id)
            response = update_zoho_crm_record(record_id, access_token)
            # dataResponse = response.json()
            logging.info(response)
            responses.append(response)

        return func.HttpResponse(
            json.dumps(responses),
            mimetype="application/json",
            status_code=200,
        )
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        return func.HttpResponse(str(e), status_code=500)
