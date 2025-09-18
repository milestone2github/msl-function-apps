import json
import logging
import requests
from azure.functions import HttpRequest, HttpResponse
from datetime import datetime
import pytz

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

# Define IST timezone
ist = pytz.timezone('Asia/Kolkata')

# Get current date and time in IST
current_date_ist = datetime.now(ist)

# Format date as dd/MM/YYYY
formatted_date = current_date_ist.strftime('%Y-%m-%d')

# Configure logging at the global level
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Zoho CRM configuration
zoho_creds = json.loads(get_secret_from_vault("zoho-credentials-mApi"))
ZOHO_CLIENT_ID = zoho_creds.get("client_id", "")
ZOHO_CLIENT_SECRET = zoho_creds.get("client_secret", "")
ZOHO_REFRESH_TOKEN = zoho_creds.get("refresh_token", "")

def main(req: HttpRequest) -> HttpResponse:
    logging.info("Processing webhook request for Zoho CRM update.")

    try:
        # Parse incoming request
        req_body = req.get_json()
        crm_id = req_body.get("crm_id")
        name = req_body.get("name")
        pan_number = req_body.get("pan_number")
        email_id = req_body.get("email_id")

        logging.info(crm_id)
        logging.info(name)
        logging.info(pan_number)
        logging.info(email_id)


        # Validate the required parameters
        if not all([crm_id, name, pan_number, email_id]):
            return HttpResponse("Missing parameters in request.", status_code=400)

        # Authenticate with Zoho CRM
        access_token = get_access_token()
        if not access_token:
            return HttpResponse("Failed to authenticate with Zoho CRM.", status_code=500)

        # Update Zoho CRM
        update_response = update_zoho_crm(access_token, crm_id, pan_number, email_id)
        if update_response.get("status") == "success":
            return HttpResponse("Zoho CRM updated successfully.", status_code=200)
        else:
            logging.error(f"Zoho CRM update failed: {update_response}")
            return HttpResponse("Error updating Zoho CRM.", status_code=500)

    except Exception as e:
        logging.error(f"Error processing request: {e}")
        return HttpResponse("Internal server error.", status_code=500)

def get_access_token():
    TOKEN_ENDPOINT = "https://accounts.zoho.com/oauth/v2/token"
    payload = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }
    response = requests.post(TOKEN_ENDPOINT, data=payload)
    return response.json().get("access_token")

def update_zoho_crm(access_token, crm_id, pan_number, email_id):
    zoho_record = {
        "data": [
            {
                "PAN_Number": pan_number,
                "Buyer_Email": email_id,
                "id": crm_id,
                "Soft_Confirmation": "TRUE",
                "Soft_Confirmation_Date":formatted_date
            }
        ]
    }
    url = f"https://www.zohoapis.com/crm/v2/Unlisted_Deals/{crm_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    response = requests.put(url, headers=headers, json=zoho_record)
    response_data = response.json()
    if response.status_code in [200, 201]:
        return {"status": "success", "details": response_data}
    else:
        return {"status": "error", "details": response_data}
