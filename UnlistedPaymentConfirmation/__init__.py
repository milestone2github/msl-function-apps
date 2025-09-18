import logging
import json
from azure.functions import HttpRequest, HttpResponse
import requests

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
  

ZOHO_AUTH_KEY = get_secret_from_vault("zoho-auth-key-mApi")

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
def send_email(amount, security_name, buyer_name, email, crm_id, mailId):
    """
    Sends an email using the ZeptoMail API with the given parameters.
    """
    url = "https://api.zeptomail.com/v1.1/email/template"

    payload = {
        "mail_template_key": mailId,
        "from": {
            "address": "noreply@mnivesh.niveshonline.com",
            "name": "noreply"
        },
        "to": [
            {
                "email_address": {
                    "address": email,
                    "name": buyer_name
                }
            }
        ],
        "merge_info": {
            "amount": amount,
            "Buyer_name": buyer_name,
            "security_name": security_name,
            "crmid":crm_id
        }
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "authorization": ZOHO_AUTH_KEY
    }

    try:
        response = requests.post(url, data=json.dumps(payload), headers=headers)
        response.raise_for_status()
        logging.info("Email sent successfully: %s", response.text)
        return {"status": "success", "response": response.text}
    except requests.exceptions.RequestException as e:
        logging.error("Error sending email: %s", str(e))
        return {"status": "error", "error": str(e)}
    
def format_indian_numeric(number):
    number_parts = str(number).split(".")
    integer_part = number_parts[0]
    decimal_part = number_parts[1] if len(number_parts) > 1 else ""

    # Reverse the string to group digits
    reversed_number = integer_part[::-1]
    grouped_number = ""

    for i, digit in enumerate(reversed_number):
        if i > 2 and (i - 3) % 2 == 0:
            grouped_number += ","
        grouped_number += digit

    # Reverse again to get the final format
    formatted_number = grouped_number[::-1]

    # Add the decimal part if it exists
    if decimal_part:
        formatted_number += "." + decimal_part

    return formatted_number

async def main(req: HttpRequest) -> HttpResponse:
    """
    Azure HTTP Trigger Function to handle POST requests and send emails.
    """
    logging.info("Processing request...")

    try:
        # Parse request JSON
        req_body = req.get_json()
        
        # Extract parameters
        amount = float(req_body.get("amount", 0))
        security_name = req_body.get("security_name")
        buyer_name = req_body.get("buyer_name")
        email = req_body.get("email")
        crm_id = req_body.get("crm_id")
        Type = req_body.get("Type")
        logging.info("Request body: %s", req.get_body().decode("utf-8"))
        # Validate required parameters
        if not all([amount, security_name, buyer_name]):
            raise ValueError("Missing one or more required parameters: amount, security_name, buyer_name")
        amount = format_indian_numeric(amount)
        logging.info(amount)

        if Type == "Seller":
                mailId = get_secret_from_vault("seller-mailId-mApi")
        elif Type == "Buyer":
                mailId = get_secret_from_vault("buyer-mailId-mApi")

        # Send the email
        email_response = send_email(amount, security_name, buyer_name, email, crm_id, mailId)

        # Return response
        return HttpResponse(json.dumps(email_response), status_code=200, mimetype="application/json")

    except ValueError as ve:
        logging.error("Validation error: %s", str(ve))
        return HttpResponse(json.dumps({"status": "error", "error": str(ve)}), status_code=400, mimetype="application/json")
    except Exception as e:
        logging.error("Unexpected error: %s", str(e))
        return HttpResponse(json.dumps({"status": "error", "error": str(e)}), status_code=500, mimetype="application/json")
