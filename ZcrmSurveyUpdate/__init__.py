import json
import random
import requests
import logging
from datetime import datetime
import pytz
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

def getAccessToken():
    TOKEN_ENDPOINT = "https://accounts.zoho.com/oauth/v2/token"
    payload = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }
    response = requests.post(TOKEN_ENDPOINT, data=payload)
    response.raise_for_status()
    ACCESS_TOKEN = response.json().get("access_token")
    return ACCESS_TOKEN


def GetRecordId(iwellCode, AccessToken):
    header = {"Authorization": f"Zoho-oauthtoken {AccessToken}"}
    response = requests.get(
        url=f"https://www.zohoapis.com/crm/v6/Portfolio_Review/search?criteria=(Iwell_Code:equals:{iwellCode})",
        headers=header,
    )
    response.raise_for_status()
    response_data = response.json()
    if "data" in response_data and len(response_data["data"]) > 0:
        return response_data["data"][0]["id"]
    else:
        logging.error("No data found or error in response")
        return None


def get_ist_date():
    utc_now = datetime.now(pytz.utc)
    ist = pytz.timezone("Asia/Kolkata")
    ist_now = utc_now.astimezone(ist)
    formatted_date = ist_now.strftime("%Y-%m-%d")
    return formatted_date


def UpdatePortfolioReview(AccessToken, SurveyScore, RecordId):
    today = get_ist_date()
    headers = {"Authorization": f"Zoho-oauthtoken {AccessToken}"}
    url = f"https://www.zohoapis.com/crm/v6/Portfolio_Review/{RecordId}"

    # Ensure SurveyScore does not exceed the maximum length allowed
    max_length = 5
    SurveyScore = SurveyScore[:max_length]

    zoho_record = {
        "data": [
            {
                "id": RecordId,
                "General_Feedback": SurveyScore,
                "General_Ve_date": today,
            }
        ]
    }
    response = requests.put(url, headers=headers, json=zoho_record)
    response_data = response.json()
    print(response_data)
    if (
        response.status_code in [200, 201]
        and response_data.get("data")[0].get("status") == "success"
    ):
        return {"status": "success", "details": response_data}
    else:
        logging.error(f"Error from Zoho CRM: {response.text}")
        return {"status": "error", "details": response_data}


def get_owner_id(access_token):
    options = ["Sagar Maini", "Ishu Mavar", "Yatin Munjal"]
    rm_name = random.choice(options)
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    response = requests.get(
        "https://www.zohoapis.com/crm/v2/users?type=ActiveUsers", headers=headers
    )
    response.raise_for_status()
    users = response.json().get("users", [])
    email_to_id = {user["email"].lower(): user["id"] for user in users}
    owner_email = f"{rm_name.split()[0].lower()}@niveshonline.com"
    return email_to_id.get(owner_email.lower(), "2969103000000183019")


def CreateInvestmentLead(access_token, lead_name, mobile, product, owner_id):
    zoho_record = {
        "data": [
            {
                "Name": lead_name,
                "Mobile": mobile,
                "Owner": owner_id,
                "Product_Type": product,
                "Refrencer_Name": "WA Marketing",
            }
        ]
    }
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    url = "https://www.zohoapis.com/crm/v2/Investment_leads"
    response = requests.post(url, headers=headers, json=zoho_record)
    response_data = response.json()
    if (
        response.status_code in [200, 201]
        and response_data.get("data")[0].get("status") == "success"
    ):
        return {"status": "success", "details": response_data}
    else:
        logging.error(f"Error from Zoho CRM: {response.text}")
        return {"status": "error", "details": response_data}


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Python HTTP trigger function processed a request.")

    if req.method == "POST":
        req_body = req.get_json()
        IwellCode = req_body.get("Iwell")
        SurveyScore = req_body.get("Score")
        FirstName = req_body.get("FName")
        LastName = req_body.get("LName")
        Mobile = req_body.get("Mobile")
        Email = req_body.get("Email")
    else:
        IwellCode = req.params.get("Iwell")
        SurveyScore = req.params.get("Score")
        logging.info(SurveyScore)
        FirstName = req.params.get("FName")
        LastName = req.params.get("LName")
        Mobile = req.params.get("Mobile")
        Email = req.params.get("Email")

    if not IwellCode or not SurveyScore:
        return func.HttpResponse(
            "Please pass IwellCode and SurveyScore in the query string or body",
            status_code=400,
        )

    lead_name = f"{FirstName} {LastName}"

    try:
        access_token = getAccessToken()
        RecordID = GetRecordId(IwellCode, access_token)

        if RecordID:
            update_status = UpdatePortfolioReview(access_token, SurveyScore, RecordID)
        else:
            logging.error("Record ID not found.")
            return func.HttpResponse("Record ID not found.", status_code=404)

        OwnerID = get_owner_id(access_token)
        CreationStatus = CreateInvestmentLead(
            access_token, lead_name, Mobile, "Mutual Funds", OwnerID
        )

        if (
            update_status["status"] == "success"
            and CreationStatus["status"] == "success"
        ):
            return func.HttpResponse("Success", status_code=200)
        else:
            error_message = f"Update Status: {update_status['details']}, Creation Status: {CreationStatus['details']}"
            return func.HttpResponse(f"Error: {error_message}", status_code=500)
    except Exception as e:
        logging.error(f"Exception occurred: {str(e)}")
        return func.HttpResponse(f"Exception: {str(e)}", status_code=500)
