import json
import logging
import time
import azure.functions as func
import requests
import smtplib, ssl
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO

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

ZEPTOPASSWORD = get_secret_from_vault("zepto-password-mApi")

zoho_client = json.loads(get_secret_from_vault("zoho-credentials-mApi"))
ZOHO_CLIENT_ID = zoho_client.get("client_id", "")
ZOHO_CLIENT_SECRET = zoho_client.get("client_secret", "")
ZOHO_REFRESH_TOKEN = zoho_client.get("refresh_token", "")

logging.basicConfig(level=logging.INFO)

def retry(func, retries=2, delay=1, *args, **kwargs):
    for attempt in range(retries + 1):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logging.error(f"Attempt {attempt + 1} failed: {e}")
            if attempt < retries:
                time.sleep(delay)
            else:
                raise


def get_access_token():
    TOKEN_ENDPOINT = "https://accounts.zoho.in/oauth/v2/token"
    payload = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }
    try:
        response = requests.post(TOKEN_ENDPOINT, data=payload)
        response.raise_for_status()
        json_response = response.json()
        return json_response.get("access_token")
    except requests.exceptions.RequestException as e:
        send_email(str(e))
        logging.error(f"Failed to get access token: {e}")
        raise


def create_document(employeeName, employeeEmail, oauth):
    url = "https://sign.zoho.in/api/v1/templates/70669000000031001/createdocument"
    headers = {"Authorization": f"Zoho-oauthtoken {oauth}"}

    data = {
        "templates": {
            "field_data": {
                "field_text_data": {},
                "field_boolean_data": {},
                "field_date_data": {},
                "field_radio_data": {},
            },
            "actions": [
                {
                    "recipient_name": employeeName,
                    "recipient_email": employeeEmail,
                    "action_id": "70669000000031024",
                    "signing_order": 1,
                    "role": "Employee",
                    "verify_recipient": False,
                    "private_notes": "mNivesh",
                    "verification_type": "EMAIL",
                },
                {
                    "recipient_name": "Vilakshan Bhutani",
                    "recipient_email": "Director@niveshonline.com",
                    "action_id": "70669000000031022",
                    "signing_order": 2,
                    "role": "Director",
                    "verify_recipient": False,
                    "private_notes": employeeName,
                },
                {
                    "recipient_name": "Human Resource",
                    "recipient_email": "HR@niveshonline.com",
                    "action_id": "70669000000041700",
                    "signing_order": 3,
                    "role": "Human Resource",
                    "verify_recipient": False,
                    "private_notes": employeeName,
                },
            ],
            "notes": employeeName,
        }
    }

    files = {
        "data": (None, str(data).replace("'", '"')),
        "is_quicksend": (None, "false"),
    }

    try:
        response = retry(
            requests.post, retries=2, url=url, headers=headers, files=files
        )
        response.raise_for_status()
        json_response = response.json()

        document_id = json_response["requests"]["document_ids"][0]["document_id"]
        request_id = json_response["requests"]["request_id"]
        logging.info(f"Document ID: {document_id}")
        logging.info(f"Request ID: {request_id}")
        return document_id, request_id
    except requests.exceptions.RequestException as e:
        send_email(str(e))
        logging.error(f"Failed to create document: {e}")
        logging.error(f"Response: {response.json()}")
        raise


def generate_estamp(
    request_id,
    document_id,
    employeePAN,
    second_party_name,
    street_address,
    city,
    state,
    pincode,
    country,
    oauth,
):
    # Fetch PAN, Phone Number and other confidential details
    RETRIEVE_FIN_CREDS = get_secret_from_vault("nda-financial-creds-mApi")
    fin_creds = json.loads(RETRIEVE_FIN_CREDS)

    url = f"https://sign.zoho.in/api/v1/requests/{request_id}"
    headers = {"Authorization": f"Zoho-oauthtoken {oauth}"}

    first_party_address = {
        "street_address": "101G, Crowne Heights, Sector 10, Rohini",
        "city": "Delhi",
        "state": "DL",
        "pincode": "110085",
        "country": "India",
    }

    second_party_address = {
        "street_address": street_address,
        "city": city,
        "state": state,
        "pincode": pincode,
        "country": country,
    }

    data = {
        "document_ids": [
            {
                "document_id": document_id,
                "document_order": 0,
                "estamping_request": {
                    "stamp_duty_paid_by": "First Party",
                    "stamp_state": "DL",
                    "document_category": "1",
                    "stamp_amount": "100",
                    "first_party_name": "Milestone Global Moneymart Private Limited",
                    "duty_payer_phone_number": fin_creds['phone'],
                    "second_party_name": second_party_name,
                    "consideration_amount": 1000000,
                    "first_party_details": {
                        "first_party_entity_type": "Organization",
                        "first_party_id_type": "PAN",
                        "first_party_id_number": fin_creds['pan'],
                    },
                    "second_party_details": {
                        "second_party_id_type": "PAN",
                        "second_party_entity_type": "Individual",
                        "second_party_id_number": employeePAN,
                    },
                    "first_party_address": first_party_address,
                    "second_party_address": second_party_address,
                },
            }
        ]
    }

    payload = {"requests": data}

    try:
        response = retry(
            requests.put, retries=2, url=url, headers=headers, json=payload
        )
        response.raise_for_status()
        logging.info("E-stamp paper generated successfully.")
        return 200
    except requests.exceptions.RequestException as e:
        send_email(str(e))
        logging.error(f"Failed to generate e-stamp paper: {e}")
        logging.error(f"Response: {response.json()}")
        raise


def SendForSignature(request_id, oauth):
    url = f"https://sign.zoho.in/api/v1/requests/{request_id}/submit"

    headers = {"Authorization": f"Zoho-oauthtoken {oauth}"}

    try:
        response = retry(requests.post, retries=2, url=url, headers=headers)
        response.raise_for_status()
        logging.info("Document sent for signature successfully.")
    except requests.exceptions.RequestException as e:
        send_email(str(e))
        logging.error(f"Failed to send document for signature: {e}")
        logging.error(f"Response: {response.json()}")
        raise


def orchestrator(
    employeeName,
    employeeEmail,
    employeePAN,
    street_address,
    city,
    state,
    pincode,
    country,
    StampRequired,
):
    try:
        oauth = retry(get_access_token, retries=2)
        logging.info(f"Access Token: {oauth}")

        document_id, request_id = retry(
            create_document,
            retries=2,
            employeeName=employeeName,
            employeeEmail=employeeEmail,
            oauth=oauth,
        )

        if StampRequired == "Y":
            StampResponse = retry(
                generate_estamp,
                retries=2,
                request_id=request_id,
                document_id=document_id,
                employeePAN=employeePAN,
                second_party_name=employeeName,
                street_address=street_address,
                city=city,
                state=state,
                pincode=pincode,
                country=country,
                oauth=oauth,
            )
            if StampResponse == 200:
                retry(SendForSignature, retries=2, request_id=request_id, oauth=oauth)
        else:
            retry(SendForSignature, retries=2, request_id=request_id, oauth=oauth)
    except Exception as e:
        send_email(str(e))
        logging.error(f"Orchestrator failed: {e}")


def send_email(message_body):
    port = 587
    smtp_server = "smtp.zeptomail.com"
    username = "emailapikey"
    password = ZEPTOPASSWORD
    sender_email = "hr@mnivesh.niveshonline.com"

    msg = MIMEMultipart()
    msg["From"], msg["To"], msg["Subject"] = (
        sender_email,
        "hr@niveshonline.com",
        "NDA Generation Error",
    )

    # Ensure message_body is a string
    if not isinstance(message_body, str):
        message_body = str(message_body)

    msg.attach(MIMEText(message_body, "html"))

    try:
        with smtplib.SMTP(smtp_server, port) as server:
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        logging.error(f"Failed to send email: {e}")


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Processing Employee NDA request")
    try:
        req_body = req.get_json()
        employeeFName = req_body.get("employeeFName")
        employeeLName = req_body.get("employeeLName")
        employeeEmail = req_body.get("employeeEmail")
        employeePAN = req_body.get("employeePAN")
        street_address = req_body.get("street_address")
        city = req_body.get("city")
        state = req_body.get("state")
        pincode = req_body.get("pincode")
        country = req_body.get("country")
        StampRequired = req_body.get("StampRequired", "Y")
        employeeName = employeeFName + " " + employeeLName
        logging.info(employeeName)
        logging.info(employeeEmail)
        logging.info(employeePAN)
        logging.info(street_address)
        logging.info(city)
        logging.info(state)
        logging.info(pincode)
        logging.info(country)
        logging.info(StampRequired)

        logging.info(f"Received request for employee: {employeeName}")

        if not all(
            [
                employeeName,
                employeeEmail,
                employeePAN,
                street_address,
                city,
                state,
                pincode,
                country,
            ]
        ):
            logging.error("Missing one or more required parameters.")
            send_email("Missing one or more required parameters.")
            return func.HttpResponse(
                "Missing one or more required parameters.", status_code=400
            )

        retry(
            orchestrator,
            retries=2,
            employeeName=employeeName,
            employeeEmail=employeeEmail,
            employeePAN=employeePAN,
            street_address=street_address,
            city=city,
            state=state,
            pincode=pincode,
            country=country,
            StampRequired=StampRequired,
        )
        return func.HttpResponse("Process completed successfully.", status_code=200)
    except Exception as e:
        logging.error(f"Process failed: {e}")
        send_email(str(e))
        return func.HttpResponse(f"Process failed: {e}", status_code=500)
