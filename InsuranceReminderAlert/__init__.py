from pymongo import MongoClient, IndexModel, ASCENDING
import pytz
from datetime import datetime, timedelta
import requests
import json
import logging
import pandas as pd
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


# Set up logging
logging.basicConfig(level=logging.INFO)

# API Credentials and Endpoints
# WATI Credentials
WATI_API_URL = get_secret_from_vault("wati-url-mApi")
WATI_KEY = get_secret_from_vault("wati-key-mApi")
WATI_API_KEY = f"Bearer {WATI_KEY}"

# Zoho Credentials
zoho_client = json.loads(get_secret_from_vault("zoho-credentials-mApi"))
ZOHO_CLIENT_ID = zoho_client.get("client_id", "")
ZOHO_CLIENT_SECRET = zoho_client.get("client_secret", "")
ZOHO_REFRESH_TOKEN = zoho_client.get("refresh_token", "")

# Function to send WhatsApp messages
def send_InsuranceReminder_via_api(
    name, formatted_product_name, product, date, mobile_number
):
    if product == "Motor Insurance":
        image = "https://niveshonline.com/public/images/WORKOUT-2.png"
    else:
        image = "https://niveshonline.com/public/images/HealthInsuranceRenewal.png"

    url = f"{WATI_API_URL}/api/v1/sendTemplateMessage?whatsappNumber={mobile_number}"

    payload = {
        "template_name": "insurance_renewal_reminder4",
        "broadcast_name": "InsuranceAlert",
        "parameters": [
            {"name": "image", "value": image},
            {"name": "name", "value": name},
            {"name": "type", "value": formatted_product_name},
            {"name": "date", "value": date},
        ],
    }

    headers = {
        "content-type": "application/json",
        "Authorization": WATI_API_KEY,
    }

    try:
        response = requests.post(url, json=payload, headers=headers)
        logging.info(
            f"Message sent to {mobile_number}. Response: {response.status_code}"
        )
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to send request: {e}")

    return response


# Function to get access token from Zoho
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
        logging.info("Successfully obtained access token.")
        return zoho_access_token
    else:
        logging.error("Failed to get access token.")
        logging.error(f"Response: {response.json()}")
        raise Exception("Failed to get access token.")


# Function to fetch data from Zoho CRM
def get_Insurance_reminder_data(access_token):
    HEADERS = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    url = "https://www.zohoapis.com/crm/v6/Insurance_Leads"
    params = {
        "fields": "Name,Renewal_Date,Renewal_Product_Name,Product,Phone",
        "cvid": "2969103000329561151",
        "per_page": 200,
        "page": 1,
    }

    all_reminders = []  # List to store all users across pages
    while True:
        response = requests.get(url, headers=HEADERS, params=params)
        if response.status_code == 200:
            data = response.json()
            logging.info("Zoho CRM data retrieved successfully.")
            all_reminders.extend(data["data"])

            if not data["info"]["more_records"]:
                break

            params["page"] += 1
        else:
            logging.error(f"Failed to fetch Zoho CRM users: {response.json()}")
            raise Exception(f"Failed to fetch Zoho CRM users: {response.json()}")

    df_reminders = pd.DataFrame(all_reminders)
    logging.info("Converted data to DataFrame successfully.")
    return df_reminders


# Function to process data
def process_data(df):
    def format_product(row):
        if row["Product"] in ["Motor Insurance", "Miscellaneous Insurance"]:
            product = row["Renewal_Product_Name"]
        else:
            product = f"{row['Renewal_Product_Name']} {row['Product']}"
        # Remove the word "Insurance" and strip extra spaces
        product = product.replace("Insurance", "").strip()
        # Replace multiple spaces with a single space
        product = " ".join(product.split())
        return product

    def format_name(name):
        return name.split()[0].capitalize()

    def format_date(date_str):
        if pd.isnull(date_str):
            return None
        return datetime.strptime(date_str, "%Y-%m-%d").strftime("%d-%b-%Y")

    def format_waid(phone):
        if len(phone) == 10 and phone.isdigit():
            return f"91{phone}"
        return phone

    # Apply transformations
    df["Formatted_Product_Name"] = df.apply(format_product, axis=1)
    df["Name"] = df["Name"].apply(format_name)
    df["Renewal_Date"] = pd.to_datetime(df["Renewal_Date"])
    df["waid"] = df["Phone"].apply(format_waid)

    # Filter columns
    df = df[["Name", "Renewal_Date", "Formatted_Product_Name", "waid", "Product"]]

    return df


# Orchestrator function
def orchestrator():
    try:
        access_token = get_access_token()
        insurance_df = get_Insurance_reminder_data(access_token)
        insurance = process_data(insurance_df)

        # Define the intervals for sending reminders
        intervals_before = [
            -7,
            -4,
            -2,
            0,
        ]  # 7 days before, 4 days before, 2 days before, same day
        intervals_after = [
            1,
            3,
            5,
            7,
        ]  # 1 day after, 3 days after, 5 days after, 7 days after

        # Get the current date in IST
        ist = pytz.timezone("Asia/Kolkata")
        current_date = datetime.now(ist).date()

        # Trigger WhatsApp message for each entry
        for index, row in insurance.iterrows():
            renewal_date = row["Renewal_Date"].date()

            # Check reminders before and on the renewal date
            for interval in intervals_before:
                reminder_date = renewal_date + timedelta(days=interval)
                if reminder_date == current_date:
                    send_InsuranceReminder_via_api(
                        name=row["Name"],
                        formatted_product_name=row["Formatted_Product_Name"],
                        product=row["Product"],
                        date=row["Renewal_Date"].strftime("%d-%b-%Y"),
                        mobile_number=row["waid"],
                    )

            # Check reminders after the renewal date if the product is Health Insurance
            if row["Product"] == "Health Insurance":
                for interval in intervals_after:
                    reminder_date = renewal_date + timedelta(days=interval)
                    if reminder_date == current_date:
                        send_InsuranceReminder_via_api(
                            name=row["Name"],
                            formatted_product_name=row["Formatted_Product_Name"],
                            product=row["Product"],
                            date=row["Renewal_Date"].strftime("%d-%b-%Y"),
                            mobile_number=row["waid"],
                        )

    except Exception as e:
        logging.error(f"An error occurred: {e}")


# Main function for Azure Timer Trigger
def main(mytimer: func.TimerRequest) -> None:
    orchestrator()


# If you want to run this script directly
if __name__ == "__main__":
    orchestrator()
