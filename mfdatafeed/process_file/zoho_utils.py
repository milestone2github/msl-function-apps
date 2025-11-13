import json
import time

import requests

from process_file.azure_utils import get_secret
from process_file.logger_utils import log_custom

# Fetch Zoho Credentials from Azure Vault
def get_zoho_credentials(vault_name):
  secret = get_secret(vault_name, "Zoho-Credentials-Process-Files")
  if not secret:
    raise ValueError("Zoho-Credentials secret is missing")
  credentials = json.loads(secret)
  return credentials

# Fetch Access-Token from Zoho-Credentials
def refresh_zoho_access_token(creds):
  log_custom("info", "Refreshing Zoho access token")
  url = "https://accounts.zoho.com/oauth/v2/token"
  params = {
    "refresh_token": creds["refresh_token"],
    "client_id": creds["client_id"],
    "client_secret": creds["client_secret"],
    "grant_type": "refresh_token"
    # "redirect_uri": creds["redirect_uri"],
  }

  response = requests.post(url, params=params)
  if response.status_code != 200:
    raise Exception(f"Failed to refresh Zoho token: {response.text}")

  token_data = response.json()
  log_custom("info", f"Access Token fetched : {token_data["access_token"]}")
  return token_data["access_token"]

# Zoho Headers for API calls
def get_zoho_service(access_token):
  return {
    "Authorization": f"Zoho-oauthtoken {access_token}",
    "Content-Type": "application/json"
  }

'''
# REDUNDANT CODE
# Fetch Zoho Account_Id
def get_zoho_account_id(access_token):
  url = "https://mail.zoho.com/api/accounts"
  headers = {
    "Authorization": f"Zoho-oauthtoken {access_token}"
  }
  resp = requests.get(url, headers=headers)
  resp.raise_for_status()
  accounts = resp.json().get("data", [])
  if not accounts:
    raise Exception("No Zoho Mail accounts found")
  return accounts[0]["accountId"]
'''

# Fetch attachment from Zoho Mail API with retries
def safe_zoho_mail_attachment_request(headers, account_id, message_id, attachment_id, max_retries=3):
  """
  Fetches an email attachment from Zoho Mail API.
  account_id: Zoho Mail account ID
  message_id: Email message ID
  attachment_id: Attachment ID in the message
  """
  url = f"https://mail.zoho.com/api/accounts/{account_id}/messages/{message_id}/attachments/{attachment_id}"

  for attempt in range(max_retries):
    try:
      log_custom("info", f"Fetching attachment for message ID '{message_id}', attempt {attempt+1}/{max_retries}")
      resp = requests.get(url, headers=headers)

      if resp.status_code == 200:
        return resp.content  # This is binary data
      else:
        raise Exception(f"HTTP {resp.status_code}: {resp.text}")

    except Exception as e:
      log_custom("error", f"Attempt {attempt+1} failed: {e}")
      if attempt < max_retries - 1:
        time.sleep(2 ** attempt)
      else:
        raise