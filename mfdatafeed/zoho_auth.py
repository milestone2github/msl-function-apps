
from mfdatafeed.config import get_vault_name
from mfdatafeed.zoho_utils import get_zoho_credentials, refresh_zoho_access_token


def get_zoho_auth():
    vault_name = get_vault_name()
    zoho_creds = get_zoho_credentials(vault_name)
    access_token = refresh_zoho_access_token(zoho_creds)
    account_id = zoho_creds["account_id"]

    print(f"access_token generated: ==> {access_token}")    # debug

    return access_token, account_id