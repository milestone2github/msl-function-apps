import os
from mfdatafeed.logger_utils import log_custom
from dotenv import load_dotenv
load_dotenv()


# Fetch vault name
vault_name = os.getenv("KEYVAULT_NAME")
def get_vault_name() -> str:
  if not vault_name:
    raise ValueError("KEYVAULT_NAME not set in environment")
  return vault_name