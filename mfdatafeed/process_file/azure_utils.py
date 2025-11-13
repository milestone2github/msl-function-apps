# Azure Imports
from datetime import datetime, timedelta
from time import timezone
import traceback
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

from process_file.config import get_vault_name
from process_file.logger_utils import log_custom

failure_counters = {"gmail_api": 0, "azure_key_vault": 0, "mongodb": 0, "blob_storage": 0}

vault_name = get_vault_name()

# Azure Key Vault Functions
def get_secret(vault_name, secret_name) -> str | None:
  try:
    log_custom("debug", f"Fetching secret '{secret_name}' from Key Vault '{vault_name}'")
    key_vault_uri = f"https://{vault_name}.vault.azure.net"
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_uri, credential=credential)
    secret = client.get_secret(secret_name)
    log_custom("info", f"Successfully fetched secret '{secret_name}'")
    return secret.value
  except Exception as e:
    failure_counters["azure_key_vault"] += 1
    log_custom("error", f"Error fetching secret '{secret_name}': {e}")
    raise

# Fetch azure blob connection string
def get_blob_connection_string():
  blob_connection_string = get_secret(vault_name, "blob-Storage-Connection-String")
  return blob_connection_string

# Fetch Azure Decrypt Key
def get_decrypt_key():
  decrypt_key = get_secret(vault_name, "ZipPasswords")
  return decrypt_key

# Initialize Azure Blob Storage
def get_azure_blob_client():
  blob_connection_string = get_blob_connection_string()
  if not blob_connection_string:
    raise ValueError("Missing Azure Blob connection string")
  blob_service_client = BlobServiceClient.from_connection_string(blob_connection_string)
  return blob_service_client

# Check/Create Azure Container
def check_azure_container(blob_service_client):
  containers = ["processed-files", "unsupported-files"]
  for container_name in containers:
    container_client = blob_service_client.get_container_client(container_name)
    if not container_client.exists():
      container_client.create_container()
      log_custom("info", f"✅ Created container: {container_name}")


# Store Decrypted and Valid Files to Azure
def store_decrypted_files(blob_service_client, container_name, decrypted_filename, content):
  """
  Stores valid, decrypted files in a separate Azure Blob Storage container.

  Args:
    blob_service_client (obj): Azure Blob Service Client.
    container_name (str): Name of the container for valid files.
    decrypted_filename (str): Name of the valid file to store.
    content (bytes): File content.
  """
  try:
    log_custom("info", f"Uploading valid file '{decrypted_filename}' to blob storage.")
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=decrypted_filename)
    blob_client.upload_blob(content, overwrite=True)

    log_custom("info", f"Decrypted file '{decrypted_filename}' stored successfully.")

  except Exception as e:
    log_custom("error", f"Failed to upload decrypted file '{decrypted_filename}': {e}")
    print(traceback.format_exc())

# Store Unsupportive File to Azure
def store_unsupported_file(blob_service_client, container_name, filename, content):
  """
  Stores unsupported files in a separate Azure Blob Storage container.
  A TTL (Time-to-Live) policy is applied for 48 hours.

  Args:
    blob_service_client (obj): Azure Blob Service Client.
    container_name (str): Name of the container for unsupported files.
    filename (str): Name of the file to store.
    content (bytes): File content.
  """
  try:
    log_custom("info", f"Storing unsupported file '{filename}' in container '{container_name}'.")
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=filename)
    blob_client.upload_blob(content, overwrite=True)    
    
    # Set a TTL of 48 hours
    # expire_time = (datetime.utcnow() + timedelta(hours=48)).isoformat()
    expire_time = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
    blob_client.set_blob_metadata({"expiration": expire_time})
    
    log_custom("info", f"Unsupported file '{filename}' stored. It will be auto-deleted after 48 hours.")

  except Exception as e:
    log_custom("error", f"Failed to store unsupported file '{filename}': {e}")
    print(traceback.format_exc())