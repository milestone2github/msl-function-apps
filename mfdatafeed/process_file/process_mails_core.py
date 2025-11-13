from process_file.email_utils import fetch_emails_with_criteria, process_and_upload_file
from process_file.logger_utils import log_custom, log_final_summary, log_summary_results
from process_file.azure_utils import check_azure_container, get_azure_blob_client, get_decrypt_key
from process_file.mongo_utils import get_mongo_client
from process_file.zoho_auth import get_zoho_auth
from process_file.zoho_utils import get_zoho_service

# Main function
def process_mails_core(run_start_time):
  days_to_fetch = 3 # Set custom if required
  
  # Zoho Auth imports
  access_token, account_id = get_zoho_auth()
  zoho_service_header = get_zoho_service(access_token)

  # MongoDB Connection imports
  MONGO_CLIENT, db = get_mongo_client()
  decrypt_key = get_decrypt_key()
  blob_service_client = get_azure_blob_client()

  # print(f"Decryption Key: --> {decrypt_key}") # debug
  
  # Fetch Emails from ZOHO API -- Process-01
  emails_cams = fetch_emails_with_criteria(zoho_service_header, "donotreply@camsonline.com", days_to_fetch, "CAMS", MONGO_CLIENT, db, account_id)
  emails_kfintech = fetch_emails_with_criteria(zoho_service_header, "distributorcare@kfintech.com", days_to_fetch, "Kfintech", MONGO_CLIENT, db, account_id)

  # Log email results
  log_custom("info", f"Fetched Emails: CAMS ({len(emails_cams)})")
  log_custom("info", f"Fetched Emails: KFintech ({len(emails_kfintech)})")
  
  # Logs incoming sample data if any exists
  if emails_cams:
    log_custom("debug", f"CAMS sample {emails_cams[0]}")
  if emails_kfintech:
    log_custom("debug", f"emails_kfintech sample {emails_kfintech[0]}")

  # Check whether required containers exists in Azure storage
  check_azure_container(get_azure_blob_client())

  # Process CAMS Emails with Attachments or Links: -- Process-02
  for email in emails_cams:
    process_and_upload_file(email, blob_service_client, db, "processed-files", "unsupported-files", zoho_service_header, decrypt_key, access_token, account_id)

  # Process KFintech Emails with Attachments or Links:
  for email in emails_kfintech:
    # process_kfintech_email(email, blob_service_client, db, "processed-files", decrypt_key, "Kfintech", access_token)
    process_and_upload_file(email, blob_service_client, db, "processed-files", "unsupported-files", zoho_service_header, decrypt_key, access_token, account_id)

  log_custom("info", f"Finished processing all emails.")
  
  # Retry Previously Failed Emails:
  # retry_failed_emails(blob_service_client, db, "processed-files", "unsupported-files", zoho_service_header, decrypt_key, access_token)

  log_custom("info", f"Finished processing all emails.")

  # Log Final Processing Summary:
  log_summary_results()
  log_custom("info", "--------------------------")
  log_final_summary(db, run_start_time)