from hashlib import sha256
import io
import json
import os
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import re
import pyzipper
import requests
from bs4 import BeautifulSoup
import urllib
from urllib.parse import parse_qs, unquote, urlparse
from typing import List, Optional

from process_file.azure_utils import get_decrypt_key, store_decrypted_files, store_unsupported_file
from process_file.logger_utils import log_custom, log_summary
from azure.core.exceptions import HttpResponseError

CAMS_ZIP_PATTERN = re.compile(r"https://.*\.camsonline\.com/.*\.zip")

########################################################
# Update Metadata in MongoDB -- Generic
########################################################

def update_email_metadata(db, email, Status, checksum=None, source_type=None, decrypted_filename=None, error=None):
  """
  Standardized MongoDB update for both CAMS and KFintech.

  Parameters:
  - db: MongoDB collection reference.
  - email: Dictionary containing email metadata.
  - Status: The processing status of the email ("processed", "failed", etc.).
  - checksum: Checksum of the decrypted file (if available).
  - source_type: Source of the file ("link" or "attachment").
  - decrypted_filename: Name of the decrypted file stored in blob (if available).
  - error: Error message in case of failure (if applicable).
  """

  message_id = email.get("message_id")
  attachments = email.get("attachments", [])
  zipped_link = email.get("zip_links", [])
  subject = email.get("subject")
  received_date = email.get("received_date")
  RTAType = email.get("RTAType")
  FileFormat = email.get("FileFormat")

  # Determine the source type if not explicitly provided
  if source_type is None:
    if zipped_link:
      source_type = "Link"
    elif attachments:
      source_type = "Attachment"
    else:
      source_type = "Undefined"

  # Reset error field if status is not "Failed"
  if Status.lower() != "failed":
    error = None

  # Build metadata dictionary
  metadata = {
    "messageId": message_id,
    "FileFormat": FileFormat,
    "RTAType": RTAType,
    "received_date": received_date,
    "subject": subject,
    "Status": Status,
    # "ProcessingTimeStamp": datetime.utcnow().isoformat(),
    "ProcessingTimeStamp": datetime.now(timezone.utc).isoformat(),
    "decrypted": True if Status.lower() == "processed" else False,  # Mark decrypted only on success
    "decryptedFilename": decrypted_filename,
    "sourceType": source_type,  
    "zip_links": zipped_link if zipped_link else None,  
    "attachments": attachments if attachments else None,  
  }

  # Add optional fields only if they have values
  if checksum:
    metadata["checksum"] = checksum
  if error:
    metadata["Error"] = error

  # Use $set to only update necessary fields, avoiding redundant writes
  db.update_one(
    {"messageId": message_id},
    {"$set": metadata},
    upsert=True
  )

  log_custom("info", f"MongoDB updated for Message ID: {message_id} with status: {Status}")

########################################################
# Links Extraction and Cleaning Function -- Process-01
########################################################

def extract_and_validate_links(RTAType: str, email_content: str) -> list[str]:
    """
    Unified function to extract and clean CAMS or KFintech links.
    Returns a list of validated links.
    """

    validated_links = []

    try:
        # Extract both raw text links and <a href> links
        all_links = re.findall(r'(https?://\S+)', email_content)
        soup = BeautifulSoup(email_content, "html.parser")
        all_links.extend([a["href"] for a in soup.find_all("a", href=True)])

        if RTAType.lower() == "cams":
            for link in all_links:
                if CAMS_ZIP_PATTERN.match(link):
                    # Clean CAMS link
                    cleaned = re.sub(r'(</a.*?>)$', '', link.strip(), flags=re.IGNORECASE)
                    cleaned = re.sub(r"[\"'>]+$", "", cleaned)  # fallback cleanup -- required step
                    validated_links.append(cleaned)

        elif RTAType.lower() == "kfintech":
            for link in all_links:
                decoded_link = urllib.parse.unquote(link)
                if "scdelivery.kfintech.com/c/?" in decoded_link:
                    # Decode 'u' param if present (Caesar -1 shift)
                    parsed_url = urlparse(decoded_link)
                    query_params = parse_qs(parsed_url.query)
                    if "u" in query_params:
                        encoded_u = query_params["u"][0]
                        shifted = ''.join(chr(ord(c) - 1) for c in unquote(encoded_u))
                        shifted = shifted.replace(">", "").replace(" ", "")
                        cleaned = f"https://scdelivery.kfintech.com/c/?u={shifted}"
                        validated_links.append(cleaned)
                    else:
                        validated_links.append(decoded_link)

        else:
            pass  # unsupported RTA

    except Exception as e:
        print(f"Error extracting links: {e}")  # replace with log_custom if needed

    return validated_links

#######################################################################################
# Process the Attachments: Decrypt and Validate content (in memory) -- Process-02
#######################################################################################

# Check if file extensions are valid
def is_valid_content(content: bytes, filename: str) -> bool:
    """Basic validation for extracted file types."""
    ext = os.path.splitext(filename)[1].lower()
    if ext == '.dbf':
        return len(content) > 0 and content[0] in (0x02, 0x03)
    elif ext == '.xls':
        return content.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1')
    elif ext == '.csv':
        try:
            decoded = content.decode('utf-8')
            return len(decoded.strip()) > 0 and (',' in decoded or '\t' in decoded or ';' in decoded)
        except UnicodeDecodeError:
            return False
    elif ext == '.aspx':
        return len(content) > 0
    else:
        return len(content) > 0

# Compute SHA-256 checksum for file integrity verification
def compute_checksum(file_data):
    checksum = sha256(file_data).hexdigest()
    log_custom("debug", f"Computed checksum: {checksum}")
    return checksum

''' # REDUNDANT -- To-Do: CURRENTLY NOT GETTING USED BUT SHOULD BE INTEGRATED AFTER DOWNLOADING AND EXTRACTING FILES
def verify_checksum(file_data, expected_checksum):
    return compute_checksum(file_data) == expected_checksum
'''

# Decrypt the file
def decrypt_zip_attachment(att_bytes: bytes, passwords: Optional[List[str]] = None) -> list:
    """
    Unzips in-memory and optionally decrypts using a list of passwords.
    Handles both standard and AES-encrypted ZIPs.
    Returns a list of dicts: {"filename": str, "file_bytes": bytes}.
    """
    files_data = []
    
    if passwords:
        for pwd in passwords:
            zip_bytes = io.BytesIO(att_bytes)  # reset for each try
            try:
                with pyzipper.AESZipFile(zip_bytes) as zf:
                    zf.pwd = pwd.encode()
                    for name in zf.namelist():
                        files_data.append({"filename": name, "file_bytes": zf.read(name)})
                    return files_data  # success
            except (RuntimeError, pyzipper.zipfile.BadZipFile):
                log_custom("warning", f"Wrong password '{pwd}' or invalid ZIP. Trying next...")
                continue
        log_custom("error", "None of the provided passwords worked.")
        raise RuntimeError("Failed to decrypt ZIP with provided passwords.")
    else:
        with pyzipper.AESZipFile(io.BytesIO(att_bytes)) as zf:
            for name in zf.namelist():
                files_data.append({"filename": name, "file_bytes": zf.read(name)})

    return files_data

#######################################################################
# Download helpers (Being used in Processing functions) -- Process-02
#######################################################################

def download_and_process_attachments(
    service_headers,
    account_id=None,
    folder_id=None,
    message_id=None,
    attachment_id=None,
    attachment_name=None,
    zip_passwords=[],
    url=None
) -> tuple[list, list]:
    """
    Download and process/decrypt attachments or linked files.
    Returns a tuple: (valid_files, invalid_files)
    - valid_files: [{filename, file_bytes, checksum}]
    - invalid_files: [{filename, file_bytes, reason}]
    """
    try:
        # --- Source selection ---
        if url:
            resp = requests.get(url, stream=True, timeout=30, verify=False)
        else:
            if not all([account_id, folder_id, message_id, attachment_id]):
                raise ValueError("Missing required parameters for Zoho attachment download")
            zoho_url = f"https://mail.zoho.com/api/accounts/{account_id}/folders/{folder_id}/messages/{message_id}/attachments/{attachment_id}"
            resp = requests.get(zoho_url, headers=service_headers)

        resp.raise_for_status()
        file_bytes = resp.content

        if not file_bytes:
            log_custom("warning", f"Empty file for messageId {message_id or url}")
            return [], []

        checksum = compute_checksum(file_bytes)
        filename = attachment_name or os.path.basename(urlparse(url).path)

        valid_files, invalid_files = [], []

        # --- Plaintext files ---
        # if filename and not (filename.endswith(".zip") or filename.endswith(".tar.gz")):  # REDUNDANT
        if filename and not (filename.endswith(".zip")):
            if not is_valid_content(file_bytes, filename):
                log_custom("warning", f"Invalid content in plaintext file '{filename}'")
                invalid_files.append({"filename": filename, "file_bytes": file_bytes, "reason": "invalid_plaintext"})
            else:
                log_custom("info", f"File '{filename}' is plaintext, skipping decryption.")
                valid_files.append({"filename": filename, "file_bytes": file_bytes, "checksum": checksum})
            return valid_files, invalid_files

        # --- Encrypted ZIP ---
        try:
            file_list = decrypt_zip_attachment(file_bytes, zip_passwords)
            for f in file_list:
                if not is_valid_content(f["file_bytes"], f["filename"]):
                    log_custom("warning", f"Invalid content in extracted file '{f['filename']}'")
                    invalid_files.append({"filename": f["filename"], "file_bytes": f["file_bytes"], "reason": "invalid_zip"})
                else:
                    valid_files.append({
                        "filename": f["filename"],
                        "file_bytes": f["file_bytes"],
                        "checksum": compute_checksum(f["file_bytes"])
                    })
        except Exception as e:
            log_custom("error", f"Failed to unzip file '{filename}': {e}")
            invalid_files.append({"filename": filename, "file_bytes": file_bytes, "reason": "unzip_failed"})

        return valid_files, invalid_files

    except Exception as e:
        log_custom("error", f"Failed to download/process file: {e}")
        return [], [{"filename": attachment_name or "unknown", "file_bytes": b"", "reason": str(e)}]

########################################################
# Processing and Cleaning functions -- Process-01
########################################################

# Clean the aggregated data and returns a standard structure
def clean_email(email, RTAType, regex_map, db, folder_id, message_id):
    subject = email.get("subject", "No Subject")
    email_content = email.get("content", "")    # full message content
    attachments = email.get("attachments", [])  # store attachments object as is

    # print(f"EMAIL ATTACHMENT DETAILS : ==> {attachments}") # debug

    # Parse and group mails based on RegEx
    FileFormat = "unknown"

    if RTAType.lower() == "cams":
        match = re.match(r"^(WBR\d+[A-Z]*)\.", subject)
        FileFormat = match.group(1) if match else subject.split()[0].rstrip(".")
        # print(f"FileFormat data for CAMS: {FileFormat}") # debug
    elif RTAType.lower() == "kfintech":
        # Searching in body text for MFSD patterns
        matches = re.findall(r"MFSD\d{1,3}", email_content)
        if matches:
            unique_matches = list(set(matches))
            FileFormat = unique_matches[0] if len(unique_matches) == 1 else ", ".join(unique_matches)


    # Ensure the subject matches expected regex
    # if not compiled_regex_map.match(subject): # REDUNDANT CODE
    if FileFormat not in regex_map or not regex_map[FileFormat].match(subject):
        return None

    # Determine processing category
    existing_record = db.find_one({"messageId": message_id})
    if existing_record and existing_record.get("status") in ["processed", "not_found"]:
        log_custom("debug", f"Skipping email - already processed. MessageId: {message_id}, subject: {subject}")
        category = "Skipping"
    elif existing_record:
        log_custom("debug", f"Re-processing email. MessageId: {message_id}, subject: {subject}")
        category = "Re-processing"
    else:
        log_custom("debug", f"Processing new email. MessageId: {message_id}, subject: {subject}")
        category = "Processing"

    # Extract and validate links
    validated_links = extract_and_validate_links(RTAType, email_content)

    ''' # debug
    # if isinstance(validated_links, str):
    #     validated_links = [validated_links]
    # print(f"Validated Links Sample ===> {validated_links[:5]}") # debug
    '''

    ''' ## To-Do : CURRENTLY UNUSED, TO BE INTEGRATED WITH MAIN LOGGING LATER FOR IN-DEPTH LOGGING
    # logs
    log_summary = {
        category: {
            "links": [],
            "attachments": [],
            "general": [],
            "file_format": {}
        }
    }

    # Categorize the status in log_summary
    if validated_links:
        log_summary[category]["links"].append((message_id, subject))
    elif attachments:
        log_summary[category]["attachments"].append((message_id, subject))
    else:
        log_summary[category]["general"].append((message_id, subject))

    # Track file format grouping
    if FileFormat:
        if FileFormat not in log_summary[category]["file_format"]:
            log_summary[category]["file_format"][FileFormat] = {"Emails": []}
        log_summary[category]["file_format"][FileFormat]["Emails"].append((message_id, subject))
    '''

    # print(f"EMAIL ATTACHMENT DETAILS BEFORE OUTPUT : ==> {attachments}") # debug

    # Final output
    if validated_links or attachments:
        log_custom("info", "Validated_links or Attachments found... Creating a structured dict for downloading and processing...")
        output_dict = {
            "subject": subject,
            "message_id": message_id,
            "folder_id": folder_id,
            "RTAType": RTAType,
            "FileFormat": FileFormat,
            "zip_links": validated_links,
            "attachments": attachments,
        }
        # print(f"OUTPUT DICT STRUCTURE ---> {output_dict}") # debug
        return output_dict
    return None

# Aggregates the data from multiple APIs
def process_email(service_headers, account_id, msg, RTAType, regex_map, db):
    try:
        message_id = msg["messageId"]
        folder_id = msg["folderId"]

        # Store full META-DATA in JSON
        meta_url = f"https://mail.zoho.com/api/accounts/{account_id}/folders/{folder_id}/messages/{message_id}/details"
        meta_resp = requests.get(meta_url, headers=service_headers)
        meta_resp.raise_for_status()
        full_email_body = meta_resp.json().get("data", {})

        # Store the body content
        content_url = f"https://mail.zoho.com/api/accounts/{account_id}/folders/{folder_id}/messages/{message_id}/content"
        content_resp = requests.get(content_url, headers=service_headers)
        content_resp.raise_for_status()
        full_email_body["content"] = content_resp.json().get("data", {}).get("content", {})

        # Store Attachments info (all incoming mails have attachments -- this block is redundant) #TO-DO: ASK IF REQUIRED?
        has_attachment = full_email_body.get("hasAttachment")
        if has_attachment:
          attachment_url = f"https://mail.zoho.com/api/accounts/{account_id}/folders/{folder_id}/messages/{message_id}/attachmentinfo"
          attachment_resp = requests.get(attachment_url, headers=service_headers)
          attachment_resp.raise_for_status()
          full_email_body["attachments"] = attachment_resp.json().get("data", {}).get("attachments", {})
        #   print("ATTACHMENT EXISTS IN EMAIL BODY...") # debug

        # return clean_email(full_email_body, RTAType, compiled_regex_map, db, service_headers, account_id, folder_id, message_id)
        return clean_email(full_email_body, RTAType, regex_map, db, folder_id, message_id)
    except Exception as e:
        log_custom("error", f"Failed to fetch email ID {msg['messageId']}: {e}")
        return None

# RegEx Mapping of Subjects/Keywords (in DB) for prefix-matching of Email subjects
def get_subject_regex_map(MONGODB_CLIENT):
    try:
        db = MONGODB_CLIENT["DataFeed"]
        collection = db["FilesConfig"]
        cursor = collection.find({}, {"fileType": 1, "subject": 1, "_id": 0}).max_time_ms(5000)
        entries = list(cursor)
        if not entries:
            log_custom("error", "No valid subject regex patterns found in MongoDB.")
            return None, {}
        regex_map = {entry["fileType"]: re.compile(entry["subject"], re.IGNORECASE)
                     for entry in entries if "fileType" in entry and "subject" in entry}
        subject_patterns = [f"({entry['subject']})" for entry in entries if "subject" in entry]
        compiled_regex_map = re.compile("|".join(subject_patterns), re.IGNORECASE)
        return compiled_regex_map, regex_map    # Only regex_map being used currently
    except re.error as regex_err:
        log_custom("error", f"Regex compilation error: {regex_err}")
        return None, {}
    except Exception as e:
        log_custom("error", f"Error fetching regex from MongoDB: {e}")
        return None, {}

####################################################################
# Extract Clean Links and Attachments from E-Mails -- Process-01
####################################################################

def fetch_emails_with_criteria(service_headers, from_email, days_to_fetch, RTAType, MONGODB_CLIENT, db, account_id):
    try:
        # account_id = get_zoho_account_id(access_token)
        date_threshold = datetime.now() - timedelta(days=days_to_fetch)
        from_date = date_threshold.strftime("%d-%b-%Y")

        _, regex_map = get_subject_regex_map(MONGODB_CLIENT)
        if not regex_map:
            log_custom("warning", "Unable to fetch Regex_Map for proper Subject mappings.")
            return []

        # zoho_url = f"https://mail.zoho.com/api/accounts/{account_id}/messages/view"  # Another API to fetch email data but with different options
        zoho_url = f"https://mail.zoho.com/api/accounts/{account_id}/messages/search"
        params = {
        #   "searchKey": f'sender:{from_email}::has:attachment',    # fetch with attachments
          "searchKey": f"sender:{from_email}::fromDate:{from_date}",  # fetch all the messges coming from certain sender of certain period given
          "start": 1,
          "limit": 200,
        }
        response = requests.get(zoho_url, headers=service_headers, params=params)
        response.raise_for_status()
        data = response.json()
        email_list = data.get("data", [])
        total_emails = len(email_list)

        emails = {}
        processed_count = 0

        # test_list_set = email_list[:5]      # debug

        with ThreadPoolExecutor(max_workers=2) as executor:
            future_to_email = {
                executor.submit(process_email, service_headers, account_id, msg, RTAType, regex_map, db): msg
                for msg in email_list
                # for msg in test_list_set   # debug
            }
            for future in as_completed(future_to_email):
                email_data = future_to_email[future]
                try:
                    cleaned_email = future.result()
                    if cleaned_email:
                        emails[email_data["messageId"]] = cleaned_email
                except Exception as e:
                    log_custom("error", f"Failed to process email ID {email_data['messageId']}: {e}")
                processed_count += 1
                if processed_count % 50 == 0:
                    log_custom("info", f"Processed {processed_count}/{total_emails} emails")
        
        if RTAType.lower() == 'cams':
            log_custom("info", "CAMS Emails processed")
        elif RTAType.lower() == 'kfintech':
            log_custom("info", "KFintech Emails processed")

        return list(emails.values()) # Return the combined dict in list format for file downloading & uploading
    except Exception as e:
        log_custom("error", f"Error fetching emails: {e}")
        return []

########################################################
# Process and Upload Email Attachments -- Process-02
########################################################

def process_and_upload_file(email, blob_service_client, db, container_name, unsupported_container, service_headers, decrypt_key, access_token, account_id):
  """
  1. Processes an email attachment or linked file:
    - Downloads the file
    - Checks if already decrypted (avoiding redundant decryption)
    - Decrypts if needed
    - Checks file validity
    - Uploads valid files to Blob Storage
    - Stores unsupported files separately
    - Updates MongoDB with full email metadata (success, failure, or unsupported)
  """
  folder_id = email.get("folder_id")
  message_id = email.get("message_id")
  attachments = email.get("attachments", [])
  zipped_links = email.get("zip_links", [])

  decrypted_files = []     # valid files
  unsupported_files = []   # invalid/improper files
  zip_passwords = json.loads(get_decrypt_key()) # Fetch zip passwords from Azure Vault
  
  # Check for Zip_Passwords
  if not zip_passwords:
    log_custom("error", "Zip Passwords not available.")
    return

  # 1. Skip if already processed in MongoDB
  existing_entry = db.find_one({ "messageId": message_id, "status": "processed" })
  if existing_entry and existing_entry.get("decrypted", False):
    log_custom("info", f"Skipping decryption for already processed file: {existing_entry.get('decryptedFilename')}")
    return

  try:
    # 2. Process attachments
    for attachment in attachments or []:
      attachment_id = attachment.get("attachmentId")
      attachment_name = attachment.get("attachmentName")
      
      log_custom("info", f"Downloading attachment '{attachment_name}' for Message ID: {message_id}")
      valid_files, invalid_files = download_and_process_attachments(
        service_headers, account_id, folder_id, message_id, attachment_id, attachment_name, zip_passwords
      )
      decrypted_files.extend(valid_files)
      unsupported_files.extend(invalid_files)

    # 3. Process Zip_Links
    for link in zipped_links or []:
      log_custom("info", f"Downloading linked file for Message ID: {message_id}")
      valid_files, invalid_files = download_and_process_attachments(
        service_headers, account_id, folder_id, message_id, None,
        os.path.basename(urlparse(link).path), zip_passwords, url=link
      )
      decrypted_files.extend(valid_files)
      unsupported_files.extend(invalid_files)

    # 4. Nothing found
    if not decrypted_files and not unsupported_files:
      log_custom("warning", f"No attachments or links found for Message ID: {message_id}")
      update_email_metadata(
        db, email, "no_attachment_found", checksum=None,
        source_type=None, decrypted_filename=None, error=None
      )
      return

    # 5. Upload valid files
    for file_obj in decrypted_files:
      decrypted_filename = file_obj["filename"]
      decrypted_file_content = file_obj["file_bytes"]
      checksum = file_obj["checksum"]

      #Store the Valid files in Azure
      store_decrypted_files(blob_service_client, container_name, decrypted_filename, decrypted_file_content)
      # Update metadata in db
      update_email_metadata(
        db, email, "processed", checksum=checksum, source_type="attachment_or_link",
        decrypted_filename=decrypted_filename, error=None
      )
      log_custom("info", f"Successfully processed and uploaded: {decrypted_filename}")

    # 6. Handle unsupported/invalid files
    for file_obj in unsupported_files:
      unsupported_filename = file_obj["filename"]
      unsupported_file_content = file_obj["file_bytes"]
      unsupported_file_reason = file_obj["reason"]
      
      # Store the Invalid files in Azure
      store_unsupported_file(blob_service_client, unsupported_container, unsupported_filename, unsupported_file_content)
      # Update metadata in db
      update_email_metadata(
        db, email, "InvalidFile" if unsupported_file_reason == "invalid_plaintext" else "InvalidZip",
        checksum=None, source_type="attachment_or_link",
        decrypted_filename=file_obj["filename"], error=unsupported_file_reason
      )
      log_custom("warning", f"Stored unsupported file: {unsupported_filename} ({unsupported_file_reason})")

    log_custom("info", f"Successfully processed and uploaded: {decrypted_filename}")
  
  except HttpResponseError as e:
    if e.response and e.response.status_code == 404:
      update_email_metadata(db, email, "not_found", checksum=None, source_type=None, decrypted_filename=None, error=str(e))
    else:
      log_custom("warning", f"Error processing file '{attachment_name}': {e}", exc_info=True)
      update_email_metadata(db, email, "failed", checksum=None, source_type=None, decrypted_filename=None, error=str(e))

  except Exception as e:
    log_custom("error", f"Error processing email {message_id}: {e}")
    print(traceback.format_exc()) # prints full traceback separately
    update_email_metadata(
      db, email, "failed", checksum=None, source_type=None,
      decrypted_filename=None, error=str(e)
    )

###############
# END_OF_FILE
###############