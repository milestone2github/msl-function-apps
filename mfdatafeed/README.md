##### Steps to run the function locally:
- Download the full code
- Must have 'azurite' installed globally on local machine (`npm i -g azurite`)
- Create a Virtual Environment (py -m venv .venv) `for Windows`
- Start the environment (`./.venv/Scripts/activate`) {CLI MUST BE IN ROOT FOLDER BEFOREHAND} `for Windows`
- Install the dependencies (`pip install -r requirements.txt`)
- Start Azurite storage module (in a separate terminal window): just type `azurite` and press enter
- Start the project: `func start`

##### Entry Point:
- app_file -> process_file

##### File Structure:
- azure_utils.py : Azure clients, fetch functions for Vault data, Blob, Decryption Keys (Passwords), Storage
- config.py : Fetch vault_name from ENVIRONMENT FILE (in Azure)/local.settings.json (on local machine)
- email_utils.py : All the helper and main functions
- logger_utils.py : All the logging based logic
- mongo_utils.py : MongoDB client fetching, db collection fetching
- process_mails_core.py : Starting point of function logic
- zoho_auth.py : Aggregator function for Zoho credentials
- zoho_utils.py : All helper functions for `zoho_auth`

##### Function Logic:
- "process_mails_core.py": main function logic starts
  
  ###### Helper Functions:
  - get_zoho_auth() : Fetches the Zoho Credentials w/ Account_Id from Azure Vault
  - get_zoho_service() : Standard Zoho headers that allows token-based auth to API requests
  - get_azure_blob_client() : Azure Blob Client
  - check_azure_container() : Checks for existing containers named 'processed-files' and 'unsupported-files' on Azure, and if they doesn't exist, creates one
  - update_email_metadata() : Updates the DB for each successful and unsuccessful entries
  - get_subject_regex_map() : Gets a REGEX of mail subjects and fileType, returns the `regex_map`

  - clean_email() :
    - Compares the subject & it's fileFormat prefix with _regex\_map_ { "CAMS": `WBR...` , "KFINTECH": `MFSD...` }
    - Checks for the email status if processed before in DB
    - Extracts the links from email's message content and returns a list of all extracted Links (using _extract\_and\_validate\_links()_)
    - Structures the output with relevant fields and extracted URLs and Attachment Info

  - extract_and_validate_links() :
    - Creates a single list of validated_links for both CAMS and KFINTECH
    - Extracts the URL of .ZIP files (for CAMS), and names prefixing 'scdelivery..' (for KFINTECH) from email's body content

  - decrypt_zip_attachment() : Takes the list of passwords fetched from Azure Vault and tries them one-by-one to each of the .zip file

  compute_checksum() : Extracts the file's checksum and stores with the processed files

  - store_decrypted_files() : Store the Valid extracted & processed files to Azure
  - store_unsupported_file() : Store the Invalid extracted & processed files to Azure, with 48 hours TTL


  ###### Main Functions:
  - fetch_emails_with_criteria() :
    - Processses the mails of last x days from today using _2 thread workers_ at a time
    - Max 200 Entries at a time allowed
    - Extracts the Links from within the mail-body content
    - cleans and structurizes the data

    - process_email() :
      - Downloads the email's metadata, message content, and attachmentinfo
      - Sends to clean_email() for link and attachment details extraction
      - Returns a structured dictionary of email's data with all required fields included

  - process_and_upload_file() :
    - Takes in each structured mail-data fetched from fetch_emails_with_criteria()
    - Downloads the file -> decryption -> extraction -> segregation in `decrypted_files (valid_files)` and `unsupported_files (invalid_files)`
    - Uploading to Azure using _blob\_client_
    - Logging success and errors to DB using _update\_email\_metadata()_

    - download_and_process_attachments() :
      - Returns processed, aggregated files and segregated into valid_files and invalid_files
      - Check for certain extensions if filename _doesn't ends with .zip extension_ (using _is\_valid\_content()_) -> Add to invalid_files
      - Add files with filename that _ends with .zip extension_ in valid_files
      - Handle plaintext files by adding them in `invalid_files`
      - Try decryption to all the valid_files (using _decrypt\_zip\_attachment()_), trying all the stored passwords -> Check for valid content inside the extracted file (using _is\_valid\_content()_) -> Add each of the valid and invalid files with checksum and formal structure `{ filename: ... , file_bytes: ... , checksum: ... }` -> Returns the aggregated `valid_files` and `invalid_files`
    
    - Perform the _download\_and\_process\_attachments()_ operation for CAMS (attachments and embedded links) and KFINTECH (attachments and embedded links) -> Store the data in `decrypted_files` and `unsupported_files`
    - Upload the data to Azure Blob Storage (using _store\_decrypted\_files()_ and _store\_unsupported\_file()_)
    - Update the DB (using _update\_email\_metadata()_) -> Print Logs in Console


---

##### PROCESS EXCEPTIONS: (as-on 15-Sept-2025)
- `ZipPasswords` are wrong for some and not valid all of the files
- All urls are extracted from kfintech without strict `.zip` extension checking (*in `extract_and_validate_links()`*)
- `NIGO` fileType should be added in `Datafeed -> FilesConfig` DB to extract `.zip` files for some CAMS mails
- CAMS email attachments aren't getting processed to download function even though there exists an attachment with that email if the name have extension other than `.zip`
- Commented the `retry_failed_emails()` due to the nature of function being recurring after certain intervals, and no `retry` field being set in DB currently that actually triggers this function execution

---