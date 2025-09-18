Employee NDA Generator (Azure Function - HTTP Trigger)
------------------------------------------------------

Purpose:
- Creates and sends an employee NDA via Zoho Sign, with optional e-stamping; retries on transient failures and emails error details on failure.

Secrets:
- Pulled from Azure Key Vault:
  - zepto-password-mApi (SMTP password)
  - zoho-credentials-mApi (JSON: client_id, client_secret, refresh_token)

Behavior:
- OAuth: Exchanges Zoho refresh token for access token.
- Document: Creates Zoho Sign document from a predefined template and assigns signers (Employee → Director → HR).
- E-Stamp (optional): Adds stamp details (state, amount, parties, IDs, addresses).
- Submission: Submits request for signature.
- Error handling: Retries selected API calls; sends error email on failure.

Inputs (JSON body; all required unless noted):
- employeeFName
- employeeLName
- employeeEmail
- employeePAN
- street_address
- city
- state
- pincode
- country
- StampRequired (default "Y")

Outputs:
- 200: "Process completed successfully."
- 400: Missing one or more required parameters.
- 500: Process failed (error message returned).

Notes:
- Sends error notifications via ZeptoMail SMTP to hr@niveshonline.com.
- Logs key input fields for traceability.

-------------------------------------------------
Example Requests
-------------------------------------------------

HTTP:
POST /api/<function>
Content-Type: application/json

{
  "employeeFName": "Asha",
  "employeeLName": "Verma",
  "employeeEmail": "asha.verma@example.com",
  "employeePAN": "ABCDE1234F",
  "street_address": "221B Baker Street",
  "city": "Mumbai",
  "state": "MH",
  "pincode": "400001",
  "country": "India",
  "StampRequired": "Y"
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{
    "employeeFName":"Asha",
    "employeeLName":"Verma",
    "employeeEmail":"asha.verma@example.com",
    "employeePAN":"ABCDE1234F",
    "street_address":"221B Baker Street",
    "city":"Mumbai",
    "state":"MH",
    "pincode":"400001",
    "country":"India",
    "StampRequired":"Y"
  }'
