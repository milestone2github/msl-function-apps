Deal Email Sender (Azure Function - HTTP Trigger)
-------------------------------------------------

Purpose:
- Sends transactional emails to buyers or sellers using ZeptoMail templates, with amount formatted in Indian numbering style.

Secrets:
- Pulled from Azure Key Vault:
  - zoho-auth-key-mApi (ZeptoMail API auth header)
  - seller-mailId-mApi (ZeptoMail template key for Seller)
  - buyer-mailId-mApi  (ZeptoMail template key for Buyer)

Behavior:
- Parses JSON request and validates required fields.
- Formats amount with Indian comma grouping (e.g., 12,34,567.89).
- Chooses ZeptoMail template based on Type ("Buyer" or "Seller").
- Sends templated email via ZeptoMail /v1.1/email/template with merge fields:
  - amount, Buyer_name, security_name, crmid.
- Returns a JSON result with success/error details.

Inputs (JSON body):
- amount         (number, required)
- security_name  (string, required)
- buyer_name     (string, required)   // used as recipient name in email
- email          (string, optional but expected) // recipient address
- crm_id         (string, optional)   // passed to template as crmid
- Type           (string, optional)   // "Buyer" or "Seller" (selects template)

Outputs:
- 200: {"status":"success","response":"..."} on successful send.
- 400: {"status":"error","error":"..."} for validation issues.
- 500: {"status":"error","error":"..."} for unexpected errors.

Notes:
- Uses ZeptoMail endpoint: https://api.zeptomail.com/v1.1/email/template
- Authorization header taken from Key Vault (zoho-auth-key-mApi).
- Logs request body and formatted amount for traceability.

-------------------------------------------------
Example Requests
-------------------------------------------------

HTTP:
POST /api/<function>
Content-Type: application/json

{
  "amount": 1234567.89,
  "security_name": "ABC Ltd. Unlisted Shares",
  "buyer_name": "Asha Verma",
  "email": "asha.verma@example.com",
  "crm_id": "1234567890001234567",
  "Type": "Buyer"
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{
    "amount": 1234567.89,
    "security_name": "ABC Ltd. Unlisted Shares",
    "buyer_name": "Asha Verma",
    "email": "asha.verma@example.com",
    "crm_id": "1234567890001234567",
    "Type": "Buyer"
  }'
