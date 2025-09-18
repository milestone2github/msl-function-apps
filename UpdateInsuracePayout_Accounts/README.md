Zoho CRM Accounts Release Updater (Azure Function - HTTP Trigger)
-----------------------------------------------------------------

Purpose:
- Bulk-updates Zoho CRM Insurance_Leads records to set Accounts_Release = true and Accounts_Release_Date = today.

Secrets:
- Pulled from Azure Key Vault:
  - zoho-credentials-mApi (JSON: client_id, client_secret, refresh_token)

Behavior:
- Exchanges Zoho refresh token for an access token.
- For each record_id provided, issues a PUT to /crm/v5/Insurance_Leads with:
  - { Accounts_Release: true, Accounts_Release_Date: YYYY-MM-DD, id: <record_id> }
- Aggregates and returns Zoho API responses.

Inputs (JSON body):
- record_ids  (array of strings; required)

Outputs:
- 200: JSON array of Zoho responses.
- 400: "No record IDs provided".
- 500: Error message on failure.

Notes:
- Accounts_Release_Date uses server date (YYYY-MM-DD).

-------------------------------------------------
Example Requests
-------------------------------------------------

HTTP:
POST /api/<function>
Content-Type: application/json

{
  "record_ids": [
    "696969000000123001",
    "696969000000123002",
    "696969000000123003"
  ]
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{
    "record_ids": [
      "696969000000123001",
      "696969000000123002",
      "696969000000123003"
    ]
  }'
