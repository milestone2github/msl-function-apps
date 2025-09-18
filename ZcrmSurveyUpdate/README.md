Portfolio Review Update & Lead Capture (Azure Function - HTTP Trigger)
----------------------------------------------------------------------

Purpose:
- Updates a Portfolio_Review record’s feedback/date in Zoho CRM and creates a new Investment_leads record from form/WA inputs.

Secrets:
- Pulled from Azure Key Vault:
  - zoho-credentials-mApi (JSON: client_id, client_secret, refresh_token)

Behavior:
- Auth: Exchanges Zoho refresh token for access token.
- Lookup: Finds Portfolio_Review record by Iwell_Code (v6 search).
- Update: Sets General_Feedback (trimmed to 5 chars) and General_Ve_date (IST, YYYY-MM-DD).
- Owner: Randomly picks RM from a list, resolves to Zoho user ID (fallback ID if not found).
- Lead create: Posts to Investment_leads (v2) with Name, Mobile, Product_Type="Mutual Funds", Refrencer_Name="WA Marketing".
- Returns 200 only if both update and lead creation succeed.

Inputs:
- Supports GET query params or POST JSON body.
- Required: Iwell (IwellCode), Score (SurveyScore)
- Optional (used for lead creation): FName, LName, Mobile, Email

Outputs:
- 200: "Success" (both CRM update and lead creation succeeded)
- 400: Missing IwellCode or SurveyScore
- 404: Portfolio_Review record not found for given Iwell_Code
- 500: Error details from Zoho or internal exception

Notes:
- Dates use Asia/Kolkata timezone.
- Portfolio_Review update via Zoho CRM v6; Investment_leads creation via v2.

-------------------------------------------------
Example Requests
-------------------------------------------------

POST (JSON body)
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "Iwell": "IW12345",
  "Score": "5/5",
  "FName": "Asha",
  "LName": "Verma",
  "Mobile": "9876543210",
  "Email": "asha.verma@example.com"
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"Iwell":"IW12345","Score":"5/5","FName":"Asha","LName":"Verma","Mobile":"9876543210","Email":"asha.verma@example.com"}'


GET (query params)
HTTP:
GET /api/<function>?Iwell=IW12345&Score=4&FName=Asha&LName=Verma&Mobile=9876543210&Email=asha.verma%40example.com

cURL:
curl -G "https://<your-func-app>.azurewebsites.net/api/<function)" \
  --data-urlencode "Iwell=IW12345" \
  --data-urlencode "Score=4" \
  --data-urlencode "FName=Asha" \
  --data-urlencode "LName=Verma" \
  --data-urlencode "Mobile=9876543210" \
  --data-urlencode "Email=asha.verma@example.com"
