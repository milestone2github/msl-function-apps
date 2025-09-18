Insurance Renewal WhatsApp Reminder (Azure Function - Timer Trigger)
-------------------------------------------------------------------

Purpose:
- Retrieves renewal leads from Zoho CRM and sends scheduled WhatsApp reminders before/on/after renewal dates.

Secrets:
- Pulled from Azure Key Vault:
  - wati-url-mApi (WATI base URL)
  - wati-key-mApi (WATI API key)
  - zoho-credentials-mApi (JSON: client_id, client_secret, refresh_token)

Behavior:
- Authenticates to Zoho (refresh token -> access token).
- Fetches Insurance_Leads (fields: Name, Renewal_Date, Renewal_Product_Name, Product, Phone) via Zoho CRM (paged).
- Transforms data:
  - Name -> first name
  - Formatted_Product_Name -> derived from Product/Renewal_Product_Name (removes "Insurance")
  - Renewal_Date -> datetime; waid -> "91" + 10-digit phone
- Schedules WhatsApp reminders:
  - Before/On date: -7, -4, -2, 0 days (all products)
  - After date: +1, +3, +5, +7 days (Health Insurance only)
- Sends WATI template message "insurance_renewal_reminder4" with parameters:
  - image (Motor: WORKOUT-2.png; others: HealthInsuranceRenewal.png)
  - name, type (Formatted_Product_Name), date (dd-MMM-YYYY)

Inputs:
- Trigger: Timer (runs automatically on schedule).
- External systems: Zoho CRM (read), WATI (send message).

Outputs:
- WhatsApp template messages to clients due for reminders.
- Logs of send attempts and errors.

Notes:
- Uses IST (Asia/Kolkata) for date comparisons.
- Zoho CRM page size per_page=200; auto-paginates until more_records is false.

-------------------------------------------------
Example Requests (manual test stubs)
-------------------------------------------------

This is a Timer Trigger; it runs on schedule. To test manually, create a temporary HTTP trigger that calls the same orchestrator.

HTTP (stub):
GET /api/<function>/run-test

cURL (stub):
curl -X GET "https://<your-func-app>.azurewebsites.net/api/<function>/run-test"

Downstream WATI API call this job performs:
HTTP:
POST <wati-base-url>/api/v1/sendTemplateMessage?whatsappNumber=<WAID>
Content-Type: application/json
Authorization: Bearer <WATI_KEY>

{
  "template_name": "insurance_renewal_reminder4",
  "broadcast_name": "InsuranceAlert",
  "parameters": [
    {"name":"image","value":"<image-url>"},
    {"name":"name","value":"Asha"},
    {"name":"type","value":"Family Floater"},
    {"name":"date","value":"21-Aug-2025"}
  ]
}

cURL:
curl -X POST "<wati-base-url>/api/v1/sendTemplateMessage?whatsappNumber=<WAID>" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <WATI_KEY>" \
  -d '{"template_name":"insurance_renewal_reminder4","broadcast_name":"InsuranceAlert","parameters":[{"name":"image","value":"<image-url>"},{"name":"name","value":"Asha"},{"name":"type","value":"Family Floater"},{"name":"date","value":"21-Aug-2025"}]}'
