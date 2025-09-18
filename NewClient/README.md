New Clients Daily Audit & Email (Azure Function - Timer Trigger)
----------------------------------------------------------------

Purpose:
- Scans yesterday’s newly imported clients in MongoDB, categorizes them (duplicates, no PAN, unique with/without AUM), and emails a summary list.

Secrets:
- Pulled from Azure Key Vault:
  - connection-string-mApi (MongoDB)
  - zoho-auth-key-mApi (ZeptoMail API auth header)
  - new-client-recipients-mApi (JSON array of recipient objects for ZeptoMail)

Behavior:
- Connects to DB: Milestone, Collection: MintDb.
- Time window: "First Imported Date" between 00:00:00 and 23:59:59 of yesterday (server local time).
- Aggregates counts per PAN for yesterday’s imports.
- Categorizes records:
  - Duplicates (PAN occurs >1 among yesterday’s imports)
  - No PAN (missing/empty PAN)
  - Unique with AUM (PAN occurs once and AUM > 0)
  - Unique without AUM (PAN occurs once and AUM = 0 or missing)
- Builds an HTML summary of each category (NAME and EMAIL).
- Sends email via ZeptoMail API to configured recipients.

Inputs:
- Trigger: Timer (runs automatically on schedule).
- External systems: MongoDB (read), ZeptoMail (send).

Outputs:
- Email titled "Client List Update" containing category-wise lists.
- Logs of counts per category and API response.

Notes:
- Date comparison uses string timestamps stored in "First Imported Date" (format "YYYY-MM-DD HH:MM:SS").
- Ensure MintDb stores "PAN", "AUM", "NAME", "EMAIL", and "First Imported Date" fields as expected.

-------------------------------------------------
Example Requests (manual test stub)
-------------------------------------------------

This is a Timer Trigger; it runs on schedule. To test manually, create a temporary HTTP trigger that calls the same logic.

HTTP (stub):
GET /api/<function>/run-test

cURL (stub):
curl -X GET "https://<your-func-app>.azurewebsites.net/api/<function>/run-test"
