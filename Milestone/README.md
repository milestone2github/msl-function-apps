Generic MongoDB CRUD Proxy (Azure Function - HTTP Trigger)
---------------------------------------------------------

Purpose:
- HTTP endpoint to perform CRUD and bulk operations on MongoDB collections, returning JSON results.

Secrets:
- Pulled from Azure Key Vault:
  - connection-string-mApi (MongoDB Atlas URI)

Behavior:
- Connects to DB: Milestone.
- Supports operations (request JSON -> "operation"):
  - find, insert, update, delete, upsert
  - bulk_insert (list of documents)
  - bulk_upsert (list; UpdateOne with upsert)
  - bulk_refresh (list; ReplaceOne with upsert)
- Serializes results to JSON (ObjectIds stringified).

Inputs (JSON body):
- collection (string)  — required
- operation (string)   — required (one of the supported operations)
- data (object/array)  — shape depends on operation:
  - find:        { "query": { ... } }
  - insert:      full document object
  - update:      { "query": { ... }, "new_values": { ... } }
  - delete:      { "query": { ... } }
  - upsert:      { "query": { ... }, "new_values": { ... } }
  - bulk_insert: { "documents": [ { ... }, { ... } ] }
  - bulk_upsert: [ { "_id": "...", ... }, ... ]
  - bulk_refresh:[ { "_id": "...", ... }, ... ]

Outputs:
- 200: JSON result (varies by operation)
- 201: Insert success (inserted_id)
- 400: Unsupported/invalid operation
- 500: Error with details

-------------------------------------------------
Example Requests
-------------------------------------------------

FIND
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "collection": "MintDb",
  "operation": "find",
  "data": { "query": { "NEWSAlert": true } }
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"collection":"MintDb","operation":"find","data":{"query":{"NEWSAlert":true}}}'


INSERT
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "collection": "MintDb",
  "operation": "insert",
  "data": { "NAME": "John Doe", "AUM": 100000 }
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"collection":"MintDb","operation":"insert","data":{"NAME":"John Doe","AUM":100000}}'


UPDATE
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "collection": "MintDb",
  "operation": "update",
  "data": { "query": { "NAME": "John Doe" }, "new_values": { "AUM": 150000 } }
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"collection":"MintDb","operation":"update","data":{"query":{"NAME":"John Doe"},"new_values":{"AUM":150000}}}'


DELETE
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "collection": "MintDb",
  "operation": "delete",
  "data": { "query": { "NAME": "John Doe" } }
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"collection":"MintDb","operation":"delete","data":{"query":{"NAME":"John Doe"}}}'


BULK INSERT
HTTP:
POST /api/<function>
Content-Type: application/json

{
  "collection": "MintDb",
  "operation": "bulk_insert",
  "data": { "documents": [ { "NAME": "A" }, { "NAME": "B" } ] }
}

cURL:
curl -X POST "https://<your-func-app>.azurewebsites.net/api/<function>" \
  -H "Content-Type: application/json" \
  -d '{"collection":"MintDb","operation":"bulk_insert","data":{"documents":[{"NAME":"A"},{"NAME":"B"}]}}'
