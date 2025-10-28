# 🏦 MarketingInsuranceCRMupdate — Azure Function

**Purpose:**  
This Azure Function automatically syncs **insurance form submissions** and **WhatsApp leads** with **Zoho CRM**, generates professional multi-section PDFs, uploads them as attachments to corresponding CRM records, and updates lead references in MongoDB.

---

## 🚀 Key Features

- 🔐 **Azure Key Vault Integration** — All secrets (Zoho credentials, Mongo URI) are fetched securely.  
- 💡 **Dual Data Sources** — Processes both:
  - `insuranceforms` collection  
  - `WhatsappLead` collection  
- 🧾 **PDF Generation** — Creates clean, formatted PDFs with:
  - Personal details  
  - Lifestyle data  
  - Medical and existing policy details  
- ☁️ **Zoho CRM Integration**
  - Creates or updates leads in **Insurance_Leads** module.  
  - Automatically uploads the generated PDF attachment.
- 🧠 **Smart Deduplication**
  - Checks for existing leads via `(Phone + Product)` criteria.
- 💾 **MongoDB Sync**
  - Maintains a mapping of lead ID ↔ phone in `leads` collection.
- ⏱️ **Timer Trigger**
  - Runs periodically (default: every 1 hour; configurable in `function.json`).

---

## 🧩 Folder Structure

