import json
import random
import requests
import logging
from datetime import datetime, timedelta
import azure.functions as func
from pymongo import MongoClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import os
import tempfile
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet


# ============ Key Vault Setup ============
VAULT_URL = f"https://{os.environ['KEYVAULT_NAME']}.vault.azure.net"
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=VAULT_URL, credential=credential)

def get_secret_from_vault(secret_name: str) -> str:
    try:
        secret = secret_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        logging.error(f"❌ Failed to fetch secret '{secret_name}' from Key Vault: {e}")
        return None


# ============ Zoho CRM Setup ============
zoho_creds = json.loads(get_secret_from_vault("zoho-credentials-mApi"))
ZOHO_CLIENT_ID = zoho_creds.get("client_id", "")
ZOHO_CLIENT_SECRET = zoho_creds.get("client_secret", "")
ZOHO_REFRESH_TOKEN = zoho_creds.get("refresh_token", "")

def extract_lead_id(response_json):
    """Safely extract lead ID from Zoho response."""
    try:
        data = response_json.get("data", [])
        if not data:
            return None
        item = data[0]
        # Handle both structures
        return item.get("details", {}).get("id") or item.get("id")
    except Exception as e:
        logging.error(f"⚠️ Failed to extract lead_id: {e} | Response: {response_json}")
        return None

def get_access_token():
    TOKEN_ENDPOINT = "https://accounts.zoho.com/oauth/v2/token"
    payload = {
        "refresh_token": ZOHO_REFRESH_TOKEN,
        "client_id": ZOHO_CLIENT_ID,
        "client_secret": ZOHO_CLIENT_SECRET,
        "grant_type": "refresh_token",
    }
    try:
        response = requests.post(TOKEN_ENDPOINT, data=payload, timeout=10)
        response.raise_for_status()
        token = response.json().get("access_token")
        logging.info("🔑 Refreshed Zoho Access Token successfully.")
        return token
    except Exception as e:
        logging.error(f"❌ Failed to refresh Zoho access token: {e}")
        return None


# ============ RM Pool ============
HEALTH_RM_ID_LIST = [
    # "2969103000142839001",  # Ishu Mavar
    # "2969103000000183019",  # Sagar Maini
    "2969103000438647001",  # Sumit Chakraborty
    # "2969103000154276001",  # Sumit Sumit
    # "2969103000193811001",  # Yatin Munjal
    "2969103000500517001",  # Rohit Bharadwaj
]


# ============ PDF Generator ============


def generate_insurance_pdf(insurance_data, filename):
    """Generate a professional multi-section PDF like exportReviewAsPDF."""
    doc = SimpleDocTemplate(filename, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    style_heading = styles["Heading2"]
    style_normal = styles["Normal"]

    def safe_get(data, *keys):
        for k in keys:
            if isinstance(data, dict):
                data = data.get(k, {})
            else:
                return None
        return data or None

    # --- Title ---
    elements.append(Paragraph("<b>Insurance Form Summary</b>", style_heading))
    elements.append(Spacer(1, 12))

    # --- Basic Info ---
    contact = insurance_data.get("contactNumber", "")
    created_at = insurance_data.get("createdAt")
    created_at = (
        created_at.get("$date", created_at)
        if isinstance(created_at, dict)
        else created_at
    )
    created_at = str(created_at).replace("T", " ").split(".")[0]

    table_data = [
        ["Contact Number", str(contact)],
        ["Created At", created_at],
        ["Current Step", str(insurance_data.get("currentStep", ""))],
        ["Progress", str(insurance_data.get("progress", ""))],
        ["Thank You Message Sent", str(insurance_data.get("thankyouMessageSent", ""))],
    ]
    table = Table(table_data, colWidths=[180, 330])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                ("BOX", (0, 0), (-1, -1), 0.25, colors.black),
                ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
            ]
        )
    )
    elements.append(table)
    elements.append(Spacer(1, 12))

    # --- Personal Info Section ---
    personal_info = safe_get(insurance_data, "personal", "personalInfo")
    if personal_info:
        elements.append(Paragraph("<b>1. Personal Details</b>", style_heading))
        elements.append(Spacer(1, 6))
        rows = [["Name", "Gender", "DOB", "Pincode"]]
        for key, val in personal_info.items():
            name = val.get("name", "")
            gender = val.get("gender", "")
            dob = (
                val.get("dob", {}).get("$date", "")
                if isinstance(val.get("dob"), dict)
                else str(val.get("dob", ""))
            )
            pincode = val.get("pincode", "")
            rows.append([name, gender, dob[:10], pincode])
        table = Table(rows, colWidths=[130, 100, 120, 120])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                ]
            )
        )
        elements.append(table)
        elements.append(Spacer(1, 12))

    # --- Lifestyle Section ---
    lifestyle = insurance_data.get("lifestyle", {})
    if lifestyle:
        elements.append(Paragraph("<b>2. Lifestyle Details</b>", style_heading))
        rows = [["Profile", "Fitness", "Alcohol", "Tobacco"]]
        ls_data = lifestyle.get("lifestyleData", {})
        for key, fitness in ls_data.items():
            alcohol = lifestyle.get("alcoholHistory", {}).get("alcoholHistoryData", {}).get(key, "No")
            tobacco = lifestyle.get("tobaccoHistory", {}).get("tobaccoHistoryData", {}).get(key, "No")
            rows.append([key, fitness, alcohol, tobacco])
        table = Table(rows, colWidths=[130, 100, 120, 120])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                ]
            )
        )
        elements.append(Spacer(1, 6))
        elements.append(table)
        elements.append(Spacer(1, 12))

    # --- Medical Section ---
    med = insurance_data.get("medicalCondition", {}).get("medicalData", {})
    if med:
        elements.append(Paragraph("<b>3. Medical / Health Details</b>", style_heading))
        rows = [["Member", "Illnesses", "Other Illness"]]
        for k, v in med.items():
            illnesses = ", ".join(v.get("selectedIllnesses", []))
            rows.append([k, illnesses or "None", v.get("otherIllness", "")])
        table = Table(rows, colWidths=[130, 200, 140])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                ]
            )
        )
        elements.append(Spacer(1, 6))
        elements.append(table)
        elements.append(Spacer(1, 12))

    # --- Existing Policy Section ---
    existing = insurance_data.get("existingPolicy", {})
    if existing.get("hasExistingPolicy"):
        elements.append(Paragraph("<b>4. Existing Policy Details</b>", style_heading))
        policies = existing.get("existingPolicyData", {})
        for pid, p in policies.items():
            elements.append(
                Paragraph(
                    f"<b>{pid}</b> — {p.get('policyName', '')} | Cover: {p.get('coverAmount', '')} lacs | Type: {p.get('policyType', '')}",
                    style_normal,
                )
            )
        elements.append(Spacer(1, 12))

    doc.build(elements)
    return filename



def upload_pdf_to_zoho(lead_id, file_path, access_token):
    url = f"https://www.zohoapis.com/crm/v2/Insurance_Leads/{lead_id}/Attachments"
    headers = {"Authorization": f"Zoho-oauthtoken {access_token}"}
    files = {"file": open(file_path, "rb")}
    response = requests.post(url, headers=headers, files=files, timeout=15)
    return response


# ============ MAIN FUNCTION ============
def main(mytimer: func.TimerRequest) -> None:
    logging.info("🚀 CRM Sync Function Triggered")

    mongo_uri = get_secret_from_vault("connection-string-mApi")
    client = MongoClient(mongo_uri)
    db = client["insurance-policy"]

    insurance_col = db["insuranceforms"]
    whatsapp_col = db["WhatsappLead"]
    leads_col = db["leads"]

    now = datetime.utcnow()
    product = "Health Insurance"

    ZOHO_ACCESS_TOKEN = get_access_token()
    if not ZOHO_ACCESS_TOKEN:
        logging.error("❌ Aborting sync — no Zoho access token available.")
        return

    ZOHO_API_BASE = "https://www.zohoapis.com/crm/v2"
    HEADERS = {"Authorization": f"Zoho-oauthtoken {ZOHO_ACCESS_TOKEN}", "Content-Type": "application/json"}

    processed_insurance = 0
    processed_whatsapp = 0

    try:
        # ========== FLOW 1: Insurance Forms ==========
        insurance_docs = list(insurance_col.find({"createdAt": {"$exists": True}}))
        for ins in insurance_docs:
            contact = str(ins.get("contactNumber", "")).lstrip("+")
            if contact.startswith("91") and len(contact) > 10:
                contact = contact[2:]
            if not contact or len(contact) < 8:
                continue

            created_at = ins.get("createdAt")
            if isinstance(created_at, dict) and "$date" in created_at:
                created_at = datetime.fromisoformat(created_at["$date"].replace("Z", ""))
            if not created_at or (now - created_at) < timedelta(hours=24):
                continue

            # Check if lead already exists
            criteria = f"(Phone:equals:{contact})and(Product:equals:{product})"
            search_url = f"{ZOHO_API_BASE}/Insurance_Leads/search?criteria={criteria}"
            search_resp = requests.get(search_url, headers=HEADERS, timeout=10)

            if search_resp.status_code == 200:
                data = search_resp.json()
                if "data" in data and len(data["data"]) > 0:
                    lead_id = extract_lead_id(data)
                    if not lead_id:
                        logging.error(f"⚠️ Missing lead ID in Zoho search response for {contact}: {data}")
                        continue

                    assigned_rm_id = data["data"][0].get("Owner", {}).get("id", random.choice(HEALTH_RM_ID_LIST))
                    logging.info(f"✅ Lead already exists in Zoho for {contact} — ID: {lead_id}")
                    with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                        pdf_path = tmp.name
                    generate_insurance_pdf(ins, pdf_path)
                    upload_pdf_to_zoho(lead_id, pdf_path, ZOHO_ACCESS_TOKEN)
                    # ✅ Still update Mongo even if exists
                    leads_col.update_one(
                        {"phone": contact},
                        {"$set": {
                            "leadId": lead_id
                        }},
                        upsert=True
                    )
                    continue

            assigned_rm_id = random.choice(HEALTH_RM_ID_LIST)
            lead_name = next((v.get("name") for v in ins.get("personal", {}).get("personalInfo", {}).values() if isinstance(v, dict) and v.get("name")), f"Lead {contact}")
            new_lead = {"data": [{"Name": lead_name, "Phone": contact, "Product": product, "Owner": {"id": assigned_rm_id}}]}
            create_resp = requests.post(f"{ZOHO_API_BASE}/Insurance_Leads", headers=HEADERS, json=new_lead)

            if 200 <= create_resp.status_code < 300:
                lead_id = extract_lead_id(create_resp.json())
                if not lead_id:
                    logging.error(f"⚠️ Could not find lead ID for {contact}. Zoho response: {create_resp.text}")
                    continue

                with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
                    pdf_path = tmp.name
                generate_insurance_pdf(ins, pdf_path)
                upload_pdf_to_zoho(lead_id, pdf_path, ZOHO_ACCESS_TOKEN)
                leads_col.update_one(
                    {"phone": contact},
                    {"$set": {"leadId": lead_id}},
                    upsert=True,
                )
                processed_insurance += 1

        # ========== FLOW 2: WhatsApp Leads ==========
        whatsapp_docs = list(whatsapp_col.find({"lastSend": {"$exists": True}}))
        for whats in whatsapp_docs:
            contact = str(whats.get("MOBILE", "")).lstrip("+")
            if contact.startswith("91") and len(contact) > 10:
                contact = contact[2:]
            if not contact or len(contact) < 8:
                continue

            last_send = whats.get("lastSend")
            if isinstance(last_send, dict) and "$date" in last_send:
                last_send = datetime.fromisoformat(last_send["$date"].replace("Z", ""))
            if not last_send or (now - last_send) < timedelta(hours=24):
                continue

            # Check if lead exists
            criteria = f"(Phone:equals:{contact})and(Product:equals:{product})"
            search_url = f"{ZOHO_API_BASE}/Insurance_Leads/search?criteria={criteria}"
            search_resp = requests.get(search_url, headers=HEADERS, timeout=10)

            if search_resp.status_code == 200:
                data = search_resp.json()
                if "data" in data and len(data["data"]) > 0:
                    lead_id = extract_lead_id(data)
                    if not lead_id:
                        logging.error(f"⚠️ Missing lead ID in Zoho search response for {contact}: {data}")
                        continue

                    assigned_rm_id = data["data"][0].get("Owner", {}).get("id", random.choice(HEALTH_RM_ID_LIST))
                    logging.info(f"✅ Lead already exists in Zoho for {contact} — ID: {lead_id}")

                    # ✅ Still update Mongo even if exists
                    leads_col.update_one(
                        {"phone": contact},
                        {"$set": {
                            "leadId": lead_id,
                        }},
                        upsert=True
                    )
                    continue

            assigned_rm_id = random.choice(HEALTH_RM_ID_LIST)
            lead_name = whats.get("NAME") or f"Lead {contact}"
            new_lead = {"data": [{"Name": lead_name, "Phone": contact, "Product": product, "Owner": {"id": assigned_rm_id}}]}
            create_resp = requests.post(f"{ZOHO_API_BASE}/Insurance_Leads", headers=HEADERS, json=new_lead)

            if 200 <= create_resp.status_code < 300:
                lead_id = extract_lead_id(create_resp.json())
                if not lead_id:
                    logging.error(f"⚠️ Could not find lead ID for {contact}. Zoho response: {create_resp.text}")
                    continue

                leads_col.update_one(
                    {"phone": contact},
                    {"$set": {"leadId": lead_id,}},
                    upsert=True,
                )
                processed_whatsapp += 1

        logging.info(f"🎯 Sync Complete — Insurance Leads Created: {processed_insurance}, WhatsApp Leads Created: {processed_whatsapp}")

    except Exception as e:
        logging.error(f"🔥 CRM Sync Error: {e}")

    finally:
        client.close()
