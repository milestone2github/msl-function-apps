import os
import logging
from datetime import datetime, timezone
from pymongo import MongoClient
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func

# ----------------------------
# Azure Key Vault setup
# ----------------------------
VAULT_URL = f"https://{os.environ['KEYVAULT_NAME']}.vault.azure.net"
# VAULT_URL = f"https://milestoneTSL1.vault.azure.net"  # enable for Local testing
credential = DefaultAzureCredential()
secret_client = SecretClient(vault_url=VAULT_URL, credential=credential)

def get_secret_from_vault(secret_name: str) -> str:
    print(f"Fetching secret: {secret_name}")  # debug
    try:
        secret = secret_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        logging.error(f"Failed to fetch secret '{secret_name}': {str(e)}")
        return None

# ----------------------------
# MongoDB Connection
# ----------------------------
CONNECTIONSTRING = get_secret_from_vault("connection-string-mApi")
client = MongoClient(CONNECTIONSTRING)
db = client["PLI_Leaderboard_Data"]

# ---------------------------------
# Collections and score fields
# ---------------------------------
collections = {
    "Leaderboard": "points_total",
    "Leaderboard_Lumpsum": "final_incentive",
    "referralLeaderboard": "points",
    "MF_SIP_Leaderboard": "points"
}

# ----------------------------
# Determine financial year
# ----------------------------
def get_financial_year(now=None):
    if not now:
        now = datetime.now(timezone.utc)
    year = now.year
    if now.month < 4:  # Jan-Mar belong to previous FY
        start_year = year - 1
        end_year = year
    else:
        start_year = year
        end_year = year + 1
    return f"score_{start_year}-{str(end_year)[-2:]}"  # i.e. score_2025-26

# ----------------------------
# Aggregation function
# ----------------------------
def aggregate_rm_scores():
    logging.info(f"Aggregation started at {datetime.now(timezone.utc)}")
    fy_field = get_financial_year()
    employee_totals = {}
    current_month_totals = {}

    # Define FY start date
    now = datetime.now(timezone.utc)
    fy_start_year = int(fy_field.split("_")[1].split("-")[0])
    fy_end_year = fy_start_year + 1
    fy_start_date = datetime(fy_start_year, 4, 1, tzinfo=timezone.utc)
    current_month_str = now.strftime("%Y-%m")  # "YYYY-MM"

    for coll_name, score_field in collections.items():
        coll = db[coll_name]

        if coll_name == "referralLeaderboard":
            # Sum all points for each employee (no month filtering)
            pipeline_fy = [
                {"$group": {
                    "_id": "$employee_id",
                    "employee_name": {"$first": "$employee_name"},
                    "total_points": {"$sum": f"${score_field}"}
                }}
            ]
            # Current month sum is skipped since there's no month field
            pipeline_month = []
        elif coll_name == "MF_SIP_Leaderboard":
            # month field is period_month
            pipeline_fy = [
                {"$match": {"period_month": {"$gte": f"{fy_start_year}-04", "$lte": f"{fy_end_year}-03"}}},
                {"$group": {
                    "_id": "$employee_id",
                     "employee_name": {"$first": "$rm_name"},
                    "total_points": {"$sum": f"${score_field}"}
                }}
            ]
            pipeline_month = [
                {"$match": {"period_month": current_month_str}},
                {"$group": {
                    "_id": "$employee_id",
                    "total_points": {"$sum": f"${score_field}"}
                }}
            ]
        else:
            # Existing FY aggregation with month filtering
            pipeline_fy = [
                {"$match": {"month": {"$gte": f"{fy_start_year}-04", "$lte": f"{fy_end_year}-03"}}},
                {"$group": {
                    "_id": "$employee_id",
                    "employee_name": {"$first": "$employee_name"},
                    "total_points": {"$sum": f"${score_field}"}
                }}
            ]
            # Current month aggregation
            pipeline_month = [
                {"$match": {"month": current_month_str}},
                {"$group": {
                    "_id": "$employee_id",
                    "total_points": {"$sum": f"${score_field}"}
                }}
            ]

        # Process FY aggregation
        for doc in coll.aggregate(pipeline_fy):
            emp_id = doc["_id"]
            total = doc.get("total_points", 0)
            name = doc.get("employee_name", "Unknown")
            if emp_id not in employee_totals:
                employee_totals[emp_id] = {"employee_name": name, "score": 0}
            employee_totals[emp_id]["score"] += total

        # Process current month aggregation
        for doc in coll.aggregate(pipeline_month):
            emp_id = doc["_id"]
            total = doc.get("total_points", 0)
            if emp_id not in current_month_totals:
                current_month_totals[emp_id] = 0
            current_month_totals[emp_id] += total

    # Print totals After aggregating all collections into employee_totals and current_month_totals
    """
    #### TEST CODE TO PIN-POINT DISCREPANCY
    for coll_name, score_field in collections.items():
        coll = db[coll_name]
        # Find documents where score exists but employee_id or employee_name is missing
        docs = coll.find(
            {
                score_field: {"$exists": True, "$ne": 0},
                "$or": [
                    {"employee_id": {"$exists": False}},
                    {"employee_id": None},
                    {"employee_name": {"$exists": False}},
                    {"employee_name": None}
                ]
            },
            {"employee_id": 1, "employee_name": 1, score_field: 1}  # only show relevant fields
        )
        print(f"Collection: {coll_name}")
        for doc in docs:
            print(doc)
    """

    ### Print single line entry for aggregated data
    for emp_id, data in employee_totals.items():
        total_fy = data["score"]
        total_month = current_month_totals.get(emp_id, 0)
        print(f"Employee: {data['employee_name']}, FY Total: {total_fy}, Current Month: {total_month}")

    # Store/update FY score and current month score in aggregatedScores collection
    aggregated_coll = db["aggregatedScores"]
    for emp_id, data in employee_totals.items():
        aggregated_coll.update_one(
            {"employee_id": emp_id},
            {"$set": {
                "employee_name": data["employee_name"],
                fy_field: data["score"],
                "scoreCurrentMonth": current_month_totals.get(emp_id, 0),
                "updated_at": datetime.now(timezone.utc)
            }},
            upsert=True
        )

    logging.info(f"Aggregation completed for {len(employee_totals)} employees at {datetime.now(timezone.utc)}")
    print("Aggregation Complete")

# ----------------------------
# Azure Function entry point (defaults to running once on every month's 1st at 0430 hours)
# ----------------------------
def main(aggrScore: func.TimerRequest) -> None:
    logging.basicConfig(level=logging.INFO)
    logging.info("Monthly financial-year aggregation triggered")
    aggregate_rm_scores()

# ----------------------------
# Local test
# ----------------------------
if __name__ == "__main__":
    aggregate_rm_scores()   # directly initilize the timer function