import json, logging, sys, io
from typing import List, Dict, Optional

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Reconfigure root logger after Azure host init
root_logger = logging.getLogger()
for handler in root_logger.handlers:
    root_logger.removeHandler(handler)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# logger = logging.getLogger("module-runner")

# Suppress Azure Storage SDK Logs
azure_loggers = [
  "azure.core.pipeline.policies.http_logging_policy",
  "azure.storage.blob"
]

log_summary = {
    "Processing": {"links": [], "attachments": [], "general": [], "file_format": {}},
    "Re-processing": {"links": [], "attachments": [], "general": [], "file_format": {}},
    "Skipping": {"links": [], "attachments": [], "general": [], "file_format": {}}
}

for logger_name in azure_loggers:
  logging.getLogger(logger_name).setLevel(logging.WARNING)

def log_start(module_name: str):
  """Log start of a module."""
  logger.info(f"▶ Running Module: {module_name}")

def log_success(module_name: str):
  """Log successful completion of a module."""
  logger.info(f"✅ Completed: {module_name}")

def log_error(module_name: str, error: Exception, stop_on_error: bool = True):
  """Log error for a module."""
  logger.error(f"❌ Error in {module_name}: {error}", exc_info=True)
  if stop_on_error:
      logger.info("Stopping further execution due to error.")

def log_warning(message: str):
  """Log a warning message."""
  logger.warning(f"⚠ {message}")

def log_custom(level: str, message: str):
  """Log a custom message at the given level."""
  level = level.lower()
  if level == "debug":
    logger.debug(message)
  elif level == "info":
    logger.info(message)
  elif level == "warning":
    logger.warning(message)
  elif level == "error":
    logger.error(message)
  elif level == "critical":
    logger.critical(message)

# Log Summary of Processed emails
def log_summary_results():  
  def summarize_category(category):
    category_data = log_summary.get(category, {})

    # Log structure to debug missing `file_format`
    if "file_format" not in category_data:
      logger.warning(f"⚠️ No file_format data found for category '{category}'")

    # Ensure `file_format` exists and is structured correctly
    file_formats = {
      fmt: len(fmt_data.get("Emails", []))  # Always fetch as list
      for fmt, fmt_data in category_data.get("file_format", {}).items()
      if isinstance(fmt_data, dict) and "Emails" in fmt_data  # ✅ Check valid dict & ensure Emails key exists
    }

    return {
      "Total": sum(len(category_data.get(k, [])) for k in ["links", "attachments", "general"]),
      "Links": len(category_data.get("links", [])),
      "Attachments": len(category_data.get("attachments", [])),
      "General": len(category_data.get("general", [])),
      "FileFormats": file_formats if file_formats else "N/A"  # ✅ Avoid empty `{}` for clarity
    }

  summary = {
    "Processing": summarize_category("Processing"),
    "Re-processing": summarize_category("Re-processing"),
    "Skipping": summarize_category("Skipping")
  }

  # Log entire structure if still empty
  if not summary["Processing"]["FileFormats"]:
    logger.error(f"FileFormats Empty! Raw log_summary['Processing']: {log_summary.get('Processing', {}).get('file_format', {})}")

  # Compress JSON (No indentation, minimal formatting)
  compressed_summary = json.dumps(summary, separators=(',', ':'))

  # Log compressed summary
  logger.info(f"Compressed Email Processing Summary: {compressed_summary}")

# Final Log Summary
def log_final_summary(db, run_start_time):
  logger.info("Generating processing summary...")

  aggregation_pipeline = [
    {
      "$match": {
        "ProcessingTimeStamp": { "$gte": run_start_time.isoformat() }
      }
    },
    {
      "$group": {
        "_id": {
          "Status": "$Status",
          "FileFormat": "$FileFormat"
        },
        "count": { "$sum": 1 }
      }
    },
    { "$sort": { "_id.Status": 1 } }
  ]

  try:
    summary = list(db.aggregate(aggregation_pipeline))

    email_stats = {
      "total_emails": db.count_documents({
        "ProcessingTimeStamp": { "$gte": run_start_time.isoformat() }
      }),
      "cams_emails": db.count_documents({
        "RTAType": "CAMS",
        "ProcessingTimeStamp": { "$gte": run_start_time.isoformat() }
      }),
      "kfintech_emails": db.count_documents({
        "RTAType": {"$regex": "KFintech", "$options": "i"},  # Case-insensitive match
        "ProcessingTimeStamp": { "$gte": run_start_time.isoformat() }
      })
    }

    processing_stats = {
      "processed": {},
      "failed": {},
      "unsupported": {},
      "downloaded_from_links": db.count_documents({"ProcessingTimeStamp": { "$gte": run_start_time.isoformat()}, "sourceType": "Link" }),
      "downloaded_from_attachments": db.count_documents({"ProcessingTimeStamp": { "$gte": run_start_time.isoformat()}, "sourceType": "Attachment" }),
    }

    for entry in summary:
      file_type = entry["_id"]["FileFormat"]
      status = entry["_id"]["Status"]

      if status == "processed":
        processing_stats["processed"][file_type] = entry["count"]
      elif status == "failed":
        processing_stats["failed"][file_type] = entry["count"]
      elif status == "unsupported_file_type":
        processing_stats["unsupported"][file_type] = entry["count"]

    # Log Summary
    logger.info(f"📨 Total Emails Processed: {email_stats['total_emails']}")
    logger.info(f"   - CAMS Emails: {email_stats['cams_emails']}")
    logger.info(f"   - KFintech Emails: {email_stats['kfintech_emails']}")
    logger.info(f"📥 Emails Filtered for Processing: {processing_stats['downloaded_from_links'] + processing_stats['downloaded_from_attachments']}")
    logger.info(f"   - From Links: {processing_stats['downloaded_from_links']}")
    logger.info(f"   - From Attachments: {processing_stats['downloaded_from_attachments']}")

    logger.info("✅ Processed Files Breakdown:")
    for file_type, count in processing_stats["processed"].items():
      logger.info(f"   - {file_type}: {count}")

    logger.info("❌ Failed Files Breakdown:")
    for file_type, count in processing_stats["failed"].items():
      logger.info(f"   - {file_type}: {count}")

    logger.info("🚫 Unsupported Files Breakdown:")
    for file_type, count in processing_stats["unsupported"].items():
      logger.info(f"   - {file_type}: {count}")

  except Exception as e:
    logger.error(f"❌ Error generating processing summary: {e}")
