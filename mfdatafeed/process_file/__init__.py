from datetime import datetime, timezone

from .process_mails_core import process_mails_core
from .logger_utils import log_error, log_start, log_success

def run_process_file():
  run_start_time = datetime.now(timezone.utc)
  try:
    log_start("process_mails_core")
    process_mails_core(run_start_time)
    log_success("process_mails_core")
  except Exception as e:
    log_error("process_mails_core", e)