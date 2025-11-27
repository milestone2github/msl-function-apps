import azure.functions as func

from process_mails_core import process_mails_core
from logger_utils import log_custom, log_error, log_start, log_success
from datetime import datetime, timezone

def run_process_file():
    run_start_time = datetime.now(timezone.utc)
    try:
        log_start("process_mails_core")
        process_mails_core(run_start_time)
        log_success("process_mails_core")
    except Exception as e:
        log_error("process_mails_core", e)


def main(timer_req: func.TimerRequest) -> None:
    if timer_req.past_due:
        log_custom("info", "Timer is past due!")

    log_custom("info", "Starting the Email Processing function...")
    run_process_file()
    log_custom("info", "Email Processing completed successfully.")
