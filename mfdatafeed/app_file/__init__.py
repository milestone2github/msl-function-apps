import azure.functions as func
from process_file import run_process_file
from process_file.logger_utils import log_custom

# def main(req: func.TimerRequest) -> func.HttpMethod:
def main(timer_req: func.TimerRequest) -> None:
# def main():
  if timer_req.past_due:
    log_custom("info", "Timer is past due!")
  
  log_custom("info", "Starting the Email Processing function...")
  run_process_file()

  log_custom("info", "Email Processing completed successfully.")
  # return func.HttpResponse(f"Result: {result}", status_code=200)

  if __name__ == "__main__":
    main()