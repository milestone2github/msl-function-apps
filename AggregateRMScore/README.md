# Aggregate RM Score (Azure Function - Timer Trigger)

## Purpose
- Aggregates employee leaderboard scores from multiple MongoDB sub-collections for a financial year (April → March).
- Calculates both financial-year-based totals and current-month totals for each employee.
- Stores the results in a consolidated MongoDB collection.

## Secrets
- Pulled from Azure Key Vault:
  - `connection-string-mApi` (MongoDB connection string)

## Behavior
- Connects to MongoDB using credentials retrieved from Azure Key Vault.
- Aggregates scores from the following sub-collections in `PLI_Leaderboard_Data`:
  - `Leaderboard` → `points_total`
  - `Leaderboard_Lumpsum` → `final_incentive`
  - `referralLeaderboard` → `points`
  - `MF_SIP_Leaderboard` → `points`
- Filters entries starting from April of the current financial year for FY totals.
- Sums points per `employee_id` across all collections.
- Aggregates scores for the **current month** across all collections.
- Stores aggregated scores in `aggregatedScores` collection with fields:
  - `employee_id`
  - `employee_name`
  - `score_<startYear>-<endYear>` (e.g., `score_2025-26`) → financial year total
  - `scoreCurrentMonth` → current month total across all collections
  - `updated_at`
- Automatically updates the FY field each year; new FY starts on 1st April.

## Inputs
- **Trigger:** Timer (runs automatically on schedule: 1st of every month at 04:30 UTC by default)
- **External systems:** MongoDB (read/write), Azure Key Vault (read secrets)

## Outputs
- Aggregated employee scores stored in `aggregatedScores` collection.
- Logs of aggregation runs with timestamps.

## Notes
- Financial year calculation:
  - If current month < April → previous FY
  - Else → current FY
- Assumes `month` field in MongoDB collections is in `"YYYY-MM"` format.
- Uses UTC for all datetime comparisons.

## Local Testing
- To test aggregation manually without waiting for the timer schedule:
- Enable the `VAULT_URL` line in the code for local execution.

```bash
python __init__.py