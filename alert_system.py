import pandas as pd
import json
import uuid
from datetime import datetime

# --- Load both rule alerts and ML results ---
rule_alerts = pd.read_csv("data/rule_alerts.csv")
ml_results = pd.read_csv("data/ml_results.csv")

# --- Merge ML risk scores into rule alerts ---
ml_scores = ml_results[["timestamp", "ip", "user", "risk_score", "ml_label"]]
alerts = pd.merge(rule_alerts, ml_scores, on=["timestamp", "ip", "user"], how="left")
alerts["risk_score"] = alerts["risk_score"].fillna(50.0)
alerts["ml_label"] = alerts["ml_label"].fillna("UNKNOWN")

# --- Assign Alert IDs ---
alerts["alert_id"] = [f"SOC-{str(uuid.uuid4())[:8].upper()}" for _ in range(len(alerts))]

# --- Priority scoring (combines rule severity + ML risk score) ---
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 20, "LOW": 10}

alerts["priority_score"] = alerts.apply(
    lambda row: SEVERITY_WEIGHT.get(row["severity"], 10) + (row["risk_score"] * 0.6), axis=1
).round(2)

# --- Recommended Actions ---
ACTION_MAP = {
    "brute_force": "Block IP immediately + Reset user password + Enable MFA",
    "credential_stuffing": "Block IP + Force password reset for all targeted users",
    "after_hours_login": "Verify with user + Flag for manager review",
    "normal_login": "Monitor closely + Check if user is aware of login",
}

alerts["recommended_action"] = alerts["event_type"].map(ACTION_MAP)

# --- Final alert structure ---
final_alerts = alerts[[
    "alert_id",
    "timestamp",
    "user",
    "ip",
    "country",
    "severity",
    "reason",
    "event_type",
    "mitre_id",
    "mitre_technique",
    "attempt_count",
    "risk_score",
    "ml_label",
    "priority_score",
    "recommended_action"
]].sort_values("priority_score", ascending=False).reset_index(drop=True)

# --- Save as CSV ---
final_alerts.to_csv("data/final_alerts.csv", index=False)

# --- Save top 50 as JSON (for dashboard) ---
top_alerts = final_alerts.head(50).to_dict(orient="records")
with open("alert_system/alerts.json", "w") as f:
    json.dump(top_alerts, f, indent=2)

# --- Summary ---
print(f" Alert Manager Complete")
print(f"Total Alerts Generated: {len(final_alerts)}")
print(f"\nSeverity Breakdown:")
print(final_alerts["severity"].value_counts())
print(f"\nTop 5 Highest Priority Alerts:")
print(final_alerts[["alert_id", "user", "ip", "severity", "risk_score", "priority_score"]].head())
print(f"\n Saved to data/final_alerts.csv")
print(f"Top 50 alerts saved to alert_system/alerts.json")
# MiniSOC Alert Manager