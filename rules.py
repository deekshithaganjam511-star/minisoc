import pandas as pd

# --- Risk Scoring Rules ---

def check_brute_force(row):
    if row["event_type"] == "brute_force" and row["attempt_count"] >= 5:
        return "CRITICAL", "Brute Force Attack Detected"
    elif row["event_type"] == "brute_force" and row["attempt_count"] >= 3:
        return "HIGH", "Multiple Failed Login Attempts"
    return None, None

def check_after_hours(row):
    if row["event_type"] == "after_hours_login":
        hour = pd.to_datetime(row["timestamp"]).hour
        if 0 <= hour <= 4:
            return "MEDIUM", "Suspicious After-Hours Login"
    return None, None

def check_credential_stuffing(row):
    if row["event_type"] == "credential_stuffing":
        return "HIGH", "Credential Stuffing Attempt Detected"
    return None, None

def check_country(row):
    HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "NG"]
    if row["country"] in HIGH_RISK_COUNTRIES and row["status"] == "FAILED":
        return "HIGH", f"Login Attempt from High-Risk Country: {row['country']}"
    return None, None

def check_attack_ip(row):
    KNOWN_ATTACK_IPS = ["185.220.101.45", "45.33.32.156", "103.21.244.0", "198.51.100.23", "192.0.2.77"]
    if row["ip"] in KNOWN_ATTACK_IPS:
        return "CRITICAL", f"Known Malicious IP Detected: {row['ip']}"
    return None, None

# --- MITRE ATT&CK Mapping ---
MITRE_MAP = {
    "brute_force": ("T1110", "Brute Force"),
    "after_hours_login": ("T1078", "Valid Accounts"),
    "credential_stuffing": ("T1110.004", "Credential Stuffing"),
    "normal_login": ("N/A", "No Technique"),
}

# --- Main Rule Engine ---
def apply_rules(df):
    alerts = []

    for _, row in df.iterrows():
        severity, reason = None, None

        # Apply all rules in priority order
        for rule in [check_attack_ip, check_brute_force, check_credential_stuffing,
                     check_after_hours, check_country]:
            severity, reason = rule(row)
            if severity:
                break

        if severity:
            mitre_id, mitre_name = MITRE_MAP.get(row["event_type"], ("N/A", "Unknown"))
            alerts.append({
                "timestamp": row["timestamp"],
                "user": row["user"],
                "ip": row["ip"],
                "country": row["country"],
                "severity": severity,
                "reason": reason,
                "event_type": row["event_type"],
                "mitre_id": mitre_id,
                "mitre_technique": mitre_name,
                "attempt_count": row["attempt_count"]
            })

    return pd.DataFrame(alerts)

if __name__ == "__main__":
    df = pd.read_csv("data/logs.csv")
    alerts_df = apply_rules(df)

    print(f"Rule Engine complete — {len(alerts_df)} alerts generated")
    print(f"\nSeverity Breakdown:")
    print(alerts_df["severity"].value_counts())
    print(f"\nTop MITRE Techniques:")
    print(alerts_df["mitre_technique"].value_counts())

    alerts_df.to_csv("data/rule_alerts.csv", index=False)
    print(f"\nAlerts saved to data/rule_alerts.csv")