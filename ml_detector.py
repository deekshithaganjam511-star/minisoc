import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import warnings
warnings.filterwarnings("ignore")

# --- Load Data ---
df = pd.read_csv("data/logs.csv")

# --- Feature Engineering ---
# Convert timestamp to hour (ML needs numbers, not strings)
df["hour"] = pd.to_datetime(df["timestamp"]).dt.hour

# Encode categorical columns to numbers
le_user = LabelEncoder()
le_country = LabelEncoder()
le_status = LabelEncoder()

df["user_encoded"] = le_user.fit_transform(df["user"])
df["country_encoded"] = le_country.fit_transform(df["country"])
df["status_encoded"] = le_status.fit_transform(df["status"])

# --- Select Features for ML ---
features = [
    "hour",
    "attempt_count",
    "user_encoded",
    "country_encoded",
    "status_encoded"
]

X = df[features]

# --- Train Isolation Forest ---
print("Training Isolation Forest model...")
model = IsolationForest(
    contamination=0.15,  # Expects ~15% anomalies
    random_state=42,
    n_estimators=100
)
model.fit(X)

# --- Predict Anomalies ---
df["anomaly_score"] = model.decision_function(X)  # Raw score
df["is_anomaly"] = model.predict(X)  # -1 = anomaly, 1 = normal

# --- Normalize score to 0-100 risk scale ---
min_score = df["anomaly_score"].min()
max_score = df["anomaly_score"].max()
df["risk_score"] = (1 - (df["anomaly_score"] - min_score) / (max_score - min_score)) * 100
df["risk_score"] = df["risk_score"].round(2)

# --- Label anomalies ---
df["ml_label"] = df["is_anomaly"].apply(lambda x: "ANOMALY" if x == -1 else "NORMAL")

# --- Results ---
print(f"\nML Detection Complete")
print(f"Total logs analyzed: {len(df)}")
print(f"\nML Label Breakdown:")
print(df["ml_label"].value_counts())
print(f"\nAverage Risk Score by Event Type:")
print(df.groupby("event_type")["risk_score"].mean().round(2).sort_values(ascending=False))

# --- Save Results ---
df.to_csv("data/ml_results.csv", index=False)
print(f"\nML results saved to data/ml_results.csv")

# --- Show top 10 highest risk logs ---
print(f"\n Top 10 Highest Risk Logs:")
top_risks = df.nlargest(10, "risk_score")[["timestamp", "user", "ip", "country", "event_type", "risk_score", "ml_label"]]
print(top_risks.to_string(index=False))
