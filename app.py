import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
import subprocess
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import numpy as np

# --- Page Config ---
st.set_page_config(
    page_title="MiniSOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- Run Full Pipeline ---
def run_pipeline():
    with st.spinner(" Generating new attack simulation..."):
        subprocess.run(["python", "genarate.py"], check=True)
        subprocess.run(["python", "rules.py"], check=True)
        subprocess.run(["python", "ml_detector.py"], check=True)
        subprocess.run(["python", "alert_system.py"], check=True)
    st.success(" New simulation generated!")
    st.cache_data.clear()

# --- Load Data ---
@st.cache_data
def load_data():
    alerts = pd.read_csv("data/final_alerts.csv")
    logs = pd.read_csv("data/logs.csv")
    ml = pd.read_csv("data/ml_results.csv")
    return alerts, logs, ml

# --- Manual Log Analyzer ---
def analyze_single_log(user, ip, country, status, attempt_count, hour):
    ATTACK_IPS = ["185.220.101.45", "45.33.32.156", "103.21.244.0", "198.51.100.23", "192.0.2.77"]
    HIGH_RISK_COUNTRIES = ["RU", "CN", "KP", "NG"]

    alerts = []
    risk_score = 0

    # Rule checks
    if ip in ATTACK_IPS:
        alerts.append(("🔴 CRITICAL", "Known malicious IP detected"))
        risk_score += 40
    if attempt_count >= 5:
        alerts.append(("🔴 CRITICAL", f"Brute force detected ({attempt_count} attempts)"))
        risk_score += 30
    if country in HIGH_RISK_COUNTRIES and status == "FAILED":
        alerts.append(("🟠 HIGH", f"Failed login from high-risk country: {country}"))
        risk_score += 20
    if 0 <= hour <= 4:
        alerts.append(("🟡 MEDIUM", "After-hours login attempt"))
        risk_score += 10
    if status == "FAILED" and attempt_count >= 3:
        alerts.append(("🟠 HIGH", "Multiple failed login attempts"))
        risk_score += 15

    # ML score estimate
    try:
        ml_data = pd.read_csv("data/ml_results.csv")
        le_user = LabelEncoder()
        le_country = LabelEncoder()
        le_status = LabelEncoder()
        le_user.fit(ml_data["user"])
        le_country.fit(ml_data["country"])
        le_status.fit(ml_data["status"])

        user_enc = le_user.transform([user])[0] if user in le_user.classes_ else 0
        country_enc = le_country.transform([country])[0] if country in le_country.classes_ else 0
        status_enc = le_status.transform([status])[0] if status in le_status.classes_ else 0

        features = ml_data[["hour", "attempt_count", "user_encoded", "country_encoded", "status_encoded"]]
        model = IsolationForest(contamination=0.15, random_state=42)
        model.fit(features)

        score = model.decision_function([[hour, attempt_count, user_enc, country_enc, status_enc]])[0]
        ml_risk = round((1 - (score + 0.5)) * 100, 2)
        ml_risk = max(0, min(100, ml_risk))
        risk_score = min(100, risk_score + ml_risk * 0.3)
    except:
        ml_risk = 50

    return alerts, round(risk_score, 2), round(ml_risk, 2)

# --- Header ---
st.title(" MiniSOC — Security Operations Center")
st.markdown("Real-time threat detection and incident monitoring dashboard")

# --- Simulation Controls ---
st.divider()
col_btn1, col_btn2 = st.columns([1, 3])
with col_btn1:
    if st.button(" Generate New Simulation", type="primary"):
        run_pipeline()

st.divider()

# --- Load Data ---
try:
    alerts, logs, ml = load_data()
    data_loaded = True
except:
    st.warning("No data found. Click 'Generate New Simulation' to start!")
    data_loaded = False

if data_loaded:
    # --- KPI Metrics ---
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(" Total Alerts", len(alerts))
    with col2:
        st.metric("🔴 Critical", len(alerts[alerts["severity"] == "CRITICAL"]))
    with col3:
        st.metric("🟡 Medium", len(alerts[alerts["severity"] == "MEDIUM"]))
    with col4:
        anomalies = len(ml[ml["ml_label"] == "ANOMALY"])
        st.metric("ML Anomalies", anomalies)

    st.divider()

    # --- Charts Row 1 ---
    col1, col2 = st.columns(2)
    with col1:
        st.subheader(" Alerts by Severity")
        severity_counts = alerts["severity"].value_counts().reset_index()
        severity_counts.columns = ["Severity", "Count"]
        colors = {"CRITICAL": "#FF4B4B", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#00CC44"}
        fig = px.bar(severity_counts, x="Severity", y="Count",
                     color="Severity", color_discrete_map=colors)
        fig.update_layout(showlegend=False, height=300)
        st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader(" Attack Types Distribution")
        event_counts = alerts["event_type"].value_counts().reset_index()
        event_counts.columns = ["Attack Type", "Count"]
        fig2 = px.pie(event_counts, values="Count", names="Attack Type",
                      color_discrete_sequence=px.colors.sequential.RdBu)
        fig2.update_layout(height=300)
        st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # --- Attack Timeline ---
    st.subheader(" Attack Timeline")
    alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
    alerts["hour"] = alerts["timestamp"].dt.floor("h")
    timeline = alerts.groupby(["hour", "severity"]).size().reset_index(name="count")
    fig3 = px.line(timeline, x="hour", y="count", color="severity",
                   color_discrete_map={"CRITICAL": "#FF4B4B", "HIGH": "#FF8C00",
                                       "MEDIUM": "#FFD700", "LOW": "#00CC44"})
    fig3.update_layout(height=300)
    st.plotly_chart(fig3, use_container_width=True)

    st.divider()

    # --- Top Users + IPs ---
    col1, col2 = st.columns(2)
    with col1:
        st.subheader(" Top Targeted Users")
        top_users = alerts["user"].value_counts().head(8).reset_index()
        top_users.columns = ["User", "Alert Count"]
        fig4 = px.bar(top_users, x="Alert Count", y="User",
                      orientation="h", color="Alert Count",
                      color_continuous_scale="Reds")
        fig4.update_layout(height=300, showlegend=False)
        st.plotly_chart(fig4, use_container_width=True)

    with col2:
        st.subheader(" Top Attacking IPs")
        top_ips = alerts["ip"].value_counts().head(8).reset_index()
        top_ips.columns = ["IP Address", "Alert Count"]
        fig5 = px.bar(top_ips, x="Alert Count", y="IP Address",
                      orientation="h", color="Alert Count",
                      color_continuous_scale="OrRd")
        fig5.update_layout(height=300, showlegend=False)
        st.plotly_chart(fig5, use_container_width=True)

    st.divider()

    # --- MITRE ATT&CK ---
    st.subheader("MITRE ATT&CK Techniques Observed")
    mitre_counts = alerts["mitre_technique"].value_counts().reset_index()
    mitre_counts.columns = ["Technique", "Count"]
    fig6 = px.bar(mitre_counts, x="Technique", y="Count",
                  color="Count", color_continuous_scale="Reds")
    fig6.update_layout(height=300)
    st.plotly_chart(fig6, use_container_width=True)

    st.divider()

    # --- ML Risk Score Distribution ---
    st.subheader(" ML Risk Score Distribution")
    fig7 = px.histogram(ml, x="risk_score", color="ml_label",
                        nbins=50,
                        color_discrete_map={"ANOMALY": "#FF4B4B", "NORMAL": "#00CC44"})
    fig7.update_layout(height=300)
    st.plotly_chart(fig7, use_container_width=True)

    st.divider()

    # --- Alert Feed ---
    st.subheader("Live Alert Feed")
    severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
    filtered = alerts if severity_filter == "ALL" else alerts[alerts["severity"] == severity_filter]
    st.dataframe(
        filtered[["alert_id", "timestamp", "user", "ip", "country",
                  "severity", "reason", "mitre_technique",
                  "risk_score", "recommended_action"]].head(50),
        use_container_width=True,
        height=400
    )
    st.caption(f"Showing {min(50, len(filtered))} of {len(filtered)} alerts")

# --- Manual Log Analyzer ---
st.divider()
st.subheader("🔍 Manual Log Analyzer")
st.markdown("Enter a suspicious log entry below to get an instant risk assessment.")

with st.form("log_form"):
    col1, col2, col3 = st.columns(3)
    with col1:
        m_user = st.selectbox("Username", ["admin", "root", "john.doe", "jane.smith", "guest", "hr.user", "dev.ops", "deekshitha"])
        m_status = st.selectbox("Login Status", ["FAILED", "SUCCESS"])
    with col2:
        m_ip = st.text_input("IP Address", placeholder="e.g. 185.220.101.45")
        m_attempt = st.number_input("Attempt Count", min_value=1, max_value=50, value=1)
    with col3:
        m_country = st.selectbox("Country", ["US", "IN", "RU", "CN", "BR", "DE", "NG", "KP"])
        m_hour = st.slider("Login Hour (0-23)", 0, 23, 9)

    submitted = st.form_submit_button("🔍 Analyze Log", type="primary")

if submitted and m_ip:
    rule_alerts, risk_score, ml_risk = analyze_single_log(
        m_user, m_ip, m_country, m_status, m_attempt, m_hour
    )

    st.divider()
    col1, col2, col3 = st.columns(3)
    with col1:
        color = "red" if risk_score >= 70 else "orange" if risk_score >= 40 else "green"
        st.metric("Overall Risk Score", f"{risk_score}/100")
    with col2:
        st.metric("ML Anomaly Score", f"{ml_risk}/100")
    with col3:
        verdict = "🔴 HIGH RISK" if risk_score >= 70 else "🟠 MEDIUM RISK" if risk_score >= 40 else "🟢 LOW RISK"
        st.metric("Verdict", verdict)

    if rule_alerts:
        st.subheader(" Triggered Alerts")
        for severity, reason in rule_alerts:
            st.error(f"{severity} — {reason}")
    else:
        st.success("No threats detected for this log entry")