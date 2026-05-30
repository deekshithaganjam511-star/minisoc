import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import json
from datetime import datetime

# --- Page Config ---
st.set_page_config(
    page_title="MiniSOC Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# --- Load Data ---
@st.cache_data
def load_data():
    alerts = pd.read_csv("data/final_alerts.csv")
    logs = pd.read_csv("data/logs.csv")
    ml = pd.read_csv("data/ml_results.csv")
    return alerts, logs, ml

alerts, logs, ml = load_data()

# --- Header ---
st.title("🛡️ MiniSOC — Security Operations Center")
st.markdown("Real-time threat detection and incident monitoring dashboard")
st.divider()

# --- Top KPI Metrics ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric("🚨 Total Alerts", len(alerts))
with col2:
    st.metric("🔴 Critical", len(alerts[alerts["severity"] == "CRITICAL"]))
with col3:
    st.metric("🟡 Medium", len(alerts[alerts["severity"] == "MEDIUM"]))
with col4:
    anomalies = len(ml[ml["ml_label"] == "ANOMALY"])
    st.metric("🤖 ML Anomalies", anomalies)

st.divider()

# --- Row 1: Severity Chart + Event Type Chart ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("📊 Alerts by Severity")
    severity_counts = alerts["severity"].value_counts().reset_index()
    severity_counts.columns = ["Severity", "Count"]
    colors = {"CRITICAL": "#FF4B4B", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#00CC44"}
    fig = px.bar(severity_counts, x="Severity", y="Count",
                 color="Severity",
                 color_discrete_map=colors)
    fig.update_layout(showlegend=False, height=300)
    st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("🎯 Attack Types Distribution")
    event_counts = alerts["event_type"].value_counts().reset_index()
    event_counts.columns = ["Attack Type", "Count"]
    fig2 = px.pie(event_counts, values="Count", names="Attack Type",
                  color_discrete_sequence=px.colors.sequential.RdBu)
    fig2.update_layout(height=300)
    st.plotly_chart(fig2, use_container_width=True)

st.divider()

# --- Row 2: Attack Timeline ---
st.subheader("📈 Attack Timeline")
alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])
alerts["hour"] = alerts["timestamp"].dt.floor("h")
timeline = alerts.groupby(["hour", "severity"]).size().reset_index(name="count")
fig3 = px.line(timeline, x="hour", y="count", color="severity",
               color_discrete_map={"CRITICAL": "#FF4B4B", "HIGH": "#FF8C00",
                                   "MEDIUM": "#FFD700", "LOW": "#00CC44"})
fig3.update_layout(height=300)
st.plotly_chart(fig3, use_container_width=True)

st.divider()

# --- Row 3: Top Targeted Users + Top Attacking IPs ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("👤 Top Targeted Users")
    top_users = alerts["user"].value_counts().head(8).reset_index()
    top_users.columns = ["User", "Alert Count"]
    fig4 = px.bar(top_users, x="Alert Count", y="User",
                  orientation="h", color="Alert Count",
                  color_continuous_scale="Reds")
    fig4.update_layout(height=300, showlegend=False)
    st.plotly_chart(fig4, use_container_width=True)

with col2:
    st.subheader("🌐 Top Attacking IPs")
    top_ips = alerts["ip"].value_counts().head(8).reset_index()
    top_ips.columns = ["IP Address", "Alert Count"]
    fig5 = px.bar(top_ips, x="Alert Count", y="IP Address",
                  orientation="h", color="Alert Count",
                  color_continuous_scale="OrRd")
    fig5.update_layout(height=300, showlegend=False)
    st.plotly_chart(fig5, use_container_width=True)

st.divider()

# --- Row 4: MITRE ATT&CK Techniques ---
st.subheader("🗺️ MITRE ATT&CK Techniques Observed")
mitre_counts = alerts["mitre_technique"].value_counts().reset_index()
mitre_counts.columns = ["Technique", "Count"]
fig6 = px.bar(mitre_counts, x="Technique", y="Count",
              color="Count", color_continuous_scale="Reds")
fig6.update_layout(height=300)
st.plotly_chart(fig6, use_container_width=True)

st.divider()

# --- Row 5: ML Risk Score Distribution ---
st.subheader("🤖 ML Risk Score Distribution")
fig7 = px.histogram(ml, x="risk_score", color="ml_label",
                    nbins=50,
                    color_discrete_map={"ANOMALY": "#FF4B4B", "NORMAL": "#00CC44"})
fig7.update_layout(height=300)
st.plotly_chart(fig7, use_container_width=True)

st.divider()

# --- Live Alert Feed ---
st.subheader("🚨 Live Alert Feed")

severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])

if severity_filter == "ALL":
    filtered = alerts
else:
    filtered = alerts[alerts["severity"] == severity_filter]

st.dataframe(
    filtered[["alert_id", "timestamp", "user", "ip", "country",
              "severity", "reason", "mitre_technique",
              "risk_score", "recommended_action"]].head(50),
    use_container_width=True,
    height=400
)

st.caption(f"Showing {min(50, len(filtered))} of {len(filtered)} alerts")