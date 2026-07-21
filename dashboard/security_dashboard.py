"""
CipherGuard Security Dashboard Module

Reusable dashboard components for displaying security analysis results.
"""

import streamlit as st
import plotly.express as px
import pandas as pd


def show_security_dashboard(df):
    """
    Display a comprehensive security dashboard for analyzed network flows.

    Args:
        df: DataFrame containing network flow data with Security Status and Confidence columns
    """
    st.markdown("## 📊 Security Dashboard")

    if df is None or df.empty:
        st.info("No data available for dashboard visualization.")
        return

    # Calculate metrics
    total_flows = len(df)
    threat_count = int(
        (df["Security Status"] == "🚨 Malicious Attack").sum()
        if "Security Status" in df.columns
        else 0
    )
    safe_count = total_flows - threat_count
    detection_rate = (threat_count / total_flows * 100) if total_flows > 0 else 0

    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🌐 Total Flows", total_flows)
    with col2:
        st.metric("✅ Safe", safe_count)
    with col3:
        st.metric("🚨 Threats", threat_count)
    with col4:
        st.metric("⚠️ Detection Rate", f"{detection_rate:.1f}%")

    # Traffic classification pie chart
    st.markdown("### 📈 Traffic Classification")
    pie = px.pie(
        names=["Safe Connections", "Threats"],
        values=[safe_count, threat_count],
        title="Network Traffic Classification",
        hole=0.45,
        color_discrete_sequence=["#2e8b57", "#ff4d4d"]
    )
    pie.update_traces(textposition="inside", textinfo="percent+label")
    pie.update_layout(showlegend=False, title_x=0.5)
    st.plotly_chart(pie, use_container_width=True)

    # Application breakdown if available
    if "application_name" in df.columns:
        st.markdown("### 📡 Top Applications")
        app_count = df["application_name"].value_counts().head(10)
        bar = px.bar(
            x=app_count.index,
            y=app_count.values,
            title="Top Network Applications",
            labels={"x": "Application", "y": "Flows"},
            text=app_count.values
        )
        bar.update_traces(textposition="outside")
        bar.update_layout(title_x=0.5, xaxis_tickangle=-35)
        st.plotly_chart(bar, use_container_width=True)

    # Threat details
    if threat_count > 0 and "Security Status" in df.columns:
        st.markdown("### 🚨 Threat Details")
        threats = df[df["Security Status"] == "🚨 Malicious Attack"]
        cols = [c for c in ["src_ip", "dst_ip", "application_name", "Confidence"]
                if c in threats.columns]
        if cols:
            st.dataframe(threats[cols], use_container_width=True)
    else:
        st.success("✅ No threats detected in the analyzed traffic.")