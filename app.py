import requests
from live_monitor.live_capture import start_live_monitoring
from streamlit_autorefresh import st_autorefresh

import os
from datetime import datetime

import joblib
import pandas as pd
import plotly.express as px
import streamlit as st
from nfstream import NFStreamer

st.set_page_config(
    page_title="CipherGuard IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Refresh dashboard every 5 seconds
st_autorefresh(interval=5000, key="live_refresh")

# ----------------------------------------------------
# SESSION STATE
# ----------------------------------------------------

if "threat_history" not in st.session_state:
    st.session_state.threat_history = []

if "monitoring_active" not in st.session_state:
    st.session_state.monitoring_active = False

BACKEND_URL = "http://127.0.0.1:8000"


st.markdown("""
<div style="
background: linear-gradient(135deg, #0f172a, #1e40af);
padding: 20px;
border-radius: 15px;
border: 1px solid #334155;
box-shadow: 0px 4px 15px rgba(0,0,0,0.35);
text-align: center;
margin-bottom: 20px;
">

<h1 style="
color: white;
margin-bottom: 10px;
font-size: 46px;
font-weight: bold;
">
🛡️ CipherGuard IDS
</h1>

<h3 style="
color: #dbeafe;
margin-top: 0;
margin-bottom: 12px;
font-weight: normal;
">
AI-Based Intrusion Detection System for Encrypted Network Traffic
</h3>

<p style="
color: #cbd5e1;
font-size: 17px;
margin-bottom: 0;
">
Behavior-based intrusion detection using NFStream and Machine Learning
</p>

</div>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# LOAD AI MODEL
# ----------------------------------------------------

MODEL_PATH = "ids_classifier.pkl"

if not os.path.exists(MODEL_PATH):
    st.error("❌ Trained AI model not found.")
    st.info("Run train.py to generate ids_classifier.pkl")
    st.stop()

model = joblib.load(MODEL_PATH)

# ----------------------------------------------------
# SIDEBAR
# ----------------------------------------------------

with st.sidebar:

    st.markdown(
        """
# 🛡️ CipherGuard IDS

**Version 1.0**

*AI-Based Intrusion Detection System*

---
"""
    )

    st.subheader("⚙️ SOC Control Panel")
    st.markdown("---")

    uploaded_file = st.file_uploader(
        "📂 Upload PCAP File",
        type=["pcap", "pcapng"]
    )

    st.markdown("---")

    st.subheader("System Status")

    st.caption("Current operational status of the detection engine.")

    st.success("🟢 AI Model Loaded")

    st.success("🟢 NFStream Ready")

    if uploaded_file is None:
        st.warning("🟡 Waiting for PCAP Upload")
    else:
        st.success("🟢 PCAP File Loaded Successfully")

    st.markdown("---")

    st.subheader("Detection Engine")

    st.write("• Random Forest Classifier")
    st.write("• Flow-Based Analysis")
    st.write("• Encrypted Traffic Detection")
    
    st.markdown("---")

    mode = st.radio(
        "Detection Mode",
        [
            "📂 Analyze PCAP",
            "🌐 Live Monitoring"
        ]
    )

    st.markdown("---")

    # ----------------------------------------------------
    # LIVE MONITORING CONTROLS (only show in Live Mode)
    # ----------------------------------------------------
    if mode == "🌐 Live Monitoring":
        st.subheader("🎛 Live Capture Controls")

        # Network interface selection
        try:
            resp = requests.get(f"{BACKEND_URL}/interfaces", timeout=2)
            available_interfaces = resp.json().get("interfaces", ["Ethernet 5"])
        except:
            available_interfaces = ["Ethernet 5"]

        selected_interface = st.selectbox(
            "🌐 Network Interface",
            available_interfaces,
            index=available_interfaces.index("Ethernet 5") if "Ethernet 5" in available_interfaces else 0
        )

        st.caption(f"Selected: {selected_interface}")

        col1, col2 = st.columns(2)

        with col1:
            if st.button("▶ Start Capture", use_container_width=True, disabled=st.session_state.monitoring_active):
                try:
                    resp = requests.post(
                        f"{BACKEND_URL}/start",
                        json={"interface": selected_interface, "batch_duration": 10},
                        timeout=5
                    )
                    if resp.status_code == 200:
                        st.session_state.monitoring_active = True
                        st.success("✅ Capture Started")
                    else:
                        st.error(f"❌ Error: {resp.json().get('message', 'Unknown')}")
                except requests.exceptions.ConnectionError:
                    st.error("❌ Backend Offline - Start uvicorn first")
                except Exception as e:
                    st.error(f"❌ Error: {e}")

        with col2:
            if st.button("⏹ Stop Capture", use_container_width=True, disabled=not st.session_state.monitoring_active):
                try:
                    resp = requests.post(f"{BACKEND_URL}/stop", timeout=5)
                    if resp.status_code == 200:
                        st.session_state.monitoring_active = False
                        st.warning("⏹ Capture Stopped")
                    else:
                        st.error(f"❌ Error: {resp.json().get('message', 'Unknown')}")
                except requests.exceptions.ConnectionError:
                    st.error("❌ Backend Offline")
                except Exception as e:
                    st.error(f"❌ Error: {e}")

        # Show current monitoring status
        if st.session_state.monitoring_active:
            st.success("🟢 Live Capture is ACTIVE")
        else:
            st.warning("🔴 Live Capture is STOPPED")

        st.markdown("---")

    st.subheader("ℹ️ About System")

    st.markdown("""
    **AI Model:** Random Forest Classifier

    **Detection Method:** Flow-Based Analysis

    **Supported Traffic:** TLS, HTTPS, QUIC

    **Traffic Analysis:** NFStream

    **Machine Learning:** Scikit-learn

    **Version:** 1.0
    """)

    st.markdown("---")

    st.caption("Academic Research Prototype")

# ----------------------------------------------------
# LIVE MONITORING MODE
# ----------------------------------------------------

if mode == "🌐 Live Monitoring":

    st.header("🌐 Live Monitoring Dashboard")

    try:
        response = requests.get(f"{BACKEND_URL}/latest", timeout=3)
        data = response.json()

        total = data.get("total_flows", 0)
        safe = data.get("safe", 0)
        threats = data.get("threats", 0)
        status = data.get("status", "Stopped")
        interface = data.get("interface", "N/A")
        last_error = data.get("last_error")

        # Status indicator
        if status == "Running":
            st.success(f"🟢 Live Capture ACTIVE on **{interface}**")
        else:
            st.warning("🔴 Live Capture is STOPPED (press ▶ Start Capture to begin)")

        if last_error:
            st.error(f"⚠️ Capture Error: {last_error}")

        # Metrics row
        col1, col2, col3, col4 = st.columns(4)

        with col1:
            st.metric("🌐 Total Flows", total)

        with col2:
            st.metric("✅ Safe Connections", safe)

        with col3:
            st.metric("🚨 Threats Detected", threats)

        with col4:
            detection_rate = (threats / total * 100) if total > 0 else 0
            st.metric("⚠️ Detection Rate", f"{detection_rate:.1f}%")

        # Threat alert
        if threats > 0:
            st.error(f"🚨 SECURITY ALERT: {threats} malicious flow(s) detected!")
        elif total > 0:
            st.success("✅ Network is Secure - No threats detected")
        else:
            st.info("⏳ Waiting for network traffic...")

        # Latest predictions
        predictions = data.get("predictions", [])
        if predictions:
            st.subheader("📊 Latest Flow Predictions")
            threat_count_display = sum(1 for p in predictions if p == 1)
            safe_count_display = len(predictions) - threat_count_display

            pred_col1, pred_col2 = st.columns(2)
            with pred_col1:
                st.metric("🟢 Safe Flows (last 100)", safe_count_display)
            with pred_col2:
                st.metric("🔴 Threat Flows (last 100)", threat_count_display)

            # Mini pie chart
            if threat_count_display > 0 or safe_count_display > 0:
                pie = px.pie(
                    names=["Safe", "Threats"],
                    values=[safe_count_display, threat_count_display],
                    title="Recent Traffic Classification",
                    hole=0.5,
                    color_discrete_sequence=["#2e8b57", "#ff4d4d"]
                )
                pie.update_traces(textposition="inside", textinfo="percent+label")
                pie.update_layout(showlegend=False, title_x=0.5)
                st.plotly_chart(pie, use_container_width=True)

        # Threat history trend
        if st.session_state.threat_history:
            st.markdown("---")
            st.subheader("📈 Threat Detection Trend")
            history_df = pd.DataFrame(st.session_state.threat_history)
            if not history_df.empty:
                trend = px.line(
                    history_df, x="Time", y="Threats",
                    markers=True, title="Threats Over Time"
                )
                st.plotly_chart(trend, use_container_width=True)

    except requests.exceptions.ConnectionError:
        st.error("❌ Backend server is not running.")
        st.info("Start the backend with: `cd backend && uvicorn api:app --reload --port 8000`")
    except Exception as e:
        st.error(f"❌ Error fetching live data: {e}")

    st.stop()

# ----------------------------------------------------
# PCAP ANALYSIS
# ----------------------------------------------------

if uploaded_file is not None:

    with st.spinner("🔄 Processing PCAP file..."):

        temp_pcap = "live_runtime_cache.pcap"

        with open(temp_pcap, "wb") as f:
            f.write(uploaded_file.getbuffer())

        streamer = NFStreamer(
            source=temp_pcap,
            statistical_analysis=True
        )

        df = streamer.to_pandas()

        if os.path.exists(temp_pcap):
            os.remove(temp_pcap)

    if len(df) == 0:

        st.warning("⚠️ No valid network flows were found.")

    else:

        st.success(f"✅ Successfully extracted {len(df)} network flows.")
        # ----------------------------------------------------
        # AI PREDICTION
        # ----------------------------------------------------

        features = [
            "bidirectional_packets",
            "bidirectional_bytes",
            "bidirectional_duration_ms",
            "src2dst_packets",
            "dst2src_packets",
            "bidirectional_min_piat_ms",
            "bidirectional_max_piat_ms",
            "bidirectional_mean_piat_ms"
        ]

        # Verify that all required features exist
        missing_features = [
            feature for feature in features
            if feature not in df.columns
        ]

        if missing_features:

            st.error("❌ Required features are missing from the uploaded PCAP.")

            st.write("Missing Features:")

            st.write(missing_features)

            st.stop()

        # Prepare the data
        X_live = df[features]

        # Run the AI model
        predictions = model.predict(X_live)

        probabilities = model.predict_proba(X_live)

        # Add prediction results
        df["Security Status"] = [
            "🚨 Malicious Attack"
            if prediction == 1
            else "✅ Secure Connection"
            for prediction in predictions
        ]

        df["Confidence"] = [
            f"{max(prob) * 100:.2f}%"
            for prob in probabilities
        ]

        st.success("🤖 AI prediction completed successfully.")

        total_flows = len(df)
        threat_incidents = int(sum(predictions == 1))
        safe_connections = total_flows - threat_incidents

        st.session_state.threat_history.append(
            {
                "Time": datetime.now().strftime("%H:%M:%S"),
                "Threats": threat_incidents,
            }
        )

        risk_percentage = (
            (threat_incidents / total_flows) * 100
            if total_flows > 0 else 0
        )

        average_confidence = (
            df["Confidence"]
            .str.replace("%", "", regex=False)
            .astype(float)
            .mean()
        )

        # ----------------------------------------------------
        # FLOW SUMMARY
        # ----------------------------------------------------

        most_active_app = (
            df["application_name"].mode()[0]
            if "application_name" in df.columns
            else "Unknown"
        )

        st.markdown("### 📊 Flow Summary")

        summary_col1, summary_col2 = st.columns(2)

        with summary_col1:

            st.write(f"**🌐 Total Network Flows:** {total_flows}")

            st.write(f"**✅ Secure Connections:** {safe_connections}")

            st.write(f"**🚨 Malicious Flows:** {threat_incidents}")

        with summary_col2:

            st.write(f"**⚠️ Detection Rate:** {risk_percentage:.2f}%")

            st.write(f"**📡 Most Active Application:** {most_active_app}")

            st.write(f"**🤖 Average AI Confidence:** {average_confidence:.2f}%")

        # ----------------------------------------------------
        # SECURITY DASHBOARD
        # ----------------------------------------------------

        st.markdown("---")

        with st.container():

            st.markdown("## 📊 Security Dashboard")

            st.caption(
                "Real-time summary of analysed encrypted network traffic."
            )

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "🌐 Total Network Flows",
                    total_flows
                )

            with col2:
                st.metric(
                    "🚨 Threats Detected",
                    threat_incidents
                )

            with col3:
                st.metric(
                    "✅ Secure Connections",
                    safe_connections
                )

            with col4:
                st.metric(
                    "⚠️ Risk Percentage",
                    f"{risk_percentage:.1f}%"
                )

        # ----------------------------------------------------
        # SYSTEM STATUS
        # ----------------------------------------------------

        if threat_incidents > 0:
            st.error(
                f"🚨 SECURITY ALERT: {threat_incidents} suspicious network flow(s) detected."
            )
        else:
            st.success(
                "🟢 SYSTEM STATUS: No malicious activity detected."
            )

        st.markdown("---")
        st.markdown("## 📝 Scan Summary")

        if threat_incidents > 0:
            st.warning(
                f"""
        The uploaded network traffic contained **{total_flows}** analysed network flows.
        The Artificial Intelligence model detected **{threat_incidents}** suspicious flow(s),
        representing **{risk_percentage:.1f}%** of the analysed traffic.
        Further investigation is recommended.
        """
            )
        else:
            st.success(
                f"""
        The uploaded network traffic contained **{total_flows}** analysed network flows.
        No malicious behaviour was detected during the analysis.
        The monitored traffic appears to be normal based on the AI prediction model.
        """
            )

        st.markdown("---")
        st.markdown("## 🚨 Threat Intelligence Report")

        malicious_flows = df[
            df["Security Status"] == "🚨 Malicious Attack"
        ]

        # ----------------------------------------------------
        # THREAT SUMMARY
        # ----------------------------------------------------

        if len(malicious_flows) > 0:

            highest_confidence = (
                malicious_flows["Confidence"]
                .str.replace("%", "", regex=False)
                .astype(float)
                .max()
            )

            primary_application = (
                malicious_flows["application_name"].mode()[0]
                if "application_name" in malicious_flows.columns
                else "Unknown"
            )

            most_targeted_ip = (
                malicious_flows["dst_ip"].mode()[0]
                if "dst_ip" in malicious_flows.columns
                else "Unknown"
            )

            # Dynamic Recommendation

            if len(malicious_flows) == 0:

                recommendation = (
                    "No immediate action required. Continue monitoring network traffic."
                )

            elif len(malicious_flows) <= 5:

                recommendation = (
                    "Investigate suspicious encrypted traffic and verify affected hosts."
                )

            elif len(malicious_flows) <= 15:

                recommendation = (
                    "Multiple suspicious flows detected. Perform detailed forensic analysis."
                )

            else:

                recommendation = (
                    "Critical threat level detected. Isolate affected systems immediately."
                )

            st.info(f"""
        ### 🚨 Threat Summary

        **Threats Detected:** {len(malicious_flows)}

        **Highest AI Confidence:** {highest_confidence:.2f}%

        **Primary Suspicious Application:** {primary_application}

        **Most Targeted Destination:** {most_targeted_ip}

        **Recommended Action:**
        {recommendation}
        """)

        if len(malicious_flows) > 0:

            threat_columns = [
                "src_ip",
                "dst_ip",
                "application_name",
                "Security Status",
                "Confidence"
            ]

            available_threat_columns = [
                col for col in threat_columns
                if col in malicious_flows.columns
            ]

            st.dataframe(
                malicious_flows[available_threat_columns],
                use_container_width=True
            )

        else:

            st.success("✅ No malicious connections detected.")

        # ----------------------------------------------------
        # RESULTS TABLE
        # ----------------------------------------------------

        st.markdown("## 🔍 Network Flow Analysis Results")

        display_columns = [
            "src_ip",
            "src_port",
            "dst_ip",
            "dst_port",
            "application_name",
            "Security Status",
            "Confidence"
        ]

        available_columns = [
            col for col in display_columns
            if col in df.columns
        ]

        search = st.text_input(
            "🔍 Search IP Address or Application"
        )

        filtered_df = df[available_columns]

        if search:

            filtered_df = filtered_df[
                filtered_df.astype(str)
                .apply(
                    lambda row: row.str.contains(
                        search,
                        case=False
                    ).any(),
                    axis=1
                )
            ]

        styled_df = filtered_df.style.map(
            lambda value:
                "background-color:#ff4d4d;color:white;font-weight:bold;"
                if "Malicious" in str(value)
                else (
                    "background-color:#2e8b57;color:white;font-weight:bold;"
                    if "Secure" in str(value)
                    else ""
                ),
            subset=["Security Status"]
        )

        st.dataframe(
            styled_df,
            use_container_width=True
        )

       
        st.markdown("---")
        st.markdown("## 📈 Traffic Overview")

        chart1, chart2 = st.columns(2)

        with chart1:

            pie = px.pie(
                names=["Secure Connections", "Malicious Traffic"],
                values=[safe_connections, threat_incidents],
                title="Network Traffic Classification",
                hole=0.45
            )

            pie.update_traces(
                textinfo="percent+label"
            )

            pie.update_layout(
                title_x=0.5,
                legend_title="Traffic Status"
            )
            
            st.plotly_chart(
                pie,
                use_container_width=True
            )

        with chart2:

            if "application_name" in df.columns:

                app_count = (
                    df["application_name"]
                    .value_counts()
                    .head(10)
                )

                bar = px.bar(
                    x=app_count.index,
                    y=app_count.values,
                    title="Top Network Applications",
                    labels={
                        "x": "Application Protocol",
                        "y": "Number of Network Flows"
                    },
                    text=app_count.values
                )

                bar.update_traces(
                    textposition="outside"
                )

                bar.update_layout(
                    title_x=0.5,
                    xaxis_title="Application Protocol",
                    yaxis_title="Number of Network Flows",
                    showlegend=False
                )

                st.plotly_chart(
                    bar,
                    use_container_width=True
                )


                # ---------------------------------------------
                # Threat Detection Trend
                # ---------------------------------------------

                st.markdown("---")
                st.markdown("## 📈 Threat Detection Trend")

                history_df = pd.DataFrame(
                    st.session_state.threat_history
                )

                if not history_df.empty:

                    trend_chart = px.line(
                        history_df,
                        x="Time",
                        y="Threats",
                        markers=True,
                        title="Threats Detected Over Time"
                    )

                    st.plotly_chart(
                        trend_chart,
                        use_container_width=True
                    )

            else:

                st.info("Application information not available.")

        st.markdown("---")
        st.markdown("## 📥 Export Detection Report")

        csv = df.to_csv(index=False).encode("utf-8")

        st.download_button(
            label="📥 Export Security Analysis Report (CSV)",
            data=csv,
            file_name="cipherguard_detection_report.csv",
            mime="text/csv"
        )

        # ----------------------------------------------------
        # FOOTER
        # ----------------------------------------------------

        st.markdown("---")

        st.caption("🛡️ CipherGuard IDS | Version 1.0")

        st.caption(
            "AI-Based Intrusion Detection System for Encrypted Network Traffic"
        )

        st.caption(
            "Protecting Modern Networks Through Intelligent Threat Detection."
        )