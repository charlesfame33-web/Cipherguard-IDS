from datetime import datetime
import time
import streamlit as st
import psutil
import plotly.express as px

from streamlit_autorefresh import st_autorefresh

from live_monitor.capture_engine import LiveCapture


def start_live_monitoring():

    if "monitoring" not in st.session_state:
        st.session_state.monitoring = False

    if "interface" not in st.session_state:
        st.session_state.interface = ""

    if "live_results" not in st.session_state:
        st.session_state.live_results = None

    if "threat_history" not in st.session_state:
        st.session_state.threat_history = []

    if "live_capture" not in st.session_state:
        st.session_state.live_capture = None



    st.title("🌐 Live Network Monitoring")

    st.write("Monitor encrypted network traffic in real time.")

    interfaces = list(psutil.net_if_addrs().keys())

    selected_interface = st.selectbox(
        "Select Network Interface",
        interfaces
    )

    st.session_state.interface = selected_interface

    st.success(f"📡 Monitoring Interface: {selected_interface}")

    col1, col2 = st.columns(2)

    with col1:

        if st.button(
            "▶ Start Monitoring",
            use_container_width=True
        ):
            st.session_state.monitoring = True

            if st.session_state.live_capture is None:

                st.session_state.live_capture = LiveCapture(
                    st.session_state.interface,
                    duration=60
                )

    with col2:

        if st.button(
            "⏹ Stop Monitoring",
            use_container_width=True
        ):
            st.session_state.monitoring = False
            st.session_state.live_capture = None

    if st.session_state.monitoring:

        st.success("🟢 Live Monitoring is ACTIVE")

        

        st.write(
            f"Capturing traffic from: {st.session_state.interface}"
        )

        try:

            

            # Start timing
            start_time = time.time()

            # Run live prediction
            df = st.session_state.live_capture.predict()

            # Stop timing
            end_time = time.time()

            scan_time = datetime.now().strftime(
                "%d %b %Y %I:%M:%S %p"
            )

            scan_duration = st.session_state.live_capture.duration

            

            st.session_state.live_results = df
            

            st.success(
                "🤖 AI Analysis Completed Successfully"
            )

            total_flows = len(df)
            

            threat_count = int(
                (
                    df["Security Status"]
            == "🚨 Malicious Attack"
            ).sum()
)

            safe_count = total_flows - threat_count

            detection_rate = (
                threat_count / total_flows * 100
                if total_flows > 0
                else 0
            )

            if detection_rate == 0:

                threat_level = "🟢 LOW"

            elif detection_rate < 10:

                threat_level = "🟡 MEDIUM"

            elif detection_rate < 30:

                threat_level = "🟠 HIGH"

            else:

                threat_level = "🔴 CRITICAL"

            average_confidence = (
                df["Confidence"]
                .str.replace("%", "", regex=False)
                .astype(float)
                .mean()
            )

            st.session_state.threat_history.append({

                "Time": scan_time,

                "Threats": threat_count,

                "Flows": total_flows,

                "Detection Rate": detection_rate

            })

            st.markdown("## 📊 Live Security Dashboard")

            col1, col2, col3, col4, col5 = st.columns(5)

            cards = [
                ("🌐", "Total Flows", total_flows),
                ("✅", "Benign", safe_count),
                ("🚨", "Threats", threat_count),
                ("⚠️", "Detection Rate", f"{detection_rate:.2f}%"),
                ("🤖", "AI Confidence", f"{average_confidence:.2f}%")
            ]

            for column, (icon, title, value) in zip(
                [col1, col2, col3, col4, col5],
                cards
            ):
                with column:
                    st.markdown(
                        f"""
            <div style="
            background:#18243b;
            padding:18px;
            border-radius:12px;
            border:1px solid #2f7efc;
            text-align:center;
            ">

            <h4>{icon}</h4>

            <p style="font-size:16px;
            margin-bottom:8px;
            color:#BFD3F7;">
            {title}
            </p>

            <h2 style="color:white;">
            {value}
            </h2>

            </div>
            """,
                        unsafe_allow_html=True
                    )
            st.markdown("---")
            st.markdown("## 🖥️ Live System Status")

            status1, status2 = st.columns(2)

            with status1:

                st.markdown(
                    f"""
            <div style="
            background:#18243b;
            padding:20px;
            border-radius:12px;
            border:1px solid #2f7efc;
            ">

            <h4>🖥️ Monitoring Status</h4>

            <p><b>Status:</b> 🟢 ACTIVE</p>

            <p><b>Interface:</b> {st.session_state.interface}</p>

            </div>
            """,
                    unsafe_allow_html=True
                )

            with status2:

                st.markdown(
                    f"""
            <div style="
            background:#18243b;
            padding:20px;
            border-radius:12px;
            border:1px solid #2f7efc;
            ">

            <h4>📈 Scan Information</h4>

            <p><b>Last Scan:</b> {scan_time}</p>

            <p><b>Duration:</b> {scan_duration} sec</p>

            <p><b>Threat Level:</b> {threat_level}</p>

            </div>
            """,
                    unsafe_allow_html=True
                )

            if threat_count == 0:

                st.success(
                    "🟢 No malicious encrypted traffic detected."
                )

            else:

                st.error(
                    f"🚨 ALERT: {threat_count} malicious encrypted flows detected!"
                )

            st.markdown("---")
            st.markdown("## 🚨 Threat Intelligence")

            malicious_flows = df[
                df["Security Status"] == "🚨 Malicious Attack"
            ]

            if len(malicious_flows) > 0:

                threat_columns = [
                     "src_ip",
                    "dst_ip",
                    "application_name",
                    "Security Status",
                    "Confidence"
                ]

                available_columns = [
                    column
                    for column in threat_columns
                    if column in malicious_flows.columns
                ]

                st.dataframe(
                    malicious_flows[available_columns],
                    use_container_width=True
                )

            else:

                st.success(
                    "✅ No malicious connections detected."
                )   

            with st.expander("🔍 View Complete Flow Details"):

                st.dataframe(
                    st.session_state.live_results,
                    use_container_width=True
                )

            st.markdown("---")
            st.markdown("## 📈 Traffic Overview")

            chart1, chart2 = st.columns(2)

            with chart1:

                pie = px.pie(
                    names=["Safe Connections", "Threats"],
                    values=[safe_count, threat_count],
                    title="Traffic Classification",
                    hole=0.45
                )

                pie.update_traces(
                    textposition="inside",
                    textinfo="percent+label",
                    pull=[0, 0.08]
                )

                pie.update_layout(
                    showlegend=False,
                    title_x=0.5,
                    margin=dict(l=10, r=10, t=50, b=10),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)"
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
                            "x": "Application",
                            "y": "Network Flows"
                        },
                        text=app_count.values
                    )

                    bar.update_traces(
                        textposition="outside"
                    )

                    bar.update_layout(
                        title_x=0.5,
                        xaxis_tickangle=-35,
                        margin=dict(l=20, r=20, t=50, b=20),
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="rgba(0,0,0,0)"
                    )

                    st.plotly_chart(
                        bar,
                        use_container_width=True
                    )

                else:

                    st.info("Application information not available.")
            

        except Exception as e:

            st.error(
                f"Live Monitoring Error: {e}"
        )

    else:

        st.warning("🔴 Live Monitoring is STOPPED")

    if st.session_state.live_results is not None:

        st.info("📄 Last Analysis Results")

        st.dataframe(
            st.session_state.live_results,
            use_container_width=True
        )

   