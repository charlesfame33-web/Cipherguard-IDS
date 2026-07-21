# 🛡️ CipherGuard IDS

**AI-Based Intrusion Detection System for Encrypted Network Traffic**

CipherGuard IDS is a machine learning-powered intrusion detection system that analyzes encrypted network traffic using flow-based behavioral features. It leverages NFStream for traffic analysis and a Random Forest classifier to detect malicious activity without requiring decryption.

---

## 📋 Features

- **🔍 PCAP Analysis** - Upload and analyze PCAP/PCAPNG files for threats
- **🌐 Live Monitoring** - Real-time network traffic monitoring via desktop agent
- **🤖 AI-Powered Detection** - Random Forest classifier trained on flow-based features
- **📊 Interactive Dashboard** - Streamlit-based SOC dashboard with visualizations
- **📡 Desktop Agent** - Lightweight agent for continuous traffic capture and analysis
- **📥 Report Export** - Export detection reports as CSV

## 🏗️ Architecture

```
├── app.py                          # Main Streamlit dashboard
├── train.py                        # Model training pipeline
├── extractor.py                    # PCAP to CSV feature extraction
├── backend/
│   ├── api.py                      # FastAPI backend server
│   └── predict.py                  # Prediction utilities
├── live_monitor/
│   ├── capture_engine.py           # Live capture engine (TShark)
│   ├── live_capture.py             # Streamlit live monitoring UI
│   └── predictor.py                # Real-time prediction module
├── desktop_agent/
│   ├── agent.py                    # Desktop agent entry point
│   ├── capture.py                  # Continuous traffic capture
│   ├── capture_test.py             # NFStream-based capture test
│   ├── config.py                   # Agent configuration
│   ├── install.py                  # Service installation script
│   ├── sender.py                   # Flow data sender to backend
│   └── requirements.txt            # Agent dependencies
├── dashboard/
│   ├── __init__.py
│   └── security_dashboard.py       # Dashboard components
├── css/
│   └── style.css                   # Dashboard styling
└── utils/                          # Utility modules
```

## 🚀 Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Train the AI Model

```bash
python train.py
```

This trains a Random Forest classifier on `extracted_features.csv` and saves it as `ids_classifier.pkl`.

### 3. Run the Dashboard

```bash
streamlit run app.py
```

### 4. (Optional) Start the Backend API

```bash
cd backend
uvicorn api:app --reload --port 8000
```

### 5. (Optional) Start the Desktop Agent

```bash
cd desktop_agent
python agent.py
```

## 📊 Detection Features

The model uses 8 behavioral flow features that are **uncompromised by encryption**:

| Feature | Description |
|---------|-------------|
| `bidirectional_packets` | Total packets in both directions |
| `bidirectional_bytes` | Total bytes transferred |
| `bidirectional_duration_ms` | Flow duration in milliseconds |
| `src2dst_packets` | Packets from source to destination |
| `dst2src_packets` | Packets from destination to source |
| `bidirectional_min_piat_ms` | Minimum packet inter-arrival time |
| `bidirectional_max_piat_ms` | Maximum packet inter-arrival time |
| `bidirectional_mean_piat_ms` | Average packet inter-arrival time |

## 🛠️ Requirements

- Python 3.8+
- Wireshark/TShark (for live capture)
- Windows/Linux/macOS

### Python Dependencies

- streamlit
- nfstream
- scikit-learn
- pandas
- plotly
- fastapi
- uvicorn
- joblib
- requests
- psutil
- streamlit-autorefresh

## 📝 Usage Examples

### Analyze a PCAP File

1. Launch the dashboard: `streamlit run app.py`
2. Upload a `.pcap` or `.pcapng` file
3. View the AI-powered analysis results

### Live Network Monitoring

1. Start the backend: `cd backend && uvicorn api:app --reload --port 8000`
2. Start the desktop agent: `cd desktop_agent && python agent.py`
3. Launch the dashboard and select "Live Monitoring" mode

## 📄 License

Academic Research Prototype

## 👨‍💻 Author

**Charles Fame**

---

*Protecting Modern Networks Through Intelligent Threat Detection*