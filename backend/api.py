from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import os
from typing import List, Optional

# Import the live capture manager
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from live_monitor.capture_manager import get_capture_manager

app = FastAPI(title="CipherGuard Backend")

# Load AI model - try multiple paths
model_paths = [
    "ids_classifier.pkl",
    "../ids_classifier.pkl",
    os.path.join(os.path.dirname(__file__), "..", "ids_classifier.pkl")
]

model = None
for path in model_paths:
    if os.path.exists(path):
        model = joblib.load(path)
        break

if model is None:
    raise FileNotFoundError(
        "ids_classifier.pkl not found. Run train.py first."
    )

# Running statistics (for desktop agent /predict endpoint)
latest_results = {
    "total_flows": 0,
    "safe": 0,
    "threats": 0,
    "predictions": [],
    "status": "Running"
}


class FlowData(BaseModel):
    flows: List[dict]


class StartRequest(BaseModel):
    interface: str = "Ethernet 5"
    batch_duration: int = 10


@app.get("/")
def home():
    return {
        "status": "CipherGuard Backend Running"
    }


@app.post("/predict")
def predict(data: FlowData):

    global latest_results

    df = pd.DataFrame(data.flows)

    predictions = model.predict(df).tolist()

    safe = predictions.count(0)
    threats = predictions.count(1)

    # KEEP RUNNING TOTALS
    latest_results["total_flows"] += len(predictions)
    latest_results["safe"] += safe
    latest_results["threats"] += threats

    # Keep only the latest 100 predictions
    latest_results["predictions"].extend(predictions)
    latest_results["predictions"] = latest_results["predictions"][-100:]

    return latest_results


@app.get("/latest")
def latest():
    """
    Returns the latest results from the live capture manager.
    If capture is not running, returns the desktop agent results.
    """
    capture_mgr = get_capture_manager()
    if capture_mgr.running:
        return capture_mgr.get_results()
    return latest_results


@app.post("/reset")
def reset():

    global latest_results

    latest_results = {
        "status": "Stopped",
        "total_flows": 0,
        "safe": 0,
        "threats": 0,
        "predictions": []
    }

    return latest_results


@app.post("/start")
def start_monitoring(request: Optional[StartRequest] = None):
    """
    Start live network capture on the specified interface.
    Default interface: "Ethernet 5"
    """
    interface = "Ethernet 5"
    batch_duration = 10

    if request is not None:
        interface = request.interface
        batch_duration = request.batch_duration

    capture_mgr = get_capture_manager()

    if capture_mgr.running:
        return {
            "status": "Already Running",
            "message": f"Capture is already running on {capture_mgr.interface}"
        }

    success = capture_mgr.start(interface, batch_duration)

    if success:
        return {
            "status": "Running",
            "message": f"Live capture started on {interface}",
            "interface": interface
        }
    else:
        return {
            "status": "Error",
            "message": "Failed to start capture"
        }


@app.post("/stop")
def stop_monitoring():
    """
    Stop live network capture.
    """
    capture_mgr = get_capture_manager()

    if not capture_mgr.running:
        return {
            "status": "Stopped",
            "message": "Capture is not running"
        }

    capture_mgr.stop()

    return {
        "status": "Stopped",
        "message": "Live capture stopped",
        "results": capture_mgr.get_results()
    }


@app.get("/interfaces")
def list_interfaces():
    """List available network interfaces."""
    import psutil
    interfaces = list(psutil.net_if_addrs().keys())
    return {"interfaces": interfaces}