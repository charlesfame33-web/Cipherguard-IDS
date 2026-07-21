from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
import os
from typing import List

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

# Running statistics
latest_results = {
    "total_flows": 0,
    "safe": 0,
    "threats": 0,
    "predictions": [],
    "status": "Running"
}


class FlowData(BaseModel):
    flows: List[dict]


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
def start_monitoring():

    global latest_results

    latest_results["status"] = "Running"

    return latest_results


@app.post("/stop")
def stop_monitoring():

    global latest_results

    latest_results["status"] = "Stopped"

    return latest_results