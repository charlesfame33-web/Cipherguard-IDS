from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import pandas as pd
from typing import List

app = FastAPI(title="CipherGuard Backend")

# Load AI model
model = joblib.load("../ids_classifier.pkl")

# Running statistics
latest_results = {
    "total_flows": 0,
    "safe": 0,
    "threats": 0,
    "predictions": []
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

    latest_results["status"] = "Running"

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