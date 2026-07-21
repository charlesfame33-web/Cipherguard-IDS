import requests
from config import SERVER_URL

def send_flows(df):

    try:
        payload = {
            "flows": df.to_dict(orient="records")
        }

        response = requests.post(
            f"{SERVER_URL}/predict",
            json=payload,
            timeout=20
        )

        return response.json()

    except Exception as e:
        print("Connection Error:", e)
        return None