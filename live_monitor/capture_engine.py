import subprocess
import joblib
import pandas as pd
import time

from extractor import convert_pcap_to_csv


class LiveCapture:

    def __init__(self, interface, duration=60):

        self.interface = interface
        self.duration = duration

        self.model = joblib.load("ids_classifier.pkl")

        self.features = [
            "bidirectional_packets",
            "bidirectional_bytes",
            "bidirectional_duration_ms",
            "src2dst_packets",
            "dst2src_packets",
            "bidirectional_min_piat_ms",
            "bidirectional_max_piat_ms",
            "bidirectional_mean_piat_ms"
        ]

        self.running = False

    def stop(self):
        self.running = False

    def capture(self):

        subprocess.run(
            [
                r"C:\Program Files\Wireshark\tshark.exe",
                "-i",
                self.interface,
                "-a",
                f"duration:{self.duration}",
                "-w",
                "live_capture.pcap"
            ],
            check=True
        )

    def extract(self):

        convert_pcap_to_csv(
            "live_capture.pcap",
            "extracted_features.csv"
        )

        return pd.read_csv(
            "extracted_features.csv"
        )

    def predict(self):

        capture_start = time.time()
        self.capture()
        capture_end = time.time()

        extract_start = time.time()
        df = self.extract()
        extract_end = time.time()

        missing = [
            feature
            for feature in self.features
            if feature not in df.columns
        ]

        if missing:
            raise Exception(
                f"Missing features: {missing}"
            )

        X_live = df[self.features]

        predictions = self.model.predict(X_live)

        probabilities = self.model.predict_proba(X_live)

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

        return df