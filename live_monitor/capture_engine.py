import subprocess
import joblib
import pandas as pd
import time

from extractor import convert_pcap_to_csv



class LiveCapture:

    def __init__(self, interface, duration=60):

        print("INIT 1")

        self.interface = interface
        self.duration = duration

        print("INIT 2")

        self.model = joblib.load("ids_classifier.pkl")

        print("INIT 3")

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

        print("INIT 4")

        self.running = False

    def capture(self):

         self.running = True

    def stop(self):

        self.running = False

    def capture(self):

        print("STEP 1: Starting TShark capture...")

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

        print("STEP 2: Capture finished.")

    def extract(self):

        print("STEP 3: Running extractor...")

        convert_pcap_to_csv(
            "live_capture.pcap",
            "extracted_features.csv"
        )

        print("STEP 4: CSV created.")

        return pd.read_csv(
            "extracted_features.csv"
        )

    def predict(self):

        print("STEP 1: Starting prediction")

        capture_start = time.time()

        self.capture()

        capture_end = time.time()

        print(f"Capture took: {capture_end - capture_start:.2f} seconds")

        print("STEP 2: Capture completed")

        extract_start = time.time()

        df = self.extract()

        extract_end = time.time()

        print(f"Feature extraction took: {extract_end - extract_start:.2f} seconds")

        print("STEP 3: Feature extraction completed")

        missing = [
            feature
            for feature in self.features
            if feature not in df.columns
        ]

        if missing:

            raise Exception(
                f"Missing features: {missing}"
            )

        print("STEP 4: Preparing model input")

        X_live = df[self.features]

        print("STEP 5: Running AI model")

        predictions = self.model.predict(
            X_live
        )

        print("STEP 6: Prediction completed")

        probabilities = self.model.predict_proba(
            X_live
        )

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

        print("STEP 7: Returning results")

        return df