import joblib


class LivePredictor:

    def __init__(self):

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

    def predict(self, df):

        X = df[self.features]

        predictions = self.model.predict(X)

        df["Security Status"] = [
            "Threat" if p == 1 else "Safe"
            for p in predictions
        ]

        return df, predictions