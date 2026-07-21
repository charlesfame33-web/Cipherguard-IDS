"""
CipherGuard Live Capture Manager

Manages background thread for live network traffic capture using TShark,
feature extraction via NFStream, and AI-based threat prediction.
"""

import threading
import subprocess
import os
import time
import joblib
import pandas as pd
from datetime import datetime
from nfstream import NFStreamer


# Feature columns expected by the AI model
FEATURES = [
    "bidirectional_packets",
    "bidirectional_bytes",
    "bidirectional_duration_ms",
    "src2dst_packets",
    "dst2src_packets",
    "bidirectional_min_piat_ms",
    "bidirectional_max_piat_ms",
    "bidirectional_mean_piat_ms"
]

# Default TShark path for Windows
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


class CaptureManager:
    """
    Manages live network capture in a background thread.
    Captures traffic in batches, runs AI prediction, and accumulates results.
    """

    def __init__(self, model_path="ids_classifier.pkl"):
        self.interface = None
        self.running = False
        self.thread = None
        self.tshark_process = None

        # Load AI model
        self.model = joblib.load(model_path)

        # Accumulated results (thread-safe via Lock)
        self.lock = threading.Lock()
        self.total_flows = 0
        self.safe_count = 0
        self.threat_count = 0
        self.predictions = []
        self.last_error = None
        self.capture_start_time = None

    def _capture_loop(self, interface, batch_duration=10):
        """
        Background loop: captures traffic in batches, analyzes, accumulates results.
        """
        self.interface = interface
        self.capture_start_time = datetime.now()

        while self.running:
            try:
                pcap_file = "live_capture_batch.pcap"

                # Remove old PCAP if exists
                if os.path.exists(pcap_file):
                    os.remove(pcap_file)

                # Step 1: Capture traffic batch with TShark
                subprocess.run(
                    [TSHARK_PATH, "-i", interface,
                     "-a", f"duration:{batch_duration}",
                     "-w", pcap_file],
                    capture_output=True,
                    timeout=batch_duration + 5
                )

                if not self.running:
                    break

                # Step 2: Analyze captured PCAP with NFStream
                if os.path.exists(pcap_file) and os.path.getsize(pcap_file) > 0:
                    streamer = NFStreamer(
                        source=pcap_file,
                        statistical_analysis=True
                    )
                    df = streamer.to_pandas()

                    # Step 3: Run AI prediction
                    if len(df) > 0:
                        self._analyze_batch(df)

                # Cleanup
                if os.path.exists(pcap_file):
                    os.remove(pcap_file)

            except subprocess.TimeoutExpired:
                continue
            except Exception as e:
                self.last_error = str(e)
                time.sleep(1)

    def _analyze_batch(self, df):
        """Run AI prediction on a batch of flows and update results."""
        # Ensure required features exist
        missing = [f for f in FEATURES if f not in df.columns]
        if missing:
            # Try with available columns
            available = [f for f in FEATURES if f in df.columns]
            if len(available) < len(FEATURES):
                return
            X = df[available]
        else:
            X = df[FEATURES]

        predictions = self.model.predict(X)

        with self.lock:
            batch_threats = int(sum(predictions == 1))
            batch_safe = len(predictions) - batch_threats

            self.total_flows += len(predictions)
            self.safe_count += batch_safe
            self.threat_count += batch_threats
            self.predictions.extend(predictions.tolist())
            # Keep last 200 predictions
            self.predictions = self.predictions[-200:]

    def start(self, interface, batch_duration=10):
        """Start live capture on the given interface."""
        if self.running:
            return False

        self.running = True
        self.total_flows = 0
        self.safe_count = 0
        self.threat_count = 0
        self.predictions = []
        self.last_error = None

        self.thread = threading.Thread(
            target=self._capture_loop,
            args=(interface, batch_duration),
            daemon=True
        )
        self.thread.start()
        return True

    def stop(self):
        """Stop live capture."""
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=15)

        # Cleanup temp files
        for f in ["live_capture_batch.pcap"]:
            if os.path.exists(f):
                os.remove(f)

    def get_results(self):
        """Get current accumulated results (thread-safe)."""
        with self.lock:
            return {
                "status": "Running" if self.running else "Stopped",
                "total_flows": self.total_flows,
                "safe": self.safe_count,
                "threats": self.threat_count,
                "predictions": self.predictions[-100:],
                "interface": self.interface or "",
                "last_error": self.last_error
            }


# Global singleton instance
_capture_manager = None


def get_capture_manager(model_path="ids_classifier.pkl"):
    """Get or create the global CaptureManager instance."""
    global _capture_manager
    if _capture_manager is None:
        _capture_manager = CaptureManager(model_path)
    return _capture_manager