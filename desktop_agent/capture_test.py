from nfstream import NFStreamer
import pandas as pd

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


def capture_live(interface):

    print("Starting Live Capture...")

    streamer = NFStreamer(
        source=interface,
        statistical_analysis=True
    )

    rows = []

    for flow in streamer:

        rows.append({
            "bidirectional_packets": flow.bidirectional_packets,
            "bidirectional_bytes": flow.bidirectional_bytes,
            "bidirectional_duration_ms": flow.bidirectional_duration_ms,
            "src2dst_packets": flow.src2dst_packets,
            "dst2src_packets": flow.dst2src_packets,
            "bidirectional_min_piat_ms": flow.bidirectional_min_piat_ms,
            "bidirectional_max_piat_ms": flow.bidirectional_max_piat_ms,
            "bidirectional_mean_piat_ms": flow.bidirectional_mean_piat_ms
        })

        if len(rows) >= 20:
            df = pd.DataFrame(rows)
            rows.clear()
            yield df