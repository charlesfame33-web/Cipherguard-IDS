import subprocess
import os
import time
import pandas as pd
from nfstream import NFStreamer

PCAP_FILE = "live_capture.pcap"

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


def start_tshark(interface="Ethernet 5"):
    """
    Start Wireshark Tshark in background
    """

    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)

    command = [
        r"C:\Program Files\Wireshark\tshark.exe",
        "-i", interface,
        "-w", PCAP_FILE
    ]
    


    process = subprocess.Popen(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    return process


def capture_live(interface="Ethernet 5"):

    print("Starting Tshark Live Capture...")

    tshark = start_tshark(interface)

    time.sleep(8)

    try:

        while True:

            if not os.path.exists(PCAP_FILE):
                time.sleep(2)
                continue

            streamer = NFStreamer(
                source=PCAP_FILE,
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

            if len(rows):

                yield pd.DataFrame(rows)

            time.sleep(5)

    finally:
        tshark.kill()