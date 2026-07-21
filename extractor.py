import pandas as pd
from nfstream import NFStreamer

def convert_pcap_to_csv(pcap_file_path, csv_output_path):
    print(f"🔄 Reading raw packet capture: {pcap_file_path}...")
    
    # NFStreamer handles layer-4 flow reassembly autonomously 
    streamer = NFStreamer(
        source=pcap_file_path,
        statistical_analysis=True,  # Crucial: Calculates mathematical packet sizes/intervals
        accounting_mode=1           # Optimizes speed for batch files
    )
    
    # Stream directly into a Pandas DataFrame
    df = streamer.to_pandas()
    
    # Save features into a clean CSV spreadsheet
    df.to_csv(csv_output_path, index=False)
    print(f"✅ Success! Generated structured dataset: {csv_output_path} ({len(df)} network flows recorded)")

if __name__ == "__main__":
    # Point this to a sample .pcap file in your folder to test it
    convert_pcap_to_csv("network_traffic.pcap", "extracted_features.csv")
