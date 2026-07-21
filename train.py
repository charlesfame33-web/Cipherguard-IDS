import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

def train_ids_model(csv_path, model_output_path):
    print("📦 Loading dataset spreadsheet...")
    df = pd.read_csv(csv_path)
    
    # Behavioral features uncompromised by TLS/SSL encryption
    features = [
        'bidirectional_packets', 
        'bidirectional_bytes', 
        'bidirectional_duration_ms', 
        'src2dst_packets', 
        'dst2src_packets',
        'bidirectional_min_piat_ms',  # Minimum Packet Inter-Arrival Time
        'bidirectional_max_piat_ms',  # Maximum Packet Inter-Arrival Time
        'bidirectional_mean_piat_ms'  # Average Packet Inter-Arrival Time
    ]
    
    # Setup handling for target classification labels (0 = Benign, 1 = Attack)
    if 'label' not in df.columns:
        print("⚠️ 'label' column not found in raw test PCAP. Injecting synthetic targets for training verification...")
        df['label'] = np.random.choice([0, 1], size=len(df), p=[0.85, 0.15])
        
    X = df[features]
    y = df['label']
    
    # Split: 80% to train the machine, 20% to independently evaluate it
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print("🧠 Training Random Forest Classifier Engine...")
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Validate accuracy
    predictions = model.predict(X_test)
    print("\n📊 --- PROJECT MODEL EVALUATION ---")
    print(f"Overall Classification Accuracy: {accuracy_score(y_test, predictions) * 100:.2f}%")
    print("\nMetrics Summary Details:")
    print(classification_report(y_test, predictions, target_names=["Normal Traffic", "Malicious Intrusion"]))
    
    # Save the trained model binary brain
    joblib.dump(model, model_output_path)
    print(f"💾 Trained model brain successfully exported to: {model_output_path}")

if __name__ == "__main__":
    train_ids_model("extracted_features.csv", "ids_classifier.pkl")