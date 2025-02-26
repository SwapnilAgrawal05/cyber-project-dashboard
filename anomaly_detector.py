import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
from threat_classifier import classify_threats

def load_logs(file_path):
    try:
        logs = pd.read_csv(file_path, sep=',', names=["timestamp", "src_ip", "dest_ip", "protocol", "status"], on_bad_lines='skip')
        
        print("✅ Raw Data Read:")
        print(logs.head())
        
        required_columns = {"timestamp", "src_ip", "dest_ip", "protocol", "status"}
        if not required_columns.issubset(logs.columns):
            raise ValueError(f"Missing required columns! Found: {logs.columns}")
        
        logs.dropna(inplace=True)
        logs['status'] = pd.to_numeric(logs['status'], errors='coerce')
        logs.dropna(subset=['status'], inplace=True)
        logs['status'] = logs['status'].astype(int)
        
        print("✅ Log Data Loaded Successfully:")
        print(logs.head())
        return logs
    except Exception as e:
        print(f"❌ ERROR: Failed to load logs - {e}")
        return None

def detect_anomalies(logs, method="isolation_forest"):
    if logs is None or logs.empty:
        print("❌ ERROR: No valid log data found.")
        return None
    
    logs['protocol_encoded'] = logs['protocol'].astype('category').cat.codes
    features = logs[['status', 'protocol_encoded']]
    
    if method == "isolation_forest":
        model = IsolationForest(contamination=0.1, random_state=42)
        logs['anomaly_score'] = model.fit_predict(features)
    elif method == "one_class_svm":
        model = OneClassSVM(nu=0.1, kernel='rbf', gamma='auto')
        logs['anomaly_score'] = model.fit_predict(features)
    elif method == "autoencoder":
        input_dim = features.shape[1]
        autoencoder = keras.Sequential([
            layers.Dense(16, activation='relu', input_shape=(input_dim,)),
            layers.Dense(8, activation='relu'),
            layers.Dense(16, activation='relu'),
            layers.Dense(input_dim, activation='linear')
        ])
        autoencoder.compile(optimizer='adam', loss='mse')
        
        features_normalized = (features - features.mean()) / features.std()
        autoencoder.fit(features_normalized, features_normalized, epochs=20, batch_size=8, verbose=0)
        reconstructions = autoencoder.predict(features_normalized)
        loss = np.mean(np.abs(reconstructions - features_normalized), axis=1)
        threshold = np.percentile(loss, 90)
        logs['anomaly_score'] = (loss > threshold).astype(int) * -1
    else:
        print("❌ ERROR: Invalid detection method selected.")
        return None
    
    anomalies = logs[logs['anomaly_score'] == -1]
    anomalies = anomalies.copy()
    anomalies['score'] = -1

    
    if anomalies.empty:
        print("✅ No anomalies detected.")
        return None
    
    print("🔍 Detected Anomalies (Before Classification):")
    print(anomalies)
    return anomalies

def main():
    import sys
    if len(sys.argv) < 3:
        print("❌ ERROR: Please provide a log file path and detection method (isolation_forest, one_class_svm, autoencoder).")
        return
    
    file_path = sys.argv[1]
    method = sys.argv[2]
    logs = load_logs(file_path)
    anomalies = detect_anomalies(logs, method)
    
    if anomalies is not None:
        classified_anomalies = classify_threats(anomalies)
        print("🔴 Anomalies with Threat Categories:")
        print(classified_anomalies)

if __name__ == "__main__":
    main()
