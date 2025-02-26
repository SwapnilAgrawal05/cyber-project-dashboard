import pandas as pd

def get_threat_category(row):
    """
    Classifies threats based on log status.
    """
    if row['status'] == 200:
        return "Low Risk"
    elif row['status'] in [401, 403]:
        return "Unauthorized Access Attempt"
    elif row['status'] == 500:
        return "Critical: Possible Server Attack"
    else:
        return "Unknown Threat"

def classify_threats(logs):
    """
    Applies threat classification to detected anomalies.
    """
    logs = logs.copy()  # Fix SettingWithCopyWarning
    logs['threat_category'] = logs.apply(get_threat_category, axis=1)
    return logs

# Test it with sample logs
if __name__ == "__main__":
    from log_parser import load_logs
    
    logs = load_logs("logs/sample_log.log")
    classified_logs = classify_threats(logs)
    
    print("🔍 Threat Classification:")
    print(classified_logs)
