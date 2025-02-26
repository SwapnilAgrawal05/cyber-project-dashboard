import json
import os

THREAT_DATA_FILE = "threat_intel/threat_data.json"

def save_threat_data(threat_info):
    if not os.path.exists("threat_intel"):
        os.makedirs("threat_intel")
    
    try:
        with open(THREAT_DATA_FILE, "a") as file:
            json.dump(threat_info, file)
            file.write("\n")
        return True
    except Exception as e:
        return {"error": str(e)}

def load_threat_data():
    if not os.path.exists(THREAT_DATA_FILE):
        return []

    with open(THREAT_DATA_FILE, "r") as file:
        return [json.loads(line) for line in file.readlines()]
