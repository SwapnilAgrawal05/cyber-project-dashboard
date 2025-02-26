from threat_intel.threat_fetcher import get_threat_data  # ✅ Importing from threat_fetcher.py

from threat_intel.threat_fetcher import get_threat_data
from threat_intel.threat_processor import process_threat_data
from threat_intel.threat_storage import save_threat_data

def main():
    ip_list = ["8.8.8.8", "1.1.1.1"]  # Example IPs

    for ip in ip_list:
        print(f"Fetching threat data for {ip}...")
        
        # Fetch raw threat data
        raw_data = get_threat_data(ip)
        
        # Process the raw data
        processed_data = process_threat_data(raw_data)
        
        # Save the processed data
        save_threat_data(processed_data)

        print(f"Threat data saved for {ip}.\n")

if __name__ == "__main__":
    main()
