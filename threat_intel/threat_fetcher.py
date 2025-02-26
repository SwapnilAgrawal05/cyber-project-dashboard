import requests
import os
from utils.api_keys import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY  # Ensure this file exists

def fetch_from_virustotal(ip):
    """Fetch threat intelligence data from VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}  # ✅ API key in quotes

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises error for non-200 responses
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"VirusTotal request failed: {e}"}

def fetch_from_abuseipdb(ip):
    """Fetch threat intelligence data from AbuseIPDB."""
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {
        "Key": ABUSEIPDB_API_KEY,  # ✅ API key in quotes
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()  
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"AbuseIPDB request failed: {e}"}

def get_threat_data(ip):
    """Fetch threat data from multiple sources."""
    return {
        "ip": ip,
        "virustotal": fetch_from_virustotal(ip),
        "abuseipdb": fetch_from_abuseipdb(ip),
    }
if __name__ == "__main__":
    test_ip = "8.8.8.8"  # Replace with any test IP
    result = get_threat_data(test_ip)
    print(result)  # ✅ Prints fetched threat intelligence data

