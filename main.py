from threat_fetcher import check_ip_virustotal, check_ip_abuseipdb
from threat_processor import parse_virustotal_response, parse_abuseipdb_response, classify_threat
from threat_storage import save_threat_data_json, save_threat_data_csv

def analyze_ip(ip):
    print(f"🔍 Checking {ip} for threats...")

    vt_data = parse_virustotal_response(check_ip_virustotal(ip))
    ab_data = parse_abuseipdb_response(check_ip_abuseipdb(ip))

    vt_threat_level = classify_threat(vt_data["Threat Score"])
    ab_threat_level = classify_threat(ab_data["Threat Score"])

    print(f"✅ VirusTotal Threat Level: {vt_threat_level}")
    print(f"✅ AbuseIPDB Threat Level: {ab_threat_level}")

    save_threat_data_json(ip, vt_data, ab_data)
    save_threat_data_csv(ip, vt_data, ab_data)

# Example: Checking a single IP
analyze_ip("8.8.8.8")
