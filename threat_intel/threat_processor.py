def process_virustotal_response(response):
    try:
        reputation = response.get("data", {}).get("attributes", {}).get("reputation", "Unknown")
        malicious_votes = response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
        return {"reputation": reputation, "malicious_votes": malicious_votes}
    except Exception as e:
        return {"error": str(e)}

def process_abuseipdb_response(response):
    try:
        score = response.get("data", {}).get("abuseConfidenceScore", 0)
        reports = response.get("data", {}).get("totalReports", 0)
        return {"abuse_score": score, "reports": reports}
    except Exception as e:
        return {"error": str(e)}

def process_threat_data(threat_data):
    return {
        "ip": threat_data["ip"],
        "virustotal": process_virustotal_response(threat_data["virustotal"]),
        "abuseipdb": process_abuseipdb_response(threat_data["abuseipdb"]),
    }
