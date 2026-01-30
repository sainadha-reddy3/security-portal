import json
import uuid
from datetime import datetime


def run_prowler():
    """
    Simulated Prowler scan using sample JSON
    """
    with open("backend/scanners/prowler_sample.json") as f:
        data = json.load(f)

    run_id = str(uuid.uuid4())
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    findings = []

    for item in data["findings"]:
        findings.append({
            "tool": "prowler",
            "file": item["resource"],
            "severity": item["severity"],
            "message": item["message"]
        })

    return findings, run_id, scan_time
