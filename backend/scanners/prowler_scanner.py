import json
import uuid
from datetime import datetime


def run_prowler():
    with open("backend/scanners/prowler_sample.json") as f:
        data = json.load(f)

    run_id = str(uuid.uuid4())
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    findings = []

    for item in data["findings"]:
        repo = item["resource"].split("/")[0]

        findings.append({
            "tool": "prowler",
            "repo": repo,
            "file": item["resource"],
            "severity": item["severity"],
            "message": item["message"],
            "run_id": run_id,
            "timestamp": scan_time
        })

    return findings, run_id, scan_time
