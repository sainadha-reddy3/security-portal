import json
import uuid
from datetime import datetime
import os

repo_name = "local-repo"

findings = []

with open("report.txt") as f:
    for line in f:
        if line.strip():
            parts = line.split(":")
            file_path = parts[0]
            message = ":".join(parts[3:]).strip()

            findings.append({
                "repo": repo_name,
                "tool": "yamllint",
                "file": file_path,
                "severity": "HIGH" if "error" in message.lower() else "LOW",
                "message": message
            })

scan = {
    "run_id": str(uuid.uuid4()),
    "scan_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "total": len(findings),
    "high": len([f for f in findings if f["severity"] == "HIGH"]),
    "low": len([f for f in findings if f["severity"] == "LOW"]),
    "findings": findings
}

with open("scan.json", "w") as out:
    json.dump(scan, out, indent=2)

print("scan.json created from yamllint output")
