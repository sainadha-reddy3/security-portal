import json
import uuid
from datetime import datetime

repo_name = "container-scan"

with open("trivy-report.json") as f:
    data = json.load(f)

findings = []

for result in data.get("Results", []):
    for vuln in result.get("Vulnerabilities", []):
        findings.append({
            "repo": repo_name,
            "tool": "trivy",
            "file": vuln.get("PkgName"),
            "severity": vuln.get("Severity"),
            "message": vuln.get("Title")
        })

scan = {
    "run_id": str(uuid.uuid4()),
    "scan_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
    "total": len(findings),
    "high": len([f for f in findings if f["severity"] in ["HIGH", "CRITICAL"]]),
    "low": len([f for f in findings if f["severity"] in ["LOW", "MEDIUM"]]),
    "findings": findings
}

with open("trivy-scan.json", "w") as out:
    json.dump(scan, out, indent=2)

print("trivy-scan.json created")
