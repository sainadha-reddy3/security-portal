import json
from datetime import datetime
import uuid

with open("trivy-report.json") as f:
    trivy = json.load(f)

findings = []

for result in trivy.get("Results", []):
    repo = result.get("Target", "image")
    for vuln in result.get("Vulnerabilities", []) or []:
        findings.append({
            "repo": repo,
            "file": vuln.get("PkgName"),
            "severity": "HIGH" if vuln.get("Severity") in ["HIGH", "CRITICAL"] else "LOW",
            "tool": "trivy",
            "message": vuln.get("Title")
        })

scan = {
    "run_id": str(uuid.uuid4()),                 # ✅ REQUIRED
    "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "total": len(findings),                     # ✅ REQUIRED
    "high": len([f for f in findings if f["severity"] == "HIGH"]),
    "low": len([f for f in findings if f["severity"] == "LOW"]),
    "findings": findings
}

with open("portal_scan.json", "w") as f:
    json.dump(scan, f, indent=2)

print("portal_scan.json created")
