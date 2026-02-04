import json
import subprocess
import requests
from datetime import datetime
import uuid
import os
import shutil

PORTAL_URL = os.getenv("PORTAL_URL", "http://127.0.0.1:5000")
PORTAL_API = f"{PORTAL_URL}/api/upload-scan"


# ---------------- YAMLLINT ----------------
def run_yamllint():
    findings = []

    result = subprocess.run(
        ["yamllint", "-f", "parsable", "."],
        capture_output=True,
        text=True
    )

    for line in result.stdout.splitlines():
        parts = line.split(":")
        if len(parts) >= 4:
            file = parts[0].strip()
            message = parts[-1].strip()

            findings.append({
                "repo": os.getenv("GITHUB_REPOSITORY", "security-portal"),
                "tool": "yamllint",
                "file": file,
                "severity": "LOW",
                "message": message
            })

    return findings


# ---------------- TRIVY ----------------
def run_trivy():
    findings = []

    trivy_path = shutil.which("trivy")

    if not trivy_path:
        print("Trivy not found!")
        return findings

    subprocess.run(
        [trivy_path, "image", "--format", "json", "-o", "trivy.json", "nginx:latest"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    if not os.path.exists("trivy.json"):
        return findings

    with open("trivy.json") as f:
        data = json.load(f)

    for result in data.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            findings.append({
                "repo": os.getenv("GITHUB_REPOSITORY", "nginx-image"),
                "tool": "trivy",
                "file": vuln.get("PkgName"),
                "severity": "HIGH" if vuln.get("Severity") in ["HIGH", "CRITICAL"] else "LOW",
                "message": vuln.get("Title")
            })

    return findings


# ---------------- MAIN ----------------
def main():
    all_findings = []

    print("Running yamllint...")
    all_findings.extend(run_yamllint())

    print("Running trivy...")
    all_findings.extend(run_trivy())

    high = len([f for f in all_findings if f["severity"] == "HIGH"])
    low = len([f for f in all_findings if f["severity"] == "LOW"])

    scan_payload = {
        "run_id": str(uuid.uuid4()),
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total": len(all_findings),
        "high": high,
        "low": low,
        "findings": all_findings
    }

    print(f"Uploading to portal at {PORTAL_API} ...")
    res = requests.post(PORTAL_API, json=scan_payload, timeout=15)
    print(res.text)


if __name__ == "__main__":
    main()
