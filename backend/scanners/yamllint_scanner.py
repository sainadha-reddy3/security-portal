import subprocess
import uuid
from datetime import datetime


def run_yamllint(scan_path="."):
    run_id = str(uuid.uuid4())
    scan_time = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    result = subprocess.run(
        ["yamllint", "-f", "parsable", scan_path],
        capture_output=True,
        text=True
    )

    findings = []

    if result.stdout:
        for idx, line in enumerate(result.stdout.strip().split("\n"), start=1):
            parts = line.split(":")
            file_path = parts[0]

            # repo = first folder name
            repo = file_path.split("/")[0]

            message = ":".join(parts[3:]).strip()
            severity = "HIGH" if "error" in message.lower() else "LOW"

            findings.append({
                "id": idx,
                "tool": "yamllint",
                "repo": repo,
                "file": file_path,
                "severity": severity,
                "message": message,
                "run_id": run_id,
                "timestamp": scan_time
            })

    return findings, run_id, scan_time
