from flask import Flask, jsonify, render_template, request, redirect, url_for
from scanners.yamllint_scanner import run_yamllint
from db import init_db, save_scan, load_scans

app = Flask(__name__)

# --------------------------------
# Initialize database
# --------------------------------
init_db()

# --------------------------------
# Load existing scans from DB
# --------------------------------
SCAN_HISTORY = load_scans()


def run_and_store_scan():
    """
    Run yamllint, store scan in DB, update in-memory history
    """
    scan = {}

    findings, run_id, scan_time = run_yamllint(".")

    high = len([f for f in findings if f["severity"] == "HIGH"])
    low = len([f for f in findings if f["severity"] == "LOW"])

    scan = {
        "run_id": run_id,
        "scan_time": scan_time,
        "total": len(findings),
        "high": high,
        "low": low,
        "findings": findings
    }

    save_scan(scan)
    SCAN_HISTORY.append(scan)

    return scan


# --------------------------------
# Run initial scan only if DB empty
# --------------------------------
if not SCAN_HISTORY:
    run_and_store_scan()


@app.route("/", methods=["GET"])
def index():
    severity_filter = request.args.get("severity")

    latest_scan = SCAN_HISTORY[-1]
    findings = latest_scan["findings"]

    if severity_filter:
        findings = [f for f in findings if f["severity"] == severity_filter]

    total = len(findings)
    high = len([f for f in findings if f["severity"] == "HIGH"])
    low = len([f for f in findings if f["severity"] == "LOW"])

    return render_template(
        "index.html",
        findings=findings,
        total=total,
        high=high,
        low=low,
        run_id=latest_scan["run_id"],
        scan_time=latest_scan["scan_time"],
        history=SCAN_HISTORY
    )


@app.route("/run-scan", methods=["POST"])
def run_scan():
    run_and_store_scan()
    return redirect(url_for("index"))


@app.route("/scan-history")
def scan_history():
    return jsonify(SCAN_HISTORY)


@app.route("/export/latest")
def export_latest():
    return jsonify(SCAN_HISTORY[-1])


@app.route("/export/all")
def export_all():
    return jsonify({
        "total_scans": len(SCAN_HISTORY),
        "scans": SCAN_HISTORY
    })


@app.route("/health")
def health():
    return jsonify({"health": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
