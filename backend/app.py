from flask import Flask, jsonify, render_template, request, Response
from db import init_db, save_scan, load_scans
from functools import wraps

app = Flask(__name__)

# ==============================
# Users & Roles (RBAC)
# ==============================
USERS = {
    "admin": {"password": "admin123", "role": "admin"},
    "viewer": {"password": "viewer123", "role": "viewer"}
}


def authenticate():
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="Security Portal"'}
    )


def check_auth(username, password):
    user = USERS.get(username)
    if user and user["password"] == password:
        return user
    return None


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth:
            return authenticate()

        user = check_auth(auth.username, auth.password)
        if not user:
            return authenticate()

        request.user = user
        return f(*args, **kwargs)
    return decorated


def requires_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.user["role"] != "admin":
            return Response("Admin access required", 403)
        return f(*args, **kwargs)
    return decorated


# ==============================
# Initialize DB
# ==============================
init_db()
SCAN_HISTORY = load_scans()


# ==============================
# MAIN DASHBOARD ROUTE
# ==============================
@app.route("/", methods=["GET"])
@requires_auth
def index():
    """
    Aggregates ALL scans across time and repos.
    Builds repo model + trend model for UI.
    """

    # 🔥 Combine findings from all scans
    all_findings = []
    for scan in SCAN_HISTORY:
        all_findings.extend(scan["findings"])

    total = len(all_findings)
    high = len([f for f in all_findings if f["severity"] == "HIGH"])
    low = len([f for f in all_findings if f["severity"] == "LOW"])

    # -------- Repository Summary (for UI table/cards) --------
    repo_summary = {}

    for f in all_findings:
        repo = f.get("repo", "unknown")

        if repo not in repo_summary:
            repo_summary[repo] = {
                "total": 0,
                "high": 0,
                "low": 0,
                "status": "Passed"
            }

        repo_summary[repo]["total"] += 1

        if f["severity"] == "HIGH":
            repo_summary[repo]["high"] += 1
            repo_summary[repo]["status"] = "Failed"
        else:
            repo_summary[repo]["low"] += 1

    # -------- Trend data (last 10 scans) --------
    trend_labels = []
    trend_high = []
    trend_low = []

    for scan in SCAN_HISTORY[-10:]:
        trend_labels.append(scan["scan_time"])
        trend_high.append(scan["high"])
        trend_low.append(scan["low"])

    return render_template(
        "index.html",
        findings=all_findings,
        total=total,
        high=high,
        low=low,
        repo_summary=repo_summary,
        trend_labels=trend_labels,
        trend_high=trend_high,
        trend_low=trend_low
    )


# ==============================
# APIs
# ==============================
@app.route("/scan-history")
@requires_auth
def scan_history():
    return jsonify(SCAN_HISTORY)


@app.route("/export/latest")
@requires_auth
@requires_admin
def export_latest():
    return jsonify(SCAN_HISTORY[-1])


@app.route("/export/all")
@requires_auth
@requires_admin
def export_all():
    return jsonify({
        "total_scans": len(SCAN_HISTORY),
        "scans": SCAN_HISTORY
    })


@app.route("/api/upload-scan", methods=["POST"])
def upload_scan():
    scan = request.get_json()

    if not scan or "findings" not in scan:
        return jsonify({"error": "Invalid scan data"}), 400

    save_scan(scan)
    SCAN_HISTORY.append(scan)

    return jsonify({"status": "Scan uploaded successfully"})


# ==============================
# Health
# ==============================
@app.route("/health")
def health():
    return jsonify({"health": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
