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


# ==============================
# Initialize DB
# ==============================
init_db()


# ==============================
# Helpers
# ==============================
def build_repo_summary(findings):
    repo_summary = {}

    for f in findings:
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

    return repo_summary


def get_all_findings():
    """
    ALWAYS read latest scans from DB.
    This prevents UI from needing restart.
    """
    scans = load_scans()
    all_findings = []

    for scan in scans:
        all_findings.extend(scan["findings"])

    return all_findings, scans


# ==============================
# Dashboard
# ==============================
@app.route("/", methods=["GET"])
@requires_auth
def index():

    all_findings, scans = get_all_findings()

    total = len(all_findings)
    high = len([f for f in all_findings if f["severity"] == "HIGH"])
    low = len([f for f in all_findings if f["severity"] == "LOW"])

    repo_summary = build_repo_summary(all_findings)

    # Trend (last 10 scans)
    trend_labels = []
    trend_high = []
    trend_low = []

    for scan in scans[-10:]:
        trend_labels.append(scan["scan_time"])
        trend_high.append(scan["high"])
        trend_low.append(scan["low"])

    return render_template(
        "index.html",
        total=total,
        high=high,
        low=low,
        repo_summary=repo_summary,
        trend_labels=trend_labels,
        trend_high=trend_high,
        trend_low=trend_low
    )


# ==============================
# Repositories Page
# ==============================
@app.route("/repos")
@requires_auth
def repos_page():
    all_findings, _ = get_all_findings()
    repo_summary = build_repo_summary(all_findings)
    return render_template("repos.html", repo_summary=repo_summary)


# ==============================
# Repo Drill-down Page
# ==============================
@app.route("/repo/<repo_name>")
@requires_auth
def repo_details(repo_name):

    all_findings = []
    for scan in SCAN_HISTORY:
        all_findings.extend(scan["findings"])

    repo_findings = [f for f in all_findings if f.get("repo") == repo_name]

    high = len([f for f in repo_findings if f["severity"] == "HIGH"])
    low = len([f for f in repo_findings if f["severity"] == "LOW"])

    return render_template(
        "repo_details.html",
        repo_name=repo_name,
        findings=repo_findings,
        high=high,
        low=low,
        total=len(repo_findings)
    )




# ==============================
# Findings Page (with filters)
# ==============================
@app.route("/findings")
@requires_auth
def findings_page():

    severity = request.args.get("severity")
    tool = request.args.get("tool")
    search = request.args.get("search")

    all_findings, _ = get_all_findings()

    if severity:
        all_findings = [f for f in all_findings if f.get("severity") == severity]

    if tool:
        all_findings = [f for f in all_findings if f.get("tool") == tool]

    if search:
        all_findings = [
            f for f in all_findings
            if search.lower() in f.get("file", "").lower()
            or search.lower() in f.get("message", "").lower()
        ]

    return render_template("findings.html", findings=all_findings)


# ==============================
# History Page
# ==============================
@app.route("/history")
@requires_auth
def history_page():
    _, scans = get_all_findings()
    return render_template("history.html", scans=scans)


# ==============================
# API Upload (CI/CD)
# ==============================
@app.route("/api/upload-scan", methods=["POST"])
def upload_scan():
    scan = request.get_json()

    if not scan or "findings" not in scan:
        return jsonify({"error": "Invalid scan data"}), 400

    save_scan(scan)
    return jsonify({"status": "Scan uploaded successfully"})


# ==============================
# Health
# ==============================
@app.route("/health")
def health():
    return jsonify({"health": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
