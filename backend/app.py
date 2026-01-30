from flask import Flask, jsonify, render_template, request, redirect, url_for, Response
from scanners.yamllint_scanner import run_yamllint
from scanners.prowler_scanner import run_prowler
from db import init_db, save_scan, load_scans
from functools import wraps

app = Flask(__name__)

# ==============================
# Users & Roles (RBAC)
# ==============================
USERS = {
    "admin": {
        "password": "admin123",
        "role": "admin"
    },
    "viewer": {
        "password": "viewer123",
        "role": "viewer"
    }
}


def authenticate():
    return Response(
        "Authentication required",
        401,
        {"WWW-Authenticate": 'Basic realm="Security Portal"'}
    )


def check_auth(username, password):
    user = USERS.get(username)
    if not user:
        return None
    if user["password"] == password:
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
# Initialize database
# ==============================
init_db()

# ==============================
# Load existing scans from DB
# ==============================
SCAN_HISTORY = load_scans()


def run_and_store_scan():
    """
    Run yamllint + prowler, store scan in DB, update in-memory history
    """

    yaml_findings, run_id, scan_time = run_yamllint(".")
    prowler_findings, _, _ = run_prowler()

    findings = yaml_findings + prowler_findings

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


# ==============================
# Run initial scan if DB empty
# ==============================
if not SCAN_HISTORY:
    run_and_store_scan()


# ==============================
# Routes
# ==============================
@app.route("/", methods=["GET"])
@requires_auth
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
@requires_auth
@requires_admin
def run_scan():
    run_and_store_scan()
    return redirect(url_for("index"))


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


# ==============================
# Health check (UNPROTECTED)
# ==============================
@app.route("/health")
def health():
    return jsonify({"health": "ok"})


if __name__ == "__main__":
    app.run(debug=True)
