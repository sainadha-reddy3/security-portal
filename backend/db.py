import sqlite3

DB_PATH = "backend/security_portal.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            run_id TEXT PRIMARY KEY,
            scan_time TEXT,
            total INTEGER,
            high INTEGER,
            low INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT,
            tool TEXT,
            file TEXT,
            severity TEXT,
            message TEXT
        )
    """)

    conn.commit()
    conn.close()


def save_scan(scan):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "INSERT OR IGNORE INTO scans VALUES (?, ?, ?, ?, ?)",
        (scan["run_id"], scan["scan_time"], scan["total"], scan["high"], scan["low"])
    )

    for f in scan["findings"]:
        cursor.execute(
            "INSERT INTO findings (run_id, tool, file, severity, message) VALUES (?, ?, ?, ?, ?)",
            (scan["run_id"], f["tool"], f["file"], f["severity"], f["message"])
        )

    conn.commit()
    conn.close()


def load_scans():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans")
    scans = cursor.fetchall()

    scan_history = []

    for run_id, scan_time, total, high, low in scans:
        cursor.execute(
            "SELECT tool, file, severity, message FROM findings WHERE run_id = ?",
            (run_id,)
        )
        findings_rows = cursor.fetchall()

        findings = [
            {
                "tool": r[0],
                "file": r[1],
                "severity": r[2],
                "message": r[3],
            }
            for r in findings_rows
        ]

        scan_history.append({
            "run_id": run_id,
            "scan_time": scan_time,
            "total": total,
            "high": high,
            "low": low,
            "findings": findings
        })

    conn.close()
    return scan_history
