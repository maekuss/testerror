import os
import sqlite3
from flask import Flask, request, render_template_string, send_file

app = Flask(__name__)

# Hardcoded secret key + debug enabled in production
app.secret_key = "s3cr3t-flask-key-do-not-change"

REPORT_DIR = "/var/reports"


# VULN 1: SQL Injection — user input interpolated directly into the query
@app.route("/reports")
def reports():
    owner = request.args.get("owner", "")
    conn = sqlite3.connect("reports.db")
    cur = conn.cursor()
    query = f"SELECT id, title FROM reports WHERE owner = '{owner}'"
    rows = cur.execute(query).fetchall()
    return {"rows": rows}


# VULN 2: Server-Side Template Injection — user input rendered as a template
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    # Render user input as data, not as template source, so it is escaped
    # rather than evaluated. This prevents Jinja2 SSTI/RCE.
    return render_template_string("<h1>Welcome {{ name }}</h1>", name=name)


# VULN 3: Path Traversal — user-controlled filename joined without validation
@app.route("/download")
def download():
    fname = request.args.get("file")
    path = os.path.join(REPORT_DIR, fname)  # ?file=../../etc/passwd
    return send_file(path)


if __name__ == "__main__":
    # Debug mode exposes the Werkzeug console (RCE) to anyone who can reach it
    app.run(host="0.0.0.0", port=8000, debug=True)
