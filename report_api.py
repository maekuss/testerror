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
    query = "SELECT id, title FROM reports WHERE owner = ?"
    rows = cur.execute(query, (owner,)).fetchall()
    return {"rows": rows}


# VULN 2: Server-Side Template Injection — user input rendered as a template
@app.route("/greet")
def greet():
    name = request.args.get("name", "guest")
    template = f"<h1>Welcome {name}</h1>"  # ?name={{7*7}} -> Jinja2 RCE
    return render_template_string(template)


# VULN 3: Path Traversal — user-controlled filename joined without validation
@app.route("/download")
def download():
    fname = request.args.get("file")
    path = os.path.join(REPORT_DIR, fname)  # ?file=../../etc/passwd
    return send_file(path)


if __name__ == "__main__":
    # Debug mode exposes the Werkzeug console (RCE) to anyone who can reach it
    app.run(host="0.0.0.0", port=8000, debug=True)
