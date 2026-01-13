# ==================================================
# Digital Forensics Investigation Framework (Educational)
# Author: Usman Ghani
# Course: Cybersecurity & Ethical Hacking (PITP)
# ==================================================

from flask import Flask, request, render_template_string, send_file
import os, hashlib, csv, platform, socket
from datetime import datetime
import psutil
import phonenumbers
from phonenumbers import geocoder, carrier

app = Flask(__name__)

# ==============================
# HTML + CSS (GUI)
# ==============================
HTML = """
<!DOCTYPE html>
<html>
<head>
<title>Digital Forensics Investigation</title>
<style>
body { font-family: Arial; background:#f4f4f4; margin:0; }
header { background:#0eca62; color:white; padding:20px; text-align:center; }
form { background:#989a9b; padding:20px; margin:20px auto; width:70%; border-radius:10px; }
input { width:100%; padding:10px; margin-top:10px; }
button { background:#520c14; color:white; padding:10px; border:none; margin-top:15px; cursor:pointer; }
table { width:95%; margin:20px auto; border-collapse:collapse; background:white; }
th, td { border:1px solid #e505cb; padding:8px; font-size:12px; }
th { background:#879a92; color:white; }
section { margin:20px; }
footer { background:#f1707b; color:white; text-align:center; padding:10px; }
</style>
</head>

<body>

<header>
<h1>Digital Forensics Investigation </h1>
<p>Ethical • Read-Only • Educational</p>
</header>

<form method="post">
<label><b>Authorized Evidence Directory</b></label>
<input type="text" name="path" placeholder="C:\\Users\\..." required>

<label><b>Phone Number (Optional – Educational)</b></label>
<input type="text" name="phone" placeholder="+92XXXXXXXXXX">

<button type="submit">Start Investigation</button>
</form>

{% if files %}
<section>
<h2>File Forensic Analysis</h2>
<table>
<tr>
<th>Logical Evidence Path</th>
<th>Size (Bytes)</th>
<th>Created</th>
<th>Modified</th>
<th>MD5</th>
<th>SHA-256</th>
</tr>
{% for f in files %}
<tr>
<td>{{ f.logical }}</td>
<td>{{ f.size }}</td>
<td>{{ f.created }}</td>
<td>{{ f.modified }}</td>
<td>{{ f.md5 }}</td>
<td>{{ f.sha256 }}</td>
</tr>
{% endfor %}
</table>
</section>
{% endif %}

{% if device %}
<section>
<h2>Device Forensics</h2>
<ul>
{% for k,v in device.items() %}
<li><b>{{ k }}</b>: {{ v }}</li>
{% endfor %}
</ul>
</section>
{% endif %}

{% if network %}
<section>
<h2>Network Forensics (Passive)</h2>
<table>
<tr><th>Interface</th><th>IP Address</th><th>Netmask</th></tr>
{% for n in network %}
<tr>
<td>{{ n.interface }}</td>
<td>{{ n.ip }}</td>
<td>{{ n.netmask }}</td>
</tr>
{% endfor %}
</table>
</section>
{% endif %}

{% if phone %}
<section>
<h2>Phone Number Analysis (Educational)</h2>
<ul>
<li>Valid: {{ phone.valid }}</li>
<li>Country: {{ phone.country }}</li>
<li>Carrier: {{ phone.carrier }}</li>
</ul>
</section>
{% endif %}

{% if files %}
<form method="post" action="/download" style="text-align:center;">
<button>Download Forensic Report</button>
</form>
{% endif %}

<footer>
All Rights Reserved | PITP Cybersecurity Project | Digital Forensics | Developer Engr.Usman Ghani
</footer>

</body>
</html>
"""

# ==============================
# HASHING
# ==============================
def calculate_hashes(path):
    md5, sha256 = hashlib.md5(), hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()
    except:
        return "N/A", "N/A"

# ==============================
# FILE FORENSICS
# ==============================
def analyze_directory(base):
    results = []
    evidence_id = "Evidence_001"
    for root, _, files in os.walk(base):
        for file in files:
            full = os.path.join(root, file)
            try:
                stat = os.stat(full)
                md5, sha256 = calculate_hashes(full)
                logical = os.path.join(evidence_id, os.path.relpath(full, base)).replace("\\","/")
                results.append({
                    "logical": logical,
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                    "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "md5": md5,
                    "sha256": sha256
                })
            except:
                pass
    return results

# ==============================
# DEVICE FORENSICS
# ==============================
def device_info():
    return {
        "OS": platform.system(),
        "OS Version": platform.version(),
        "Machine": platform.machine(),
        "Processor": platform.processor(),
        "Hostname": socket.gethostname()
    }

# ==============================
# NETWORK FORENSICS (PASSIVE)
# ==============================
def network_info():
    data = []
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET:
                data.append({"interface": iface, "ip": a.address, "netmask": a.netmask})
    return data

# ==============================
# PHONE NUMBER FORENSICS (EDU)
# ==============================
def phone_analysis(num):
    try:
        p = phonenumbers.parse(num)
        return {
            "valid": phonenumbers.is_valid_number(p),
            "country": geocoder.description_for_number(p, "en"),
            "carrier": carrier.name_for_number(p, "en")
        }
    except:
        return {"valid":"False","country":"N/A","carrier":"N/A"}

# ==============================
# ROUTES
# ==============================
stored = []

@app.route("/", methods=["GET","POST"])
def index():
    global stored
    stored = []
    dev = net = phone = None

    if request.method == "POST":
        path = request.form["path"]
        number = request.form.get("phone")

        if os.path.exists(path):
            stored = analyze_directory(path)

        dev = device_info()
        net = network_info()
        if number:
            phone = phone_analysis(number)

    return render_template_string(
        HTML,
        files=stored,
        device=dev,
        network=net,
        phone=phone
    )

@app.route("/download", methods=["POST"])
def download():
    report = "forensic_report.csv"
    with open(report,"w",newline="",encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["Logical Path","Size","Created","Modified","MD5","SHA256"])
        for r in stored:
            w.writerow([r["logical"],r["size"],r["created"],r["modified"],r["md5"],r["sha256"]])
    return send_file(report, as_attachment=True)

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    app.run(debug=True)