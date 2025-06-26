#!/usr/bin/env python3
import os
import sys
import subprocess
import threading
import time
import json
import re
import getpass
import logging
import random
import shutil
import socket
import string
import hashlib
from datetime import datetime

from flask import Flask, request, redirect, session, render_template_string, Response
import requests

# PDF generation imports using reportlab
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors


# =========================
# Security Helper Functions
# =========================

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


def generate_key():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))


def is_malicious(input_str):
    # Use DOTALL to allow . to match newline characters and add word boundaries
    flags = re.IGNORECASE | re.DOTALL
    patterns = [
        r"<\s*script\b",
        r"select\s+.*?\s+from\b",
        r"union\s+select\b",
        r"insert\s+into\b",
        r"delete\s+from\b",
        r"update\s+.*?\s+set\b",
        r"drop\s+table\b",
        r"or\s+1\s*=\s*1",
        r"--",
        r";"
    ]
    for pattern in patterns:
        if re.search(pattern, input_str, flags):
            return True
    return False


# WAF Blocked Template
waf_template = """
<html>
<head><title>WAF Blocked</title></head>
<body>
  <h1 style="color:red; font-weight:bold; text-align:center;">RS4V WAF Blocked this request.</h1>
</body>
</html>
"""

# =========================
# Captive Portal Credential Initialization
# =========================

USER_CREDENTIALS_CONFIG = "captive_credentials.json"


def initialize_captive_credentials():
    """
    Load captive portal credentials from captive_credentials.json.
    If not found, prompt admin to create a default user.
    The file now stores all users under the "RegisteredUsers" key.
    """
    config_file = USER_CREDENTIALS_CONFIG
    creds = {}
    if os.path.exists(config_file):
        try:
            with open(config_file, "r") as f:
                creds = json.load(f)
            if "RegisteredUsers" not in creds:
                if "username" in creds and "password" in creds and "key" in creds:
                    user = creds["username"]
                    creds = {"RegisteredUsers": {user: {"password": creds["password"], "key": creds["key"]}}}
                else:
                    creds["RegisteredUsers"] = {}
            with open(config_file, "w") as f:
                json.dump(creds, f, indent=4)
        except Exception as e:
            print("Error loading captive portal credentials:", e)
    else:
        print("No captive portal credentials found. Please create default captive portal credentials.")
        username = input("Enter default captive portal username: ").strip()
        password = getpass.getpass("Enter default captive portal password: ").strip()
        creds = {"RegisteredUsers": {username: {"password": hash_password(password), "key": generate_key()}}}
        with open(config_file, "w") as f:
            json.dump(creds, f, indent=4)
    for user, data in creds["RegisteredUsers"].items():
        key_filename = f"{user}.rs4v"
        if not os.path.exists(key_filename):
            try:
                with open(key_filename, "w") as f:
                    f.write(data["key"])
                print(f"Key file created: {key_filename}")
            except Exception as e:
                print("Error creating key file for user", user, ":", e)
    return creds


CAPTIVE_CREDENTIALS = initialize_captive_credentials()

# =========================
# Configuration & Constants
# =========================

LOG_FILE = os.path.expanduser('~/logs.txt')
CERT_FILE = 'server.crt'
KEY_FILE = 'server.key'
ORTHANC_URL = "http://localhost:8042"
PROXY_PORT = 443
REDIRECT_PORT = 80
FLASK_SECRET = "change_this_secret_key"

MENU_PROMPT = (
    "=============================\n"
    "Proxy Server Control Menu\n"
    "=============================\n"
    "1) View logs\n"
    "2) Add/Remove user (no captcha)\n"
    "3) View Users and Change Password\n"
    "4) Save PDF report\n"
    "5) Restart Server\n"
    "6) Whitelist/Blacklist an IP address\n"
    "7) Turn off Server\n"
    "8) Generate new key for a user\n"
    "=============================\n"
    "Enter your choice (1-8): "
)

# Updated banner with new text.
BANNER = (
    "\033[1;33m"  # Bright yellow
    "****************************************\n"
    "*   RS4V WAF Server Panel              *\n"
    "****************************************\n"
    "\033[0m"  # Reset color
)


# =========================
# Helper Functions (continued)
# =========================

def run_command(cmd):
    print("Running:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def generate_self_signed_cert():
    if not (os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE)):
        print("Generating self-signed certificate for rs4v.com with IP 192.168.247.131 ...")
        # Create a temporary OpenSSL config file with the desired settings.
        config_text = """
[ req ]
default_bits       = 4096
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_ca

[ dn ]
CN = rs4v.com
O  = RS4V ROOT CA

[ v3_ca ]
subjectAltName = @alt_names
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign, digitalSignature

[ alt_names ]
DNS.1 = rs4v.com
IP.1  = 192.168.247.131
"""
        config_file = "openssl_config.cnf"
        with open(config_file, "w") as f:
            f.write(config_text)
        run_command([
            "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:4096",
            "-keyout", KEY_FILE, "-out", CERT_FILE,
            "-days", "365", "-config", config_file, "-extensions", "v3_ca"
        ])
        os.remove(config_file)


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def load_json_file(path):
    if not os.path.exists(path):
        return {}
    with open(path, 'r') as f:
        text = f.read()
    text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
    text = re.sub(r'//.*', '', text)
    return json.loads(text)


def save_json_file(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


# =========================
# Flask Applications
# =========================

app = Flask(__name__)
app.secret_key = FLASK_SECRET

redirect_app = Flask("redirector")
redirect_app.secret_key = FLASK_SECRET


# Allow shutdown endpoints without login.
@app.before_request
def require_login():
    if request.endpoint in ['login', 'upload_key', 'static', 'redirect_to_https', 'shutdown']:
        return
    if not session.get('authenticated'):
        return redirect("/login?next=" + request.url)


@redirect_app.before_request
def require_login_redirect():
    if request.endpoint in ['redirect_to_https', 'shutdown_redirect']:
        return


@redirect_app.route('/', defaults={'path': ''})
@redirect_app.route('/<path:path>')
def redirect_to_https(path):
    host = request.host.split(':')[0]
    return redirect(f"https://{host}:{PROXY_PORT}/{path}", code=301)


# Shutdown endpoint for proxy app.
@app.route('/shutdown', methods=['POST'])
def shutdown():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Proxy server shutting down...'


# Shutdown endpoint for redirector.
@redirect_app.route('/shutdown', methods=['POST'])
def shutdown_redirect():
    func = request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()
    return 'Redirector shutting down...'


# -------------------------
# Captive Portal – Login (Step 1)
# -------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    current_time = time.time()
    if session.get('locked_until', 0) > current_time:
        remaining = int((session['locked_until'] - current_time) / 60) + 1
        error = f"Too many failed login attempts. Please try again in {remaining} minute(s)."
        return render_template_string(login_template, error=error)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if is_malicious(username) or is_malicious(password):
            return render_template_string(waf_template)
        users = CAPTIVE_CREDENTIALS.get("RegisteredUsers", {})
        if username not in users:
            error = "Invalid username or password."
        elif hash_password(password) != users[username].get("password", ""):
            error = "Invalid username or password."

        if error:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            if session['login_attempts'] >= 3:
                session['locked_until'] = current_time + 3600
                error = "Too many failed login attempts. Please try again after one hour."
            return render_template_string(login_template, error=error)
        else:
            session['password_verified'] = True
            session['username'] = username
            return redirect("/upload_key")
    return render_template_string(login_template, error=error)


# Updated login template with image and new title.
login_template = """
<html>
<head>
  <title>RS4V WAF Login</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
    .login-container {
      width: 320px; margin: 100px auto; padding: 20px; background: #fff;
      box-shadow: 0 0 15px rgba(0,0,0,0.2); border-radius: 8px;
      text-align: center;
    }
    .login-container h2 { text-align: center; color: #333; }
    .login-container input[type=text],
    .login-container input[type=password] {
      width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #ccc;
      border-radius: 4px;
    }
    .login-container input[type=submit] {
      width: 100%; padding: 10px; background-color: #007bff;
      border: none; color: white; font-size: 16px; border-radius: 4px;
      cursor: pointer;
    }
    .login-container input[type=submit]:hover { background-color: #0056b3; }
    .error { color: red; text-align: center; }
    .reset-link { text-align: center; margin-top: 10px; }
    .reset-link a { text-decoration: none; color: blue; }
  </style>
</head>
<body>
  <div class="login-container">
    <img src="https://shravanprojects.github.io/rs4v-framework/logo.png" alt="Logo" style="max-width:100%; height:auto; margin-bottom:10px;">
    <h2>RS4V WAF Login</h2>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post">
      <input type="text" name="username" placeholder="Username" required /><br/>
      <input type="password" name="password" placeholder="Password" required /><br/>
      <input type="submit" value="Next" />
    </form>
    <div class="reset-link">
      <p><a href="https://wa.me/918088593127?text=Reset%20password" target="_blank">Reset Password</a></p>
    </div>
  </div>
</body>
</html>
"""


# -------------------------
# Captive Portal – Key Upload (Step 2)
# -------------------------
@app.route('/upload_key', methods=['GET', 'POST'])
def upload_key():
    error = None
    if not session.get('password_verified'):
        return redirect("/login")
    if request.method == 'POST':
        if 'keyfile' not in request.files:
            error = "Key file is required."
            # Block immediately if file is missing.
            session['locked_until'] = time.time() + 3600
            return render_template_string(key_template, error="Invalid file. You are blocked for 1 hour.")
        key_file = request.files['keyfile']
        # If uploaded file is not .rs4v, block for 1 hour.
        if not key_file.filename.lower().endswith(".rs4v"):
            session['locked_until'] = time.time() + 3600
            return render_template_string(key_template, error="Invalid file type. You are blocked for 1 hour.")
        try:
            key_content = key_file.read().decode('utf-8').strip()
        except Exception as e:
            error = "Error reading key file."
        username = session.get('username')
        user_data = CAPTIVE_CREDENTIALS.get("RegisteredUsers", {}).get(username)
        if not user_data or key_content != user_data.get("key", ""):
            error = "Invalid key file."
        if error:
            session['login_attempts'] = session.get('login_attempts', 0) + 1
            if session['login_attempts'] >= 3:
                session['locked_until'] = time.time() + 3600
                error = "Too many failed login attempts. Please try again after one hour."
            return render_template_string(key_template, error=error)
        else:
            session['authenticated'] = True
            session.pop('password_verified', None)
            session['login_attempts'] = 0
            success_message = f"Successful login for user: {session.get('username')} from {request.remote_addr}"
            logging.info(success_message)
            print(success_message)
            next_url = request.args.get('next') or "/"
            return redirect(next_url)
    return render_template_string(key_template, error=error)


key_template = """
<html>
<head>
  <title>Upload Key File</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #f0f2f5; }
    .key-container {
      width: 320px; margin: 100px auto; padding: 20px; background: #fff;
      box-shadow: 0 0 15px rgba(0,0,0,0.2); border-radius: 8px;
      text-align: center;
    }
    .key-container h2 { color: #333; }
    .key-container input[type=file] { margin: 10px 0; }
    .key-container input[type=submit] {
      padding: 10px 20px; background-color: #007bff;
      border: none; color: white; font-size: 16px; border-radius: 4px;
      cursor: pointer;
    }
    .key-container input[type=submit]:hover { background-color: #0056b3; }
    .error { color: red; text-align: center; }
  </style>
</head>
<body>
  <div class="key-container">
    <h2>Upload Your Key File</h2>
    {% if error %}<p class="error">{{ error }}</p>{% endif %}
    <form method="post" enctype="multipart/form-data">
      <input type="file" name="keyfile" required /><br/>
      <input type="submit" value="Upload Key" />
    </form>
  </div>
</body>
</html>
"""


# -------------------------
# Proxy Route
# -------------------------
@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy(path):
    target_url = f"{ORTHANC_URL}/{path}"
    if request.query_string:
        target_url += "?" + request.query_string.decode()
    resp = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for key, value in request.headers.items() if key.lower() != 'host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False
    )
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
    return Response(resp.content, resp.status_code, headers)


@app.before_request
def log_request():
    client_ip = request.remote_addr
    requested_url = request.url
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_line = f"{now} - {client_ip} accessed {requested_url}"
    logging.info(log_line)
    print(log_line)


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


# =========================
# Server Runner Functions
# =========================

def run_proxy():
    generate_self_signed_cert()
    local_ip = get_local_ip()
    print(f"HTTPS proxy is running. Access it at: https://{local_ip}:{PROXY_PORT}")
    app.run(host='0.0.0.0', port=PROXY_PORT, ssl_context=(CERT_FILE, KEY_FILE), threaded=True)


def run_redirector():
    print(f"HTTP redirector is running on port {REDIRECT_PORT} (all HTTP traffic will be redirected to HTTPS).")
    redirect_app.run(host='0.0.0.0', port=REDIRECT_PORT)


# =========================
# Interactive Menu Functions
# =========================

def view_logs():
    print("Displaying log contents:")
    try:
        with open(LOG_FILE, 'r') as f:
            print(f.read())
    except Exception as e:
        print("Error reading log file:", e)
    input("Press Enter to return to the menu...")


def add_remove_user():
    choice = input("Do you want to (a)dd or (r)emove a user? [a/r]: ").strip().lower()
    creds = load_json_file(USER_CREDENTIALS_CONFIG)
    if "RegisteredUsers" not in creds:
        creds["RegisteredUsers"] = {}
    if choice == 'a':
        new_user = input("Enter new username: ").strip()
        if is_malicious(new_user):
            print("RS4V WAF Blocked this request.")
            return
        if new_user in creds["RegisteredUsers"]:
            print("User already exists.")
            return
        new_pass = getpass.getpass("Enter new password: ").strip()
        if is_malicious(new_pass):
            print("RS4V WAF Blocked this request.")
            return
        new_pass_hashed = hash_password(new_pass)
        new_key = generate_key()
        creds["RegisteredUsers"][new_user] = {"password": new_pass_hashed, "key": new_key}
        save_json_file(USER_CREDENTIALS_CONFIG, creds)
        try:
            with open(f"{new_user}.rs4v", "w") as f:
                f.write(new_key)
            print(f"User '{new_user}' added. Key file generated: {new_user}.rs4v")
        except Exception as e:
            print("Error generating key file:", e)
    elif choice == 'r':
        if "RegisteredUsers" not in creds or not creds["RegisteredUsers"]:
            print("No users to remove.")
            return
        print("Current users:")
        for user in creds["RegisteredUsers"]:
            print(" -", user)
        rem_user = input("Enter username to remove: ").strip()
        if rem_user in creds["RegisteredUsers"]:
            del creds["RegisteredUsers"][rem_user]
            save_json_file(USER_CREDENTIALS_CONFIG, creds)
            print(f"User '{rem_user}' removed.")
        else:
            print(f"User '{rem_user}' not found.")
    else:
        print("Invalid choice.")


def view_users_and_change_pass():
    creds = load_json_file(USER_CREDENTIALS_CONFIG)
    if "RegisteredUsers" not in creds or not creds["RegisteredUsers"]:
        print("No users found.")
        return
    print("Registered Users:")
    for user in creds["RegisteredUsers"]:
        print(" -", user)
    change = input("Do you want to change a user's password? (y/n): ").strip().lower()
    if change == 'y':
        user_to_change = input("Enter the username to change password: ").strip()
        if user_to_change in creds["RegisteredUsers"]:
            new_pass = getpass.getpass("Enter new password: ").strip()
            creds["RegisteredUsers"][user_to_change]["password"] = hash_password(new_pass)
            save_json_file(USER_CREDENTIALS_CONFIG, creds)
            print(f"Password for '{user_to_change}' updated.")
        else:
            print("User not found.")


def save_log():
    dest = input("Enter the full destination path to save the PDF report (including .pdf): ").strip()
    try:
        creds = load_json_file(USER_CREDENTIALS_CONFIG)
        users = list(creds.get("RegisteredUsers", {}).keys())
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                log_lines = f.readlines()
        else:
            log_lines = []
        doc = SimpleDocTemplate(dest, pagesize=letter)
        styles = getSampleStyleSheet()
        Story = []
        Story.append(Paragraph("Server PDF Report", styles['Title']))
        Story.append(Spacer(1, 12))
        Story.append(
            Paragraph(f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        Story.append(Spacer(1, 24))
        Story.append(Paragraph("Registered Users", styles['Heading2']))
        user_data = [["Username"]]
        for user in users:
            user_data.append([user])
        t = Table(user_data, hAlign='LEFT')
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ]))
        Story.append(t)
        Story.append(Spacer(1, 24))
        Story.append(Paragraph("Access Logs", styles['Heading2']))
        log_data = [["Timestamp", "IP", "Message"]]
        for line in log_lines:
            line = line.strip()
            parts = line.split(" - ", 1)
            if len(parts) == 2:
                timestamp = parts[0]
                rest = parts[1]
                ip_and_message = rest.split(" ", 1)
                if len(ip_and_message) == 2:
                    ip = ip_and_message[0]
                    message = ip_and_message[1]
                else:
                    ip = ""
                    message = rest
            else:
                timestamp = ""
                ip = ""
                message = line
            log_data.append([timestamp, ip, message])
        t_log = Table(log_data, colWidths=[100, 80, 300])
        t_log.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.gray),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('BACKGROUND', (0, 1), (-1, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.25, colors.black),
        ]))
        Story.append(t_log)
        Story.append(Spacer(1, 24))
        doc.build(Story)
        print(f"PDF report saved to {dest}")
    except Exception as e:
        print("Error generating PDF report:", e)


def restart_server():
    print("Restarting server gracefully...")
    try:
        # Shutdown proxy (HTTPS) server.
        requests.post(f"https://localhost:{PROXY_PORT}/shutdown", verify=False)
    except Exception as e:
        print("Error shutting down proxy server:", e)
    try:
        # Shutdown HTTP redirector.
        requests.post(f"http://localhost:{REDIRECT_PORT}/shutdown")
    except Exception as e:
        print("Error shutting down redirector:", e)
    time.sleep(2)  # Give some time for sockets to be released.
    python = sys.executable
    os.execl(python, python, *sys.argv)


def whitelist_blacklist():
    ip_addr = input("Enter the IP address: ").strip()
    try:
        socket.inet_aton(ip_addr)
    except socket.error:
        print("Invalid IP address format.")
        return
    action = input("Type 'w' to whitelist or 'b' to blacklist: ").strip().lower()
    try:
        if action == 'w':
            run_command(["ufw", "allow", "from", ip_addr])
            run_command(["ufw", "reload"])
            print(f"IP {ip_addr} whitelisted.")
        elif action == 'b':
            run_command(["ufw", "deny", "from", ip_addr])
            run_command(["ufw", "reload"])
            print(f"IP {ip_addr} blacklisted.")
        else:
            print("Invalid action.")
    except Exception as e:
        print("Error updating firewall:", e)


def generate_new_key():
    creds = load_json_file(USER_CREDENTIALS_CONFIG)
    if "RegisteredUsers" not in creds or not creds["RegisteredUsers"]:
        print("No users found.")
        return
    print("Registered Users:")
    for user in creds["RegisteredUsers"]:
        print(" -", user)
    user_name = input("Enter username to generate a new key: ").strip()
    if user_name not in creds["RegisteredUsers"]:
        print("User not found.")
        return
    new_key = generate_key()
    creds["RegisteredUsers"][user_name]["key"] = new_key
    save_json_file(USER_CREDENTIALS_CONFIG, creds)
    try:
        with open(f"{user_name}.rs4v", "w") as f:
            f.write(new_key)
        print(f"New key generated for user {user_name}.")
    except Exception as e:
        print("Error generating key file:", e)


def turn_off_server():
    print("Turning off server...")
    os._exit(0)


def display_menu():
    return input(MENU_PROMPT).strip()


def menu_loop():
    while True:
        os.system("clear")
        print(BANNER)  # Print the colorful banner above the menu.
        choice = display_menu()
        if choice == '1':
            view_logs()
        elif choice == '2':
            add_remove_user()
        elif choice == '3':
            view_users_and_change_pass()
        elif choice == '4':
            save_log()
        elif choice == '5':
            restart_server()
        elif choice == '6':
            whitelist_blacklist()
        elif choice == '7':
            turn_off_server()
        elif choice == '8':
            generate_new_key()
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")
        input("Press Enter to return to the menu...")


# =========================
# Main Execution
# =========================

if __name__ == '__main__':
    proxy_thread = threading.Thread(target=run_proxy, daemon=True)
    proxy_thread.start()
    redirect_thread = threading.Thread(target=run_redirector, daemon=True)
    redirect_thread.start()
    time.sleep(2)
    menu_loop()
