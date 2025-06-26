#!/usr/bin/env python3

import os
import sys
import json
import requests
import socket
import re
import shutil


###############################################################################
# Banner Function
###############################################################################
def print_banner():
    banner = r"""

  _   _ _____ _______ _  __     _____  _____ 
 | \ | |_   _|__   __| |/ /    | ____|/ ____|
 |  \| | | |    | |  | ' /_____| |__ | |     
 | . ` | | |    | |  |  <______|___ \| |     
 | |\  |_| |_   | |  | . \      ___) | |____ 
 |_| \_|_____|  |_|  |_|\_\    |____/ \_____|
                                             

                      RS4V Security Scanner
    """
    # Print the banner in bright magenta
    print("\033[95m" + banner + "\033[0m")


###############################################################################
# Copy orthanc.json from /etc/orthanc/orthanc.json to a local file
###############################################################################
def copy_orthanc_json(src="/etc/orthanc/orthanc.json", dst="orthanc_copy.json"):
    """
    Attempts to copy Orthanc config from /etc/orthanc/orthanc.json to a local file.
    Returns None if successful, or an error message if something went wrong.
    """
    if not os.path.exists(src):
        return f"Source file '{src}' not found."

    try:
        shutil.copyfile(src, dst)
        return None
    except Exception as e:
        return f"Error copying '{src}' to '{dst}': {e}"


###############################################################################
# Helper: Remove Comments from JSON Content
###############################################################################
def remove_comments(json_str):
    """
    Remove C-style (// and /* */) comments from a JSON string.
    Note: This is a simple approach and may not handle all edge cases.
    """
    # Remove block comments (/* ... */)
    json_str = re.sub(r'/\*.*?\*/', '', json_str, flags=re.DOTALL)
    # Remove line comments (//...)
    json_str = re.sub(r'//.*$', '', json_str, flags=re.MULTILINE)
    return json_str


###############################################################################
# Basic Orthanc Info & Vulnerability Scan
###############################################################################
def get_orthanc_version(url="http://localhost:8042/system"):
    """
    Retrieves Orthanc server details via its REST API.
    Expects a JSON response with a "Version" (or "version") key.
    """
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            version = data.get("Version") or data.get("version")
            if version:
                print(f"Detected Orthanc version: {version}")
                return version
            else:
                print("Orthanc version not found in API response.")
                return None
        else:
            print("Orthanc server responded with status code", response.status_code)
            return None
    except Exception as e:
        print("Error connecting to Orthanc server:", e)
        return None


def is_port_open(host, port):
    """
    Checks if a given port on a host is open.
    Used here to test if the DICOM service (default port 4242) is active.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False


def compare_versions(v1, v2):
    """
    Compares two version strings (e.g. "1.2.3") and returns True if v1 is older than v2.
    If parsing fails, returns True (assumes vulnerability).
    """

    def normalize(v):
        return [int(x) for x in v.split(".") if x.isdigit()]

    try:
        return normalize(v1) < normalize(v2)
    except Exception:
        return True


def scan_vulnerabilities():
    """
    Simulates scanning for vulnerabilities.
    - Checks the Orthanc REST API version against a secure threshold.
    - Checks if the DICOM port (4242) is open.

    Returns a dictionary of CVE entries with details, a simulated vulnerability status,
    and the detected Orthanc version.
    """
    secure_version = "1.15.0"
    orthanc_version = get_orthanc_version()
    version_vulnerable = True
    if orthanc_version:
        version_vulnerable = compare_versions(orthanc_version, secure_version)

    # Check if the DICOM port is open (simulating CVE-2019-11687)
    dicom_port_open = is_port_open("localhost", 4242)

    vulnerabilities = {}
    vulnerabilities["CVE-2019-11687"] = {
        "Category": "Dicom",
        "Fix": "----",
        "Details": "https://www.cisa.gov/news-events/ics-alerts/ics-alert-19-162-01",
        "Status": dicom_port_open,
        "Score": 7.5
    }
    vulnerabilities["CVE-2023-33466"] = {
        "Category": "Orthanc",
        "Fix": "----",
        "Details": "https://nvd.nist.gov/vuln/detail/CVE-2023-33466",
        "Status": version_vulnerable,
        "Score": 9.0
    }
    vulnerabilities["CVE-2024-22725"] = {
        "Category": "Orthanc",
        "Fix": "----",
        "Details": "https://nvd.nist.gov/vuln/detail/CVE-2024-22725",
        "Status": version_vulnerable,
        "Score": 8.5
    }
    vulnerabilities["CVE-2025-0896"] = {
        "Category": "Orthanc",
        "Fix": "----",
        "Details": "https://www.securityweek.com/orthanc-server-vulnerability-poses-risk-to-medical-data-healthcare-operations/",
        "Status": version_vulnerable,
        "Score": 8.0
    }
    vulnerabilities["CVE-2023-7238"] = {
        "Category": "Orthanc",
        "Fix": "----",
        "Details": "https://vulmon.com/vulnerabilitydetails?qid=CVE-2023-7238",
        "Status": version_vulnerable,
        "Score": 7.0
    }
    return vulnerabilities, orthanc_version


###############################################################################
# Orthanc Configuration Check (reads local copy orthanc_copy.json)
###############################################################################
def check_orthanc_config(local_file="orthanc_copy.json"):
    """
    Checks the Orthanc configuration file for security issues.
    Returns a list of strings describing issues if found.

    Conditions:
      - "HttpPort": if 8042 then warn (default port)
      - "HttpDescribeErrors": if true then warn (could expose sensitive info)
      - "DicomPort": if 4242 then warn (default DICOM port)
      - "RemoteAccessAllowed": if true then warn in bold red (exposed to internet)
      - "SslEnabled": if false then warn (connection is not encrypted)
      - "AuthenticationEnabled": if false then warn (should be enabled)
      - "DicomTlsEnabled": if false then warn (security issue)
    """
    issues = []
    if not os.path.exists(local_file):
        issues.append(f"Configuration file '{local_file}' not found (copy failed?).")
        return issues

    try:
        with open(local_file, "r") as f:
            content = f.read()
            clean_content = remove_comments(content)
            config = json.loads(clean_content)
    except Exception as e:
        issues.append(f"Error reading {local_file}: {e}")
        return issues

    if config.get("HttpPort") == 8042:
        issues.append("Default HTTP port (8042) is used. Consider changing it.")
    if config.get("HttpDescribeErrors") is True:
        issues.append("HttpDescribeErrors is enabled. It can expose sensitive information. Disable it.")
    if config.get("DicomPort") == 4242:
        issues.append("Default Dicom port (4242) is enabled. This might be a security issue.")
    if config.get("RemoteAccessAllowed") is True:
        issues.append("\033[91mRemoteAccessAllowed is enabled! System can be exposed to the internet.\033[0m")
    if config.get("SslEnabled") is False:
        issues.append("SSL is disabled. Connection is not encrypted. Security issue.")
    if config.get("AuthenticationEnabled") is False:
        issues.append("Authentication is disabled. Please enable it for security.")
    if config.get("DicomTlsEnabled") is False:
        issues.append("Dicom TLS is disabled. Security issue.")
    return issues


###############################################################################
# PDF Report Generation
###############################################################################
def generate_pdf_report(vulns, config_issues, orthanc_version):
    """
    Generates a PDF report with the scan results.
      - Orthanc version
      - A table of CVEs
      - Configuration issues
    """
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        print("ReportLab is not installed. Please install it with 'pip install reportlab'.")
        return

    doc = SimpleDocTemplate(
        "Orthanc_Scan_Report.pdf",
        pagesize=letter,
        leftMargin=30,
        rightMargin=30,
        topMargin=30,
        bottomMargin=30
    )
    styles = getSampleStyleSheet()
    Story = []
    Story.append(Paragraph("Orthanc Vulnerability Scan Report", styles["Title"]))
    Story.append(Spacer(1, 12))

    if orthanc_version:
        Story.append(Paragraph(f"Orthanc Version: {orthanc_version}", styles["Normal"]))
    else:
        Story.append(Paragraph("Orthanc Version: Not detected", styles["Normal"]))
    Story.append(Spacer(1, 12))

    # Vulnerability Table
    data = [["CVE", "Category", "Score", "Status", "Fix", "Details"]]
    for cve, info in vulns.items():
        data.append([
            cve,
            info["Category"],
            str(info["Score"]),
            str(info["Status"]),
            info["Fix"],
            info["Details"]
        ])

    col_widths = [80, 80, 50, 50, 80, 212]
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    Story.append(table)
    Story.append(Spacer(1, 24))

    # Configuration Issues Section
    Story.append(Paragraph("Orthanc Configuration Issues:", styles["Heading2"]))
    if config_issues:
        for issue in config_issues:
            clean_issue = re.sub(r'\033\[[0-9;]*m', '', issue)
            Story.append(Paragraph(f"- {clean_issue}", styles["Normal"]))
    else:
        Story.append(Paragraph("No configuration issues detected.", styles["Normal"]))
    Story.append(Spacer(1, 24))

    try:
        doc.build(Story)
        print("PDF report generated as Orthanc_Scan_Report.pdf")
    except Exception as e:
        print("Error generating PDF:", e)


###############################################################################
# Global Variables to Store Scan Results
###############################################################################
scan_results = None
orthanc_version = None
config_issues = None


###############################################################################
# Menu Functions
###############################################################################
def option_scan():
    """
    Option 1: Perform vulnerability scan AND check Orthanc configuration.
    1) Copy /etc/orthanc/orthanc.json to a local file (orthanc_copy.json)
    2) Scan for vulnerabilities
    3) Check orthanc_copy.json for security issues (after cleaning comments)
    4) Print findings
    """
    global scan_results, orthanc_version, config_issues

    # Copy the config file
    copy_error = copy_orthanc_json("/etc/orthanc/orthanc.json", "orthanc_copy.json")
    if copy_error:
        print(f"Could not copy /etc/orthanc/orthanc.json: {copy_error}")
        print("Continuing but config checks may fail...\n")

    # Scan for vulnerabilities
    print("\n--- Scanning for Vulnerabilities ---")
    scan_results, orthanc_version = scan_vulnerabilities()
    for cve, info in scan_results.items():
        print(f"CVE({cve}): {info['Status']}")
        print(f"  Category: {info['Category']}")
        print(f"  Fix: {info['Fix']}")
        print(f"  Details: {info['Details']}")
        print(f"  Score: {info['Score']}\n")

    # Check the local copy of Orthanc config
    print("--- Checking Orthanc Configuration (orthanc_copy.json) ---")
    config_issues = check_orthanc_config("orthanc_copy.json")
    if config_issues:
        for issue in config_issues:
            print(issue)
    else:
        print("No configuration issues detected.")
    print()


def option_list_cves():
    """
    Option 2: List all CVEs related to DICOM and Orthanc.
    Uses saved scan results if available, otherwise runs a scan first.
    """
    global scan_results
    if not scan_results:
        print("No scan results found. Running vulnerability scan first...")
        scan_results, _ = scan_vulnerabilities()
    print("\n--- Listing All CVEs ---")
    for cve, info in scan_results.items():
        print(f"CVE({cve}): {info['Status']}")
        print(f"  Category: {info['Category']}")
        print(f"  Fix: {info['Fix']}")
        print(f"  Details: {info['Details']}")
        print(f"  Score: {info['Score']}\n")


def option_save_pdf():
    """
    Option 3: Save the scan results as a PDF report.
    Runs a scan if not already done.
    """
    global scan_results, orthanc_version, config_issues
    if not scan_results:
        print("No scan results found. Running vulnerability scan first...")
        scan_results, orthanc_version = scan_vulnerabilities()
        copy_error = copy_orthanc_json("/etc/orthanc/orthanc.json", "orthanc_copy.json")
        if not copy_error:
            config_issues = check_orthanc_config("orthanc_copy.json")
        else:
            config_issues = [copy_error]
    generate_pdf_report(scan_results, config_issues, orthanc_version)


def print_menu():
    print("====== Orthanc Vulnerability Scanner Menu ======")
    print("1) Scan For Vulnerability (Basic Orthanc info + config check)")
    print("2) List All CVEs")
    print("3) Save as PDF (Report with graphics and CVE scores)")
    print("0) Exit")
    print("==================================================")


###############################################################################
# Main Menu Loop
###############################################################################
def main():
    # Print the colorful banner at startup
    print_banner()

    while True:
        print_menu()
        choice = input("Enter your choice: ").strip()
        if choice == "1":
            option_scan()
        elif choice == "2":
            option_list_cves()
        elif choice == "3":
            option_save_pdf()
        elif choice == "0":
            print("Exiting.")
            break
        else:
            print("Invalid choice. Please try again.\n")
        input("Press Enter to continue...")


if __name__ == "__main__":
    main()
