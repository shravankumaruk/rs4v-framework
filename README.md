# 🏥 RS4V Orthanc Installer & Proxy Documentation (NITK Award winning 🥇 1st Place)
<p align="center">
  <img src="https://shravanprojects.github.io/rs4v-framework/logo.png" alt="RS4V Logo" width="250"/>
</p>

<p align="center">
  <!-- Shields.io Badges (10) -->
  <img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge&logo=gnu" alt="License: GPL v3" />
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python version" />
  <img src="https://img.shields.io/badge/Orthanc-1.9.0-green?style=for-the-badge" alt="Orthanc version" />
  <img src="https://img.shields.io/badge/Proxy-Secure%20HTTPS-red?style=for-the-badge" alt="Secure HTTPS Proxy" />
  <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge&logo=github" alt="CI Build Passing" />
  <img src="https://img.shields.io/badge/Version-1.0.0-yellow?style=for-the-badge" alt="Version 1.0.0" />
  <img src="https://img.shields.io/badge/Issues-Welcome-lightgrey?style=for-the-badge&logo=github" alt="Issues Welcome" />
  <img src="https://img.shields.io/badge/PRs-Welcome-orange?style=for-the-badge&logo=gitpullrequest" alt="PRs Welcome" />
  <img src="https://img.shields.io/badge/Platform-Ubuntu-blue?style=for-the-badge&logo=ubuntu" alt="Ubuntu Compatible" />
  <img src="https://img.shields.io/badge/Download-zip-blue?style=for-the-badge&logo=download" alt="Download ZIP" />

</p>




<p align="center">
  <img src="https://img.shields.io/github/stars/shravankumaruk/rs4v-framework?style=for-the-badge" alt="GitHub Stars"/>
  <img src="https://img.shields.io/github/forks/shravankumaruk/rs4v-framework?style=for-the-badge" alt="GitHub Forks"/>
  <img src="https://img.shields.io/github/watchers/shravankumaruk/rs4v-framework?style=for-the-badge" alt="GitHub Watchers"/>
  <img src="https://img.shields.io/github/v/release/shravankumaruk/rs4v-framework?style=for-the-badge" alt="GitHub Release"/>
  <img src="https://img.shields.io/github/downloads/shravankumaruk/rs4v-framework/total?style=for-the-badge" alt="Total Downloads"/>
</p>



<p align="center">
  <!-- ForTheBadge (5) replaced with fun code-related badges -->
  <img src="https://forthebadge.com/images/badges/built-with-love.svg" alt="Built with Love" />
<img src="https://forthebadge.com/images/badges/powered-by-black-magic.svg" alt="Powered by Black Magic Badge" />
<img src="https://forthebadge.com/images/badges/works-on-my-machine.svg" alt="Works on My Machine Badge" />
  <img src="https://forthebadge.com/images/badges/uses-git.svg" alt="Uses Git" />
  <img src="https://forthebadge.com/images/badges/built-by-developers.svg" alt="Devs"/>
  </p>
  
<p align="center">
  <img src="https://img.shields.io/badge/nginx-%23009639.svg?style=for-the-badge&logo=nginx&logoColor=white" alt="Nginx Badge"/>
  <img src="https://img.shields.io/badge/bash_script-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white" alt="Bash Script"/>
  <img src="https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white" alt="Ubuntu"/>
  <img src="https://img.shields.io/badge/Kali-268BEE?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux"/>
  <img src="https://img.shields.io/badge/html5-%23E34F26.svg?style=for-the-badge&logo=html5&logoColor=white" alt="HTML5"/>
  <img src="https://img.shields.io/badge/pycharm-143?style=for-the-badge&logo=pycharm&logoColor=black&color=black&labelColor=green" alt="PyCharm"/>
</p>

<hr>
<p align="center">
  <!-- Read About PDF Button -->
  <a href="https://shravanprojects.github.io/rs4v-framework/PACS-DICOM.pdf" target="_blank">
    <img src="https://img.shields.io/badge/Click%20Here%20to%20Read%20About-PDF-red?style=for-the-badge&logo=adobe" alt="Read About PDF" />
  </a>
</p>
<hr>



## 🔍 Table of Contents

1. [Introduction](#introduction)
2. [Features 🚀](#features-)
3. [Prerequisites ✅](#prerequisites-)
4. [Installation 🛠️](#installation-)

   * [Method 1: Manual Pip Installation](#method-1-manual-pip-installation)
   * [Method 2: Automated Script (install.sh)](#method-2-automated-script-installsh)
5. [Configuration 🔧](#configuration-)
6. [Usage ✨](#usage-)
7. [Proxy & Security 📡🛡️](#proxy--security-)
8. [Video Tutorial 🎬](#video-tutorial-)
9. [Screenshots 📸](#screenshots-)
10. [Troubleshooting 🐞](#troubleshooting-)
11. [Contributing 🤝](#contributing-)
12. [License & Credits 📄](#license--credits-)
13. [Acknowledgements 🙏](#acknowledgements-)

---

## 📝 Introduction

In modern healthcare, managing DICOM images securely is paramount. **RS4V Orthanc Installer & Proxy** offers an end-to-end solution to deploy Orthanc—a powerful, lightweight DICOM server—behind a hardened HTTPS proxy. This framework not only automates installation and configuration but also integrates advanced security controls such as WAF, rate limiting, CVE scanning, audit logging, two-factor authentication (2FA), and PDF report generation. The interactive CLI harnesses `pyfiglet` to present a fun, easy-to-navigate menu, while the underlying scripts ensure reproducible, production-ready deployments.

---

## 🎉 Features 🚀

Below is an overview of the key features included in RS4V Orthanc Installer & Proxy:

| **Feature**                         | **Description**                                                                                                          |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| 🔒 **Secure HTTPS Proxy**           | TLS termination via self-signed certs, integrated with own built in servers |
| 🔐 **Two-Factor Authentication**    | Uses our in house .rs4v key based authentication which can be regenrated also.                                         |
| 🔍 **Automated CVE Scanning**       | Updated to scan Orthanc endpoints for known vulnerabilities (see PACS-DICOM.pdf for details)      |
| 📋 **Audit Logging & PDF Reports**  | Centralized logging of operations and user actions—all logs emitted by `server.py` in your home directory                |
| 🛠️ **Automated Installer**         | `install.sh` script installs dependencies, sets up services, gathers TLS certs, configures JSON/YAML files               |
| 🎨 **Interactive CLI Menu**         | ASCII-art headers and numbered options guided by `pyfiglet`, making operations intuitive and visually appealing          |
| ⚙️ **Config Management**            | Declarative JSON/YAML under `your-project` directory—easy to customize Orthanc, proxy, auth, and WAF settings                 |
| 🔄 **Backup & Restore**             | One-line commands to view backup logs                                  |
| 🔄 **Health Checks & Monitoring**   | Built-in ORTHANC Webviewer to view DICOM(.dcm) files easily via browser                              |
| 🛡️ **Rate Limiting & DoS Defense** | Configurable rate limits on REST API calls to mitigate brute-force and flood attacks                                     |
| 🧩 **Plugin Architecture**          | Design patterns to extend backend logic, such as custom anonymization or routing plugins                                 |
| 🛠️ **Troubleshooting Helpers**     | Scripts and tips for common pitfalls—`dos2unix` for Windows line endings, permission fixes, port conflicts               |

---
![image](https://github.com/user-attachments/assets/efe106c4-9f35-4a83-a798-81ae5d6dcd3a)

![image](https://github.com/user-attachments/assets/3520d309-d507-4c9c-ac10-1a51ba153ca8)

![image](https://github.com/user-attachments/assets/718ca5af-fa71-40e6-8704-d910b8ee3e05)

![image](https://github.com/user-attachments/assets/952e2221-2bd9-47a3-a73c-de4fb3ac303b)

![image](https://github.com/user-attachments/assets/1cf80c36-769c-471b-a0ff-e4b48cd3c361)

![image](https://github.com/user-attachments/assets/11d649c5-7996-4f8e-8c0c-c34ce5553fcc)



---
## ✅ Prerequisites

Before you begin, ensure your system meets the following requirements:

* **Operating System**: Ubuntu 18.04 or newer (or Debian-based distros).
* **Python**: Version 3.8+ installed and accessible as `python3`.
* **Git**: For cloning this repository.
* **Sudo** or **root** privileges.
* **Recommended Utilities**:

  * `dos2unix` (to normalize script line endings).
  * `curl` or `wget` (for network operations).
  * `jq` (for JSON validation).


---

## ⚙️ Installation 🛠️

We support two installation methods—choose whichever suits your workflow.

### Method 1: Manual Pip Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/shravankumaruk/rs4v-framework.git
   cd rs4v-framework
   ```

2. **Install Python dependencies**:

   ```bash
   pip3 install pyfiglet requests pyyaml
   ```

3. **Run the main script**:

   ```bash
   sudo -E python3 main.py
   ```

   * The `-E` flag preserves environment variables, ensuring certificates and paths resolve correctly.

### Method 2: Automated Script (install.sh)

For a single-command setup:

```bash
sudo bash install.sh
sudo -E python3 main.py
```

The `install.sh` does the following:

* Installs system packages: `orthanc`, `nginx`, `modsecurity`, `python3-pip`, etc.
* Obtains TLS certificates generates self-signed.
* Configures Nginx as a reverse proxy with WAF rules.
* Sets up Orthanc JSON config with secure defaults.
* Creates systemd services for auto-start on boot.

> **Pro Tip**: If you hit a `python: bad interpreter: No such file or directory` error, normalize line endings:
>
> ```bash
> dos2unix main.py
> ```

---

## 🔧 Configuration

All configuration files live under the directory where you installed (type `pwd` in terminal):

* `captive_credentials.json`: Orthanc users and pass with keys stored
* `/etc/orthanc/orthanc.json`: Original config for ORTHANC Servers.
* `User.rs4V`: This will be your generated Key.

My real snippet from `captive_credentials.json`:

```json
{
    "RegisteredUsers": {
        "shravan": {
            "password": "07417e5860dfe946c74f32120b2a35500dd3fb508e9627ab7be7084bbdc4ba16",
            "key": "Xc4Dy9B905FEz6J147f03fup3l8ukh79"
        }
    }

```

> **Security Note**: Our application stores password in hashes use server.py or access via main.py to change or remove passwords or add or remove users or else direct modification may result in errors.

---

## ✨ Usage

Below is the exact output when launching `main.py`:

```bash
shravan@shravan-pc:~/Desktop$ sudo -E python3 main.py
 ____  ____  _  ___     __
|  _ \/ ___|| || \ \   / /
| |_) \___ \| || |\ \ / / 
|  _ < ___) |__   _\ V /  
|_| \_\____/   |_|  \_/   
                          
 _____                                            _    
|  ___| __ __ _ _ __ ___   _____      _____  _ __| | __
| |_ | '__/ _` | '_ ` _ \ / _ \ \ /\ / / _ \| '__| |/ /
|  _|| | | (_| | | | | | |  __/\ V  V / (_) | |  |   < 
|_|  |_|  \__,_|_| |_| |_|\___| \_/\_/ \___/|_|  |_|\_\
                                                       
Please select an option from the menu below:
1) Install orthanc with WebViewer automatically.
2) Run proxy server.
3) Scan for vulnerabilities in the system.

Enter your choice (1/2/3):
```

Use the numeric choice to access installer, proxy setup, or vulnerability scanning.

All logs are emitted by `server.py` in your home directory; you can view live logs by running `python3 server.py`, or check archived logs there. For PDF report generation details, refer to the Video Tutorial.
```bash
****************************************
*   RS4V WAF Server Panel              *
****************************************

=============================
Proxy Server Control Menu
=============================
1) View logs
2) Add/Remove user (no captcha)
3) View Users and Change Password
4) Save PDF report
5) Restart Server
6) Whitelist/Blacklist an IP address
7) Turn off Server
8) Generate new key for a user
=============================
Enter your choice (1-8): 1
Displaying log contents:
2025-06-26 23:13:51 - WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.142.144:80
2025-06-26 23:13:51 - Press CTRL+C to quit
2025-06-26 23:13:54 - WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on https://127.0.0.1:443
 * Running on https://192.168.142.144:443
2025-06-26 23:13:54 - Press CTRL+C to quit

Press Enter to return to the menu...
```
### 🛡️ Vulnerability Scanner (`scanner.py`)

```bash
  _   _ _____ _______ _  __     _____  _____ 
 | \ | |_   _|__   __| |/ /    | ____|/ ____|
 |  \| | | |    | |  | ' /_____| |__ | |     
 | . ` | | |    | |  |  <______|___ \| |     
 | |\  |_| |_   | |  | . \      ___) | |____ 
 |_| \_|_____|  |_|  |_|\_\    |____/ \_____|

                      RS4V Security Scanner

====== Orthanc Vulnerability Scanner Menu ======
1) Scan For Vulnerability (Basic Orthanc info + config check)
2) List All CVEs
3) Save as PDF (Report with graphics and CVE scores)
0) Exit
==================================================
Enter your choice:
📄 Tip: Selecting Option 3 generates a detailed PDF report with visual CVE scoring graphs and summary tables.
📘 For CVE scan logic and methodology, refer to PACS-DICOM.pdf.
🎥 If unsure how to run this, check the Video Tutorial section.
```

## 📡 Proxy & Security

An Nginx reverse proxy fronts Orthanc to enforce robust security:

* **TLS Termination**: Secure all client-server traffic.
* **ModSecurity WAF**: Apply custom DICOM and OWASP CRS rules.
* **Rate Limiting**: Throttle per-IP API calls to prevent abuse.
* **Daily CVE Checks**: Automated vulnerability scanning against public feeds (see PACS-DICOM.pdf for scan methodology).

All logs are emitted by `server.py` in your home directory and include proxy, WAF, and scan events.


## 🎬 Video Tutorial

[![Watch the video](https://img.youtube.com/vi/pBy1zgt0XPc/hqdefault.jpg)](https://www.youtube.com/watch?v=pBy1zgt0XPc)

Prefer a step-by-step walkthrough? Watch on YouTube:

▶️ [https://www.youtube.com/watch?v=pBy1zgt0XPc](https://www.youtube.com/watch?v=pBy1zgt0XPc)

Follow along to see live installation, menu navigation, and sample report generation.

---

## 📸 Screenshots

1. **Installation Progress**:

2. **Main Menu**:

3. **PDF Report**:



---

## 🐞 Troubleshooting

Comprehensive troubleshooting table from real-world usage:

| Symptom                             | Possible Cause                           | Solution                                                                             |
| ----------------------------------- | ---------------------------------------- | ------------------------------------------------------------------------------------ |
| `python: bad interpreter`           | DOS line endings in Python scripts       | Convert with `dos2unix *.py`                                                         |
| `Permission denied` on `install.sh` | Missing execute permission               | `chmod +x install.sh`                                                                |
| `port 8042 already in use`          | Another service occupying Orthanc port   | Change `HttpsPort` in `config/orthanc.json` and restart service                      |
| `TLS handshake failure`             | Invalid or expired certificates          | Regenerate with `sudo bash install.sh` or `certbot renew`                            |
| `CVE database fetch failed`         | Network connectivity or feed URL changed | Verify internet access, update CVE feed URL in `main.py`                             |
| **Service starts but no UI**        | Proxy misconfiguration                   | Check `server.py` targets `localhost:8042` and service is running            |
| **Slow image retrieval**            | High load or storage IO bottleneck       | Enable caching in Nginx, monitor disk I/O, or increase database performance settings |
| **2FA token invalid**               | Time drift on server or client           | Sync time with NTP (`sudo apt install ntp && sudo service ntp restart`)              |


---

## 🛠️ Maintenance & Support

If you encounter any bugs, issues, or discover a potential vulnerability 🐞🔐, please help us improve by opening an issue.

Click the button below to report it directly:

<p align="center">
  <a href="https://github.com/shravankumaruk/rs4v-framework/issues" target="_blank">
    <img src="https://img.shields.io/badge/Report%20an%20Issue-GitHub-blue?style=for-the-badge&logo=github" alt="Report an Issue"/>
  </a>
</p>

We have **custom labels** like `bug`, `security`, `enhancement`, and `question` to categorize and speed up triage.  
Your feedback keeps this project secure and strong 💪!





---



## 🤝 Contributing

We welcome all contributions—code, docs, tests, and bug reports! Please follow these steps:

1. Fork the repo and create a feature branch:

   ```bash
   git checkout -b feature/MyFeature
   ```
2. Commit changes with descriptive messages.
3. Push branch and open a Pull Request.
4. Use our **custom labels** to categorize your PR.

Be sure to run `flake8` and `jsonlint` to maintain code quality and config validity.

---

## 📄 License & Credits

© **Shravan Kumar UK** 2025

This project is licensed under the **GNU General Public License v3.0**. See [LICENSE](LICENSE) for full terms.

---

## 🙏 Acknowledgements

A big thank you to:

* **Regan**, **Shashank**, **Varad** for helping along with various DICOM Files and testing the server in local wireless ranges.
* **Orthanc** community for an extensible DICOM server.
* **pyfiglet** for making CLI art fun.
* **Ubuntu** for the best Open-Source OS
* **PyCharm** for free open source community edition IDE.
* **Nginx** for reverse proxy server.

---

<p align="center">
  🛠️ Made with ❤️ and a lot of coffee by <strong>Shravan Kumar UK</strong><br>
  🩺 Empowering secure and smart medical imaging — happy diagnosing! 📸🧠
</p>

---
