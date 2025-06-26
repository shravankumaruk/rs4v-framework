#!/usr/bin/env python3
import subprocess
import os
import sys

# Attempt to import pyfiglet for creating ASCII art.
try:
    from pyfiglet import figlet_format
except ImportError:
    # Install pyfiglet with --break-system-packages
    subprocess.run("pip3 install --break-system-packages pyfiglet", shell=True)
    from pyfiglet import figlet_format

def print_rainbow_banner(text):
    """
    Displays a rainbow-colored banner with the provided text using ASCII art.
    """
    ascii_art = figlet_format(text)
    colors = ['\033[31m', '\033[33m', '\033[32m', '\033[36m', '\033[34m', '\033[35m']
    lines = ascii_art.splitlines()
    color_index = 0
    for line in lines:
        color = colors[color_index % len(colors)]
        print(color + line + '\033[0m')
        color_index += 1

def run_commands(commands):
    """
    Executes each command in the provided list sequentially.
    If any command fails, the script exits with an error.
    """
    for command in commands:
        print(f"\nExecuting: {command}")
        result = subprocess.run(command, shell=True)
        if result.returncode != 0:
            print(f"Command failed: {command}")
            sys.exit(1)

def main():
    # Ensure the script is executed as root.
    if os.geteuid() != 0:
        print("This script must be run as root. Exiting.")
        sys.exit(1)

    # Display the rainbow banner.
    print_rainbow_banner("RS4V Framework")
    
    # Present the menu options.
    print("\nPlease select an option from the menu below:")
    print("1) Install orthanc with WebViewer automatically.")
    print("2) Run proxy server.")
    print("3) Scan for vulnerabilities in the system.")
    
    choice = input("\nEnter your choice (1/2/3): ").strip()

    if choice == "1":
        # Commands for option 1 (using dos2unix).
        commands = [
            "sudo apt install dos2unix -y",
            "dos2unix install.sh",
            "chmod +x install.sh",
            "sudo bash install.sh"
        ]
        run_commands(commands)
    elif choice == "2":
        # Commands for option 2.
        # Instead of uninstalling blinker (which fails if installed by Debian),
        # override it in your Python environment.
        commands = [
            "pip3 install --break-system-packages --ignore-installed blinker",
            "pip3 install --break-system-packages flask requests pillow",
            "sudo -E python3 server.py"
        ]
        run_commands(commands)
    elif choice == "3":
        # Commands for option 3.
        commands = [
            "pip3 install --break-system-packages reportlab",
            "sudo -E python3 scanner.py"
        ]
        run_commands(commands)
    else:
        print("Invalid selection. Kindly re-run the script and choose a valid option.")
        sys.exit(1)

if __name__ == "__main__":
    main()
