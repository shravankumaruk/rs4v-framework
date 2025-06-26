#!/bin/bash
 
# RS4V AutoInstaller
 
echo -e "\e[1;34m"  # Set color to bold blue
 
sleep 0.5
echo "###############################################"
sleep 0.5
echo "#                                             #"
sleep 0.5
echo "#      RS4V AutoInstaller - Starting          #"
sleep 0.5
echo "#                                             #"
sleep 0.5
echo "###############################################"
sleep 0.5
 
echo -e "\e[0m"  # Reset color
 
# Ensure script runs with root privileges
if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi
 
echo "Updating package list and upgrading existing packages..."
sudo apt update && sudo apt upgrade -y
 
echo "Installing dependencies..."
sudo apt install -y gnupg curl unzip wget lsb-release software-properties-common
 
echo "Installing Orthanc and plugins from official Ubuntu repositories..."
sudo apt install -y orthanc orthanc-webviewer
 
echo "Starting and enabling Orthanc service..."
sudo systemctl enable --now orthanc
 
# Install Python dependencies
echo "Installing Python3 and pip..."
sudo apt install -y python3-pip python3
echo "Python3 and pip installation completed. This is for http proxy setup"
 
# Install Python packages using pip3 with --break-system-packages and --ignore-installed flags
echo "Installing Flask, requests, Pillow, and ReportLab using pip3..."
sudo pip3 install --break-system-packages --ignore-installed Flask requests Pillow reportlab
echo "Python packages installed successfully."
 
# Modify WebViewer.json configuration
echo "Modifying WebViewer configuration..."
cat <<EOL | sudo tee /etc/orthanc/webviewer.json > /dev/null
{
  "WebViewer" : {
      "CachePath" : "/tmp/OrthancWebViewerCache",
      "WebViewer": true
  }
}
EOL
echo "WebViewer configuration updated successfully."
 
# Get the IP address of the server
IP_ADDR=$(hostname -I | awk '{print $1}')
 
# Output the login URL
echo -e "\e[1;32mInstallation completed successfully!\e[0m"
echo "You can also access Orthanc locally via: http://localhost:8042"
