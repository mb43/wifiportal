#!/bin/bash
# One-command installer
# Usage: curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

REPO_URL="https://github.com/mb43/wifiportal"
INSTALL_DIR="/opt/captive-portal"
TEMP_DIR="/tmp/wifi-portal-install"

echo -e "${BLUE}🌐 WiFi Captive Portal Installer${NC}"

# Check if root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root${NC}"
    exit 1
fi

# Check OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    echo -e "${GREEN}✅ Detected: $PRETTY_NAME${NC}"
else
    echo -e "${RED}❌ Unsupported OS${NC}"
    exit 1
fi

# Install git if needed
if ! command -v git &> /div/null; then
    echo "Installing git..."
    apt update && apt install -y git || yum install -y git || dnf install -y git
fi

# Clone repository
echo "📥 Downloading files..."
rm -rf $TEMP_DIR
git clone $REPO_URL $TEMP_DIR

# Install dependencies
echo "📦 Installing dependencies..."
cd $TEMP_DIR
chmod +x scripts/install-dependencies.sh
./scripts/install-dependencies.sh

# Setup directories
echo "📁 Creating directories..."
mkdir -p $INSTALL_DIR/{api,config,scripts,certs,logs}
mkdir -p /var/www/captive-portal
mkdir -p /var/log/captive-portal

# Copy files
echo "📋 Installing files..."
cp api/portal-api.py $INSTALL_DIR/api/
cp api/requirements.txt $INSTALL_DIR/api/
cp -r config/* $INSTALL_DIR/config/
cp -r scripts/* $INSTALL_DIR/scripts/
cp setup-wizard.sh $INSTALL_DIR/
chmod +x $INSTALL_DIR/setup-wizard.sh
chmod +x $INSTALL_DIR/scripts/*

# Setup Python environment
echo "🐍 Setting up Python..."
cd $INSTALL_DIR
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r api/requirements.txt

# Install systemd services
cp $TEMP_DIR/api/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable captive-portal-api

# Enable IP forwarding
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf
sysctl -p

# Cleanup
rm -rf $TEMP_DIR

echo -e "${GREEN}✅ Installation complete!${NC}"
echo ""
echo "Next steps:"
echo "1. Setup GitHub Pages: https://github.com/mb43/wifiportal/settings/pages"
echo "2. Run setup wizard: sudo $INSTALL_DIR/setup-wizard.sh"
echo "3. Your portal URL: https://mb43.github.io/wifiportal"
