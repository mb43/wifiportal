#!/bin/bash
# Install system dependencies

set -e

echo "🔧 Installing system dependencies..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "❌ Cannot detect OS"
    exit 1
fi

# Install based on OS
case $OS in
    "ubuntu"|"debian"|"raspbian")
        apt update
        apt install -y \
            hostapd dnsmasq iptables-persistent \
            nginx python3 python3-pip python3-venv \
            sqlite3 openssl curl wget git \
            build-essential libssl-dev libffi-dev python3-dev
        ;;
    "centos"|"rhel"|"fedora")
        if command -v dnf &> /dev/null; then
            dnf install -y hostapd dnsmasq iptables-services nginx python3 python3-pip sqlite openssl curl wget git gcc gcc-c++ openssl-devel libffi-devel python3-devel
        else
            yum install -y hostapd dnsmasq iptables-services nginx python3 python3-pip sqlite openssl curl wget git gcc gcc-c++ openssl-devel libffi-devel python3-devel
        fi
        ;;
    *)
        echo "❌ Unsupported OS: $OS"
        exit 1
        ;;
esac

echo "✅ System dependencies installed"
