#!/bin/bash
# WiFi Captive Portal Setup Wizard
# Interactive configuration script

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

INSTALL_DIR="/opt/captive-portal"
CONFIG_FILE="$INSTALL_DIR/config.json"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}❌ Please run as root: sudo $0${NC}"
    exit 1
fi

clear
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║          WiFi Captive Portal Setup Wizard                    ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "This wizard will guide you through the initial setup of your"
echo "captive portal system."
echo ""
read -p "Press Enter to continue..."

# ===========================
# Basic Configuration
# ===========================

clear
echo -e "${CYAN}═══ Basic Configuration ═══${NC}"
echo ""

read -p "Portal Name (e.g., Coffee Shop WiFi): " PORTAL_NAME
PORTAL_NAME=${PORTAL_NAME:-"WiFi Portal"}

read -p "WiFi Network Name (SSID): " SSID
SSID=${SSID:-"PublicHotspot"}

read -p "GitHub Pages URL (https://mb43.github.io/wifiportal): " GITHUB_URL
GITHUB_URL=${GITHUB_URL:-"https://mb43.github.io/wifiportal"}

read -p "WiFi Interface (default: wlan0): " INTERFACE
INTERFACE=${INTERFACE:-"wlan0"}

read -p "Domain name (default: wifi.portal): " DOMAIN
DOMAIN=${DOMAIN:-"wifi.portal"}

# Detect available network interfaces
echo ""
echo -e "${YELLOW}Available network interfaces:${NC}"
ip link show | grep -E '^[0-9]+:' | awk '{print "  - " $2}' | sed 's/:$//'
echo ""

# ===========================
# Authentication Methods
# ===========================

clear
echo -e "${CYAN}═══ Authentication Methods ═══${NC}"
echo ""
echo "Select which authentication methods to enable:"
echo ""

# Username/Password
AUTH_PASSWORD="true"
echo -e "${GREEN}✓ Username/Password (Always enabled)${NC}"

# Google OAuth
echo ""
read -p "Enable Google OAuth? (y/N): " ENABLE_GOOGLE
GOOGLE_ENABLED="false"
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""

if [[ "$ENABLE_GOOGLE" =~ ^[Yy]$ ]]; then
    GOOGLE_ENABLED="true"
    echo ""
    echo "To get Google OAuth credentials:"
    echo "1. Go to: https://console.cloud.google.com/apis/credentials"
    echo "2. Create OAuth 2.0 Client ID"
    echo "3. Add authorized redirect URI: ${GITHUB_URL}"
    echo ""
    read -p "Google Client ID: " GOOGLE_CLIENT_ID
    read -p "Google Client Secret: " GOOGLE_CLIENT_SECRET
fi

# Facebook OAuth
echo ""
read -p "Enable Facebook OAuth? (y/N): " ENABLE_FACEBOOK
FACEBOOK_ENABLED="false"
FACEBOOK_APP_ID=""
FACEBOOK_APP_SECRET=""

if [[ "$ENABLE_FACEBOOK" =~ ^[Yy]$ ]]; then
    FACEBOOK_ENABLED="true"
    echo ""
    echo "To get Facebook OAuth credentials:"
    echo "1. Go to: https://developers.facebook.com/apps"
    echo "2. Create a new app"
    echo "3. Add Facebook Login product"
    echo "4. Add OAuth redirect URI: ${GITHUB_URL}"
    echo ""
    read -p "Facebook App ID: " FACEBOOK_APP_ID
    read -p "Facebook App Secret: " FACEBOOK_APP_SECRET
fi

# Email Signup
echo ""
read -p "Enable Email Signup? (y/N): " ENABLE_EMAIL
EMAIL_ENABLED="false"
SMTP_HOST=""
SMTP_PORT="587"
SMTP_USER=""
SMTP_PASSWORD=""
FROM_ADDRESS=""

if [[ "$ENABLE_EMAIL" =~ ^[Yy]$ ]]; then
    EMAIL_ENABLED="true"
    echo ""
    echo "SMTP Configuration for sending verification emails:"
    read -p "SMTP Host (e.g., smtp.gmail.com): " SMTP_HOST
    read -p "SMTP Port (default: 587): " SMTP_PORT
    SMTP_PORT=${SMTP_PORT:-587}
    read -p "SMTP Username: " SMTP_USER
    read -sp "SMTP Password: " SMTP_PASSWORD
    echo ""
    read -p "From Email Address: " FROM_ADDRESS
fi

# LDAP/Active Directory
echo ""
read -p "Enable LDAP/Active Directory? (y/N): " ENABLE_LDAP
LDAP_ENABLED="false"
LDAP_HOST=""
LDAP_PORT="389"
LDAP_BASE_DN=""
LDAP_USER_DN_TEMPLATE=""
LDAP_USE_SSL="false"

if [[ "$ENABLE_LDAP" =~ ^[Yy]$ ]]; then
    LDAP_ENABLED="true"
    echo ""
    echo "LDAP Configuration:"
    read -p "LDAP Host (e.g., ldap.company.com): " LDAP_HOST
    read -p "LDAP Port (default: 389): " LDAP_PORT
    LDAP_PORT=${LDAP_PORT:-389}
    read -p "Base DN (e.g., dc=company,dc=com): " LDAP_BASE_DN
    read -p "User DN Template (e.g., cn={username},ou=users,dc=company,dc=com): " LDAP_USER_DN_TEMPLATE
    read -p "Use SSL? (y/N): " LDAP_SSL
    if [[ "$LDAP_SSL" =~ ^[Yy]$ ]]; then
        LDAP_USE_SSL="true"
    fi
fi

# ===========================
# Session Settings
# ===========================

clear
echo -e "${CYAN}═══ Session Settings ═══${NC}"
echo ""

read -p "Session timeout in seconds (default: 3600 = 1 hour): " SESSION_TIMEOUT
SESSION_TIMEOUT=${SESSION_TIMEOUT:-3600}

read -p "Bandwidth limit per user in KB/s (0 = unlimited): " BANDWIDTH_LIMIT
BANDWIDTH_LIMIT=${BANDWIDTH_LIMIT:-0}

# ===========================
# Generate Configuration File
# ===========================

clear
echo -e "${CYAN}═══ Generating Configuration ═══${NC}"
echo ""

cat > "$CONFIG_FILE" <<EOF
{
  "portal_name": "$PORTAL_NAME",
  "ssid": "$SSID",
  "github_portal_url": "$GITHUB_URL",
  "interface": "$INTERFACE",
  "domain": "$DOMAIN",
  "ports": {
    "redirect": 8080,
    "admin": 8443
  },
  "session": {
    "timeout": $SESSION_TIMEOUT,
    "bandwidth_limit": $BANDWIDTH_LIMIT
  },
  "auth": {
    "password": {
      "enabled": true
    },
    "google": {
      "enabled": $GOOGLE_ENABLED,
      "client_id": "$GOOGLE_CLIENT_ID",
      "client_secret": "$GOOGLE_CLIENT_SECRET"
    },
    "facebook": {
      "enabled": $FACEBOOK_ENABLED,
      "app_id": "$FACEBOOK_APP_ID",
      "app_secret": "$FACEBOOK_APP_SECRET"
    },
    "email": {
      "enabled": $EMAIL_ENABLED,
      "smtp_host": "$SMTP_HOST",
      "smtp_port": $SMTP_PORT,
      "smtp_user": "$SMTP_USER",
      "smtp_password": "$SMTP_PASSWORD",
      "from_address": "$FROM_ADDRESS"
    },
    "ldap": {
      "enabled": $LDAP_ENABLED,
      "host": "$LDAP_HOST",
      "port": $LDAP_PORT,
      "base_dn": "$LDAP_BASE_DN",
      "user_dn_template": "$LDAP_USER_DN_TEMPLATE",
      "use_ssl": $LDAP_USE_SSL
    }
  }
}
EOF

echo -e "${GREEN}✓ Configuration saved to $CONFIG_FILE${NC}"

# ===========================
# Generate SSL Certificates
# ===========================

echo ""
echo -e "${CYAN}═══ Generating SSL Certificates ═══${NC}"
echo ""

CERT_DIR="$INSTALL_DIR/certs"
mkdir -p "$CERT_DIR"

if [ ! -f "$CERT_DIR/portal.crt" ]; then
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout "$CERT_DIR/portal.key" \
        -out "$CERT_DIR/portal.crt" \
        -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
        2>/dev/null

    echo -e "${GREEN}✓ SSL certificates generated${NC}"
else
    echo -e "${YELLOW}⚠ SSL certificates already exist${NC}"
fi

# ===========================
# Configure Services
# ===========================

echo ""
echo -e "${CYAN}═══ Configuring Services ═══${NC}"
echo ""

# hostapd configuration
echo "Configuring hostapd..."
sed "s/{{INTERFACE}}/$INTERFACE/g; s/{{SSID}}/$SSID/g" \
    "$INSTALL_DIR/config/hostapd.conf.template" > /etc/hostapd/hostapd.conf
echo -e "${GREEN}✓ hostapd configured${NC}"

# dnsmasq configuration
echo "Configuring dnsmasq..."
sed "s/{{INTERFACE}}/$INTERFACE/g" \
    "$INSTALL_DIR/config/dnsmasq.conf.template" > /etc/dnsmasq.conf
echo -e "${GREEN}✓ dnsmasq configured${NC}"

# nginx configuration
echo "Configuring nginx..."
sed "s|{{REDIRECT_PORT}}|8080|g; s|{{ADMIN_PORT}}|8443|g; s|{{DOMAIN}}|$DOMAIN|g; s|{{GITHUB_PORTAL_URL}}|$GITHUB_URL|g" \
    "$INSTALL_DIR/config/nginx.conf.template" > /etc/nginx/sites-available/captive-portal
ln -sf /etc/nginx/sites-available/captive-portal /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
echo -e "${GREEN}✓ nginx configured${NC}"

# firewall configuration
echo "Configuring firewall..."
sed "s/{{INTERFACE}}/$INTERFACE/g; s/{{REDIRECT_PORT}}/8080/g; s/{{ADMIN_PORT}}/8443/g" \
    "$INSTALL_DIR/scripts/firewall.sh.template" > "$INSTALL_DIR/scripts/firewall.sh"
chmod +x "$INSTALL_DIR/scripts/firewall.sh"
bash "$INSTALL_DIR/scripts/firewall.sh"
echo -e "${GREEN}✓ Firewall rules applied${NC}"

# ===========================
# Configure Network Interface
# ===========================

echo ""
echo -e "${CYAN}═══ Configuring Network Interface ═══${NC}"
echo ""

# Configure static IP for WiFi interface
cat > /etc/network/interfaces.d/$INTERFACE <<EOF
auto $INTERFACE
iface $INTERFACE inet static
    address 192.168.4.1
    netmask 255.255.255.0
EOF

# Bring interface up
ifconfig $INTERFACE 192.168.4.1 netmask 255.255.255.0 2>/dev/null || true

echo -e "${GREEN}✓ Network interface configured${NC}"

# ===========================
# Start Services
# ===========================

echo ""
echo -e "${CYAN}═══ Starting Services ═══${NC}"
echo ""

# Stop services first
systemctl stop hostapd dnsmasq nginx captive-portal-api 2>/dev/null || true

# Start services
echo "Starting hostapd..."
systemctl enable hostapd
systemctl start hostapd
echo -e "${GREEN}✓ hostapd started${NC}"

echo "Starting dnsmasq..."
systemctl enable dnsmasq
systemctl start dnsmasq
echo -e "${GREEN}✓ dnsmasq started${NC}"

echo "Starting nginx..."
systemctl enable nginx
systemctl start nginx
echo -e "${GREEN}✓ nginx started${NC}"

echo "Starting portal API..."
systemctl enable captive-portal-api
systemctl start captive-portal-api
sleep 2
echo -e "${GREEN}✓ Portal API started${NC}"

# ===========================
# Verify Services
# ===========================

echo ""
echo -e "${CYAN}═══ Verifying Services ═══${NC}"
echo ""

check_service() {
    if systemctl is-active --quiet $1; then
        echo -e "${GREEN}✓ $1 is running${NC}"
        return 0
    else
        echo -e "${RED}✗ $1 is not running${NC}"
        return 1
    fi
}

ALL_OK=true
check_service hostapd || ALL_OK=false
check_service dnsmasq || ALL_OK=false
check_service nginx || ALL_OK=false
check_service captive-portal-api || ALL_OK=false

# ===========================
# Summary
# ===========================

clear
echo -e "${GREEN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                                                               ║"
echo "║                 Setup Complete! 🎉                           ║"
echo "║                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo -e "${CYAN}Portal Configuration:${NC}"
echo "  • Portal Name: $PORTAL_NAME"
echo "  • WiFi SSID: $SSID"
echo "  • Interface: $INTERFACE"
echo "  • Portal URL: $GITHUB_URL"
echo ""
echo -e "${CYAN}Authentication Methods:${NC}"
echo "  • Username/Password: ✓ Enabled"
[[ "$GOOGLE_ENABLED" == "true" ]] && echo "  • Google OAuth: ✓ Enabled"
[[ "$FACEBOOK_ENABLED" == "true" ]] && echo "  • Facebook OAuth: ✓ Enabled"
[[ "$EMAIL_ENABLED" == "true" ]] && echo "  • Email Signup: ✓ Enabled"
[[ "$LDAP_ENABLED" == "true" ]] && echo "  • LDAP/AD: ✓ Enabled"
echo ""
echo -e "${CYAN}Access Information:${NC}"
echo "  • Portal URL: $GITHUB_URL"
echo "  • Admin Panel: https://$(hostname -I | awk '{print $1}'):8443"
echo "  • Default Admin: admin / admin123"
echo ""
echo -e "${CYAN}Next Steps:${NC}"
echo "  1. Users can now connect to '$SSID' WiFi"
echo "  2. They will be redirected to the portal automatically"
echo "  3. Access admin panel to manage users and settings"
echo "  4. View logs: journalctl -u captive-portal-api -f"
echo ""

if [ "$ALL_OK" = true ]; then
    echo -e "${GREEN}✅ All services are running correctly!${NC}"
else
    echo -e "${YELLOW}⚠ Some services may need attention. Check status with:${NC}"
    echo "   systemctl status hostapd dnsmasq nginx captive-portal-api"
fi

echo ""
echo -e "${CYAN}Configuration Tips:${NC}"
echo "  • To reconfigure: sudo $0"
echo "  • Edit config: $CONFIG_FILE"
echo "  • View logs: tail -f /var/log/captive-portal/*.log"
echo "  • Restart API: systemctl restart captive-portal-api"
echo ""
echo -e "${BLUE}For support: https://github.com/mb43/wifiportal${NC}"
echo ""
