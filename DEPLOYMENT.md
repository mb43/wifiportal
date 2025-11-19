# 🚀 WiFi Captive Portal - Complete Deployment Guide

This guide will walk you through deploying a fully-featured WiFi captive portal with multiple authentication methods.

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Authentication Configuration](#authentication-configuration)
- [Troubleshooting](#troubleshooting)
- [Maintenance](#maintenance)
- [Architecture](#architecture)

---

## Prerequisites

### Hardware Requirements

- **Linux Server** (Mac/Windows NOT supported for hosting)
  - Ubuntu 18.04+, Debian 9+, CentOS 7+, or Raspberry Pi OS
  - 1GB+ RAM
  - 2+ CPU cores
  - 10GB+ storage
- **WiFi Interface** that supports AP (Access Point) mode
  - Raspberry Pi: Built-in WiFi works great
  - Servers: USB WiFi adapter or PCIe card
- **Internet Connection** via Ethernet or second WiFi adapter

### Software Requirements

All dependencies are installed automatically:
- hostapd (WiFi access point)
- dnsmasq (DNS/DHCP server)
- nginx (web server)
- Python 3.6+ (API backend)
- iptables (firewall)

### Development (Your Mac/Windows)

- Git
- Text editor
- GitHub account

---

## Quick Start

### 1. Setup GitHub Pages (One-Time, from your Mac/PC)

Your portal interface is hosted on GitHub Pages. This must be set up first:

```bash
# If you haven't already pushed to GitHub
cd /path/to/wifiportal
git add .
git commit -m "Complete portal system"
git push origin main
```

Then enable GitHub Pages:
1. Go to: https://github.com/mb43/wifiportal/settings/pages
2. **Source**: Select `main` branch, `/root` folder
3. Click **Save**
4. Wait 2-3 minutes for deployment
5. Verify at: https://mb43.github.io/wifiportal

### 2. Deploy to Linux Server

SSH into your Linux server and run:

```bash
# One command installs everything
curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash

# Run the configuration wizard
sudo /opt/captive-portal/setup-wizard.sh
```

### 3. Connect and Test

1. Look for the WiFi network (SSID you configured)
2. Connect from your phone/laptop
3. Browser should auto-redirect to the portal
4. Login and get internet access!

---

## Detailed Setup

### Step 1: Clone Repository (Development)

On your Mac/PC:

```bash
git clone https://github.com/mb43/wifiportal.git
cd wifiportal
```

### Step 2: Enable GitHub Pages

1. Push your code to GitHub
2. Go to Repository Settings → Pages
3. Enable Pages from `main` branch
4. Note your URL: `https://mb43.github.io/wifiportal`

### Step 3: Server Installation

On your Linux server:

```bash
# Download and run installer
curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash
```

This will:
- Install all dependencies (hostapd, dnsmasq, nginx, Python)
- Create directory structure in `/opt/captive-portal`
- Set up Python virtual environment
- Install Python packages
- Create systemd services
- Enable IP forwarding

### Step 4: Run Configuration Wizard

```bash
sudo /opt/captive-portal/setup-wizard.sh
```

The wizard will guide you through:

1. **Basic Configuration**
   - Portal name
   - WiFi SSID
   - Network interface (wlan0, wlan1, etc.)
   - GitHub Pages URL

2. **Authentication Methods**
   - Username/Password (always enabled)
   - Google OAuth (optional)
   - Facebook OAuth (optional)
   - Email Signup (optional)
   - LDAP/Active Directory (optional)

3. **Session Settings**
   - Session timeout
   - Bandwidth limits

4. **Service Configuration**
   - Generate SSL certificates
   - Configure hostapd, dnsmasq, nginx
   - Apply firewall rules
   - Start all services

---

## Authentication Configuration

### Username/Password (Built-in)

Always enabled. Demo users:
- `admin` / `admin123`
- `demo` / `demo123`
- `user` / `password`

To add permanent users, use the API or database:

```bash
# Access the database
sqlite3 /opt/captive-portal/portal.db

# Add user (password will be hashed automatically via API)
# Use the admin panel instead for easier management
```

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create project → Create OAuth 2.0 Client ID
3. Application type: **Web application**
4. Authorized redirect URIs:
   ```
   https://mb43.github.io/wifiportal
   ```
5. Copy **Client ID** and **Client Secret**
6. Enter in setup wizard or admin panel

### Facebook OAuth

1. Go to [Facebook Developers](https://developers.facebook.com/apps)
2. Create App → Business Type
3. Add **Facebook Login** product
4. Settings → Valid OAuth Redirect URIs:
   ```
   https://mb43.github.io/wifiportal
   ```
5. Copy **App ID** and **App Secret**
6. Enter in setup wizard or admin panel

### Email Signup (SMTP)

Requires SMTP server for sending verification codes.

**Gmail Example:**
```
SMTP Host: smtp.gmail.com
SMTP Port: 587
SMTP User: your-email@gmail.com
SMTP Password: your-app-password (not regular password!)
From Address: your-email@gmail.com
```

**Note:** For Gmail, create an [App Password](https://myaccount.google.com/apppasswords)

### LDAP/Active Directory

For corporate environments:

**Example Configuration:**
```
LDAP Host: ldap.company.com
LDAP Port: 389 (or 636 for SSL)
Base DN: dc=company,dc=com
User DN Template: cn={username},ou=users,dc=company,dc=com
Use SSL: Yes (recommended)
```

Test LDAP connection:
```bash
ldapsearch -x -H ldap://ldap.company.com -D "cn=testuser,ou=users,dc=company,dc=com" -W
```

---

## Troubleshooting

### Services Not Starting

Check service status:
```bash
sudo systemctl status hostapd
sudo systemctl status dnsmasq
sudo systemctl status nginx
sudo systemctl status captive-portal-api
```

View logs:
```bash
# API logs
sudo journalctl -u captive-portal-api -f

# nginx logs
sudo tail -f /var/log/nginx/error.log

# hostapd logs
sudo journalctl -u hostapd -f
```

### WiFi Network Not Appearing

1. Check if interface supports AP mode:
   ```bash
   iw list | grep "Supported interface modes" -A 8
   # Should show "AP" in the list
   ```

2. Check hostapd configuration:
   ```bash
   sudo hostapd -dd /etc/hostapd/hostapd.conf
   # Run in debug mode
   ```

3. Verify interface is not managed by NetworkManager:
   ```bash
   # Add to /etc/NetworkManager/NetworkManager.conf
   [keyfile]
   unmanaged-devices=interface-name:wlan0

   sudo systemctl restart NetworkManager
   ```

### Users Can't Access Internet

1. Check firewall rules:
   ```bash
   sudo iptables -L -v -n
   sudo iptables -t nat -L -v -n
   ```

2. Verify IP forwarding:
   ```bash
   cat /proc/sys/net/ipv4/ip_forward
   # Should show "1"
   ```

3. Check internet connection on server:
   ```bash
   ping -c 3 8.8.8.8
   ```

4. Verify user is authenticated in database:
   ```bash
   sqlite3 /opt/captive-portal/portal.db "SELECT * FROM user WHERE active=1;"
   ```

### GitHub Pages Not Loading

1. Wait 2-3 minutes after enabling (deployment takes time)
2. Check Pages settings: Repository → Settings → Pages
3. Verify URL matches configuration: `https://mb43.github.io/wifiportal`
4. Check browser console for errors (F12)
5. Try accessing directly in browser to test

### OAuth Not Working

**Google:**
- Verify redirect URI exactly matches: `https://mb43.github.io/wifiportal`
- Check if Client ID/Secret are correct
- Make sure OAuth consent screen is configured

**Facebook:**
- App must be in "Live" mode (not Development)
- Verify redirect URI matches exactly
- Check App ID/Secret are correct

### LDAP Authentication Fails

1. Test LDAP connectivity:
   ```bash
   telnet ldap.company.com 389
   ```

2. Verify DN format:
   ```bash
   # Try manual LDAP search
   ldapsearch -x -H ldap://your-server -D "your-dn" -W
   ```

3. Check API logs for LDAP errors:
   ```bash
   sudo journalctl -u captive-portal-api | grep -i ldap
   ```

---

## Maintenance

### Viewing Logs

```bash
# API logs (authentication, errors)
sudo journalctl -u captive-portal-api -f

# All system logs
sudo tail -f /var/log/syslog

# nginx access logs
sudo tail -f /var/log/nginx/access.log
```

### Restarting Services

```bash
# Restart all services
sudo systemctl restart hostapd dnsmasq nginx captive-portal-api

# Restart individual service
sudo systemctl restart captive-portal-api
```

### Updating Configuration

```bash
# Re-run setup wizard
sudo /opt/captive-portal/setup-wizard.sh

# Or edit config file directly
sudo nano /opt/captive-portal/config.json

# Then restart API
sudo systemctl restart captive-portal-api
```

### Updating Portal Code

```bash
# On your development machine
cd /path/to/wifiportal
# Make changes to index.html or other files
git add .
git commit -m "Update portal"
git push origin main

# GitHub Pages will auto-update in 2-3 minutes
# No server restart needed for frontend changes!

# For backend changes (portal-api.py):
ssh user@your-server
cd /opt/captive-portal
# Update api/portal-api.py
sudo systemctl restart captive-portal-api
```

### Database Backup

```bash
# Backup database
sudo cp /opt/captive-portal/portal.db /opt/captive-portal/portal.db.backup

# Backup configuration
sudo cp /opt/captive-portal/config.json /opt/captive-portal/config.json.backup
```

### Managing Users

Access admin panel at: `https://your-server-ip:8443`

Or use command line:

```bash
# View connected users
sqlite3 /opt/captive-portal/portal.db "SELECT username, ip_address, connected_at FROM user WHERE active=1;"

# Disconnect user by IP
curl -X POST https://localhost:8443/api/users/disconnect \
  -H "Content-Type: application/json" \
  -d '{"id": 1}'
```

### Performance Monitoring

```bash
# Check system resources
htop

# Monitor bandwidth
iftop -i wlan0

# Check connected clients
iw dev wlan0 station dump
```

---

## Architecture

### Network Flow

```
User Device
    ↓
WiFi (hostapd on wlan0)
    ↓
DHCP/DNS (dnsmasq)
    ↓
Firewall Redirect (iptables) → Port 80/443 → 8080
    ↓
nginx (reverse proxy)
    ↓
GitHub Pages (index.html) ← Frontend
    ↓
User authenticates
    ↓
POST /api/authenticate
    ↓
Flask API (portal-api.py) ← Backend
    ↓
Database (SQLite)
    ↓
iptables rule added
    ↓
User gets internet access ✓
```

### File Structure

```
/opt/captive-portal/
├── api/
│   └── portal-api.py          # Flask backend
├── config/
│   ├── nginx.conf             # nginx config
│   ├── hostapd.conf           # WiFi AP config
│   └── dnsmasq.conf           # DNS/DHCP config
├── scripts/
│   ├── firewall.sh            # iptables rules
│   └── install-dependencies.sh
├── certs/
│   ├── portal.crt             # SSL certificate
│   └── portal.key             # SSL private key
├── venv/                      # Python virtualenv
├── portal.db                  # SQLite database
└── config.json                # Portal configuration
```

### API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/authenticate` | POST | User authentication (all methods) |
| `/config` | GET | Get portal configuration |
| `/config` | POST | Update configuration |
| `/users` | GET | List connected users |
| `/users/disconnect` | POST | Disconnect a user |
| `/monitoring` | GET | System metrics (CPU, memory, disk) |
| `/logs` | GET | View system logs |
| `/health` | GET | Health check |

### Database Schema

**users** table:
- User sessions (currently connected)
- IP address, MAC address
- Authentication method
- Connection time, data usage

**auth_users** table:
- Permanent user accounts
- Hashed passwords
- Admin status

**log_entries** table:
- System events
- Authentication attempts
- Errors

---

## Production Best Practices

### Security

1. **Change default admin password immediately**
   ```bash
   # Via admin panel or database
   sqlite3 /opt/captive-portal/portal.db
   UPDATE auth_user SET password_hash='...' WHERE username='admin';
   ```

2. **Use real SSL certificates** (Let's Encrypt):
   ```bash
   sudo certbot certonly --standalone -d wifi.yourdomain.com
   # Update nginx config to use new certs
   ```

3. **Firewall hardening**:
   ```bash
   # Only allow necessary ports
   ufw allow 22/tcp    # SSH
   ufw allow 80/tcp    # HTTP
   ufw allow 443/tcp   # HTTPS
   ufw allow 8080/tcp  # Portal redirect
   ufw allow 8443/tcp  # Admin panel
   ufw enable
   ```

4. **Regular updates**:
   ```bash
   sudo apt update && sudo apt upgrade
   ```

### Monitoring

1. **Set up monitoring** (optional):
   - Prometheus + Grafana for metrics
   - ELK stack for log analysis
   - Uptime monitoring

2. **Alerts**:
   - Service failures
   - High resource usage
   - Failed authentication attempts

### Scaling

For high-traffic deployments:

1. **Use MySQL** instead of SQLite:
   ```python
   # Edit api/portal-api.py
   app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://user:pass@localhost/portal'
   ```

2. **Load balancing**:
   - Multiple backend servers
   - HAProxy or nginx load balancer

3. **Redis for session storage**:
   - Faster than database
   - Shared across multiple servers

---

## Support

- **Issues**: https://github.com/mb43/wifiportal/issues
- **Documentation**: https://github.com/mb43/wifiportal
- **Portal Demo**: https://mb43.github.io/wifiportal

---

## License

MIT License - Use freely for personal or commercial projects

---

**Enjoy your captive portal! 🎉**
