# 🌐 WiFi Captive Portal

Professional captive portal system with multiple authentication methods and GitHub Pages integration.

## ✨ Features

- 🔐 **Multiple Authentication**: Username/Password, Google OAuth, Facebook OAuth, Email, LDAP/AD
- 🎨 **GitHub Pages Hosted**: Portal runs on GitHub Pages
- 📱 **Mobile Responsive**: Works on all devices
- ⚙️ **Admin Panel**: Real-time user management and configuration
- 🔒 **Secure**: SSL encryption, firewall integration, session management
- 🚀 **Easy Setup**: One-command installation

## 🖥️ System Requirements

### Server (Required)
- **OS**: Ubuntu 18.04+, Debian 9+, CentOS 7+, or Raspberry Pi OS
- **Hardware**: 1GB RAM, 2 CPU cores, 10GB storage
- **Network**: WiFi interface + internet connection
- **Note**: ⚠️ **Must be Linux** (hostapd, iptables, dnsmasq are Linux-only)

### Development (Your Mac)
- Git
- Text editor
- GitHub account

## 🚀 Quick Start

### On Your Server (Linux):

```bash
# One command installs everything
curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash

# Run configuration wizard
sudo /opt/captive-portal/setup-wizard.sh
```

### Setup GitHub Pages:

1. Go to: https://github.com/mb43/wifiportal/settings/pages
2. Enable Pages from `main` branch
3. Your portal URL: `https://mb43.github.io/wifiportal`

## 📖 What Gets Installed

- ✅ WiFi Access Point (hostapd)
- ✅ DNS/DHCP Server (dnsmasq)
- ✅ Web Server (nginx)
- ✅ Python API Backend
- ✅ Firewall Rules (iptables)
- ✅ Admin Panel
- ✅ Database (SQLite/MySQL)

## 🔐 Authentication Methods

Configure during setup or via admin panel:

- **Username/Password**: Built-in, demo users included
- **Google OAuth**: Requires Client ID/Secret
- **Facebook OAuth**: Requires App ID/Secret
- **Email Signup**: Requires SMTP settings
- **LDAP/AD**: For corporate networks

### 🔑 Default Credentials

The portal includes demo accounts for testing:

**Admin Access:**
- Username: `admin`
- Password: `admin123`
- Access: Admin panel at `https://your-server:8443`

**Demo User Accounts:**
- Username: `demo` / Password: `demo123`
- Username: `user` / Password: `password`

⚠️ **Important**: Change the admin password immediately after installation for production use!

## 📱 User Experience

1. User connects to WiFi → Auto-redirect to GitHub Pages
2. Choose authentication method
3. Login → Instant internet access
4. Admin monitors via web panel

## 🛠️ Admin Panel

Access at: `https://your-server:8443`

Features:
- Real-time user monitoring
- Session management
- Configuration updates
- System monitoring
- Log viewing

## 📁 Files in This Repo

```
wifiportal/
├── README.md                    # This file
├── index.html                   # Portal interface (GitHub Pages)
├── install.sh                   # Quick installer
├── setup-wizard.sh              # Configuration wizard
├── api/
│   ├── portal-api.py            # Python backend
│   ├── requirements.txt         # Dependencies
│   └── systemd/                 # System services
├── config/                      # Configuration templates
└── scripts/                     # Helper scripts
```

## 🎯 Deployment Options

### Option 1: Raspberry Pi (Recommended for Home/Small Office)
```bash
# Perfect for small deployments
# Built-in WiFi works great
ssh pi@raspberrypi
curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash
```

### Option 2: Ubuntu Server (Recommended for Production)
```bash
# Best for larger deployments
# Requires USB WiFi adapter or built-in WiFi
ssh user@server
curl -sSL https://raw.githubusercontent.com/mb43/wifiportal/main/install.sh | sudo bash
```

### Option 3: VPS + External WiFi Router
- Run backend on VPS
- Configure router to redirect to VPS
- Good for distributed locations

## ⚠️ Important Notes

- **Mac is NOT supported** as the portal server (development only)
- Linux required for: hostapd, iptables, dnsmasq
- GitHub Pages hosts the portal UI only
- Backend must run on Linux server

## 📞 Support

- Open an issue for bugs
- Star the repo if you find it useful!

## 📄 License

MIT License - Use freely for personal or commercial projects

---

**Portal URL**: https://mb43.github.io/wifiportal  
**Repository**: https://github.com/mb43/wifiportal
