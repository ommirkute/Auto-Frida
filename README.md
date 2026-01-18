<div align="center">

# 🚀 Auto Frida

### Complete Android Security Testing Automation for Windows

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078d7.svg)](https://www.microsoft.com/windows)
[![Frida](https://img.shields.io/badge/Frida-16+-orange.svg)](https://frida.re/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

<img src="https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white" />
<img src="https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=hackaday&logoColor=white" />

---

**Auto Frida** is a powerful, all-in-one automation toolkit that handles everything from Frida installation to script injection. Zero manual setup required – just connect your device and start testing.

</div>

---

## ⚡ Key Features

| Feature | Description |
|---------|-------------|
| 🔧 **Auto Installation** | Automatically installs Frida tools on Windows and deploys matching Frida server to Android device |
| 🔓 **SSL Pinning Bypass** | Universal SSL/TLS certificate pinning bypass for intercepting HTTPS traffic |
| 🛡️ **Root Detection Bypass** | Bypass root detection in banking and security-sensitive applications |
| 🦋 **Flutter SSL Bypass** | Specialized script for bypassing SSL pinning in Flutter/Dart applications |
| 📜 **Custom Scripts** | Load and execute your own Frida scripts with full spawn/attach support |
| ✅ **3-Layer Validation** | Robust Frida server management with process, port, and protocol validation |
| 🎯 **PID-based Attach** | Reliable attachment using process ID instead of package name |
| 🔄 **Smart Lifecycle** | Idempotent server management - only starts/restarts when needed |

---

## 📋 Requirements

### Windows Host
- ✅ Python 3.8 or higher
- ✅ pip package manager
- ✅ ADB (Android Debug Bridge)
- ✅ Internet connection (for downloads)

### Android Device
- ✅ USB Debugging enabled
- ✅ Rooted device (for Spawn mode)
- ℹ️ Non-rooted works with Attach mode
- ✅ ARM64/ARM/x86/x86_64 CPU

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/auto-frida.git
cd auto-frida

# Run Auto Frida
python auto_frida.py
```

> 💡 **Note:** Auto Frida will automatically install `frida` and `frida-tools` via pip if not already installed.

---

## ⚡ Quick Start

```bash
# 1. Connect your Android device via USB
# 2. Enable USB Debugging on your device
# 3. Run Auto Frida

python auto_frida.py

# That's it! Auto Frida handles everything:
#   ✓ Installs Frida on Windows
#   ✓ Detects device architecture
#   ✓ Downloads matching Frida server
#   ✓ Pushes and starts server on device
#   ✓ Lists all installed apps
#   ✓ Injects your chosen script
```

---

## 🔄 How It Works

```
┌─────────────────────────────────────────────────────────────┐
│  1️⃣  Environment Validation                                 │
│      └── Checks Python, pip, Frida. Auto-installs if needed │
├─────────────────────────────────────────────────────────────┤
│  2️⃣  Device Detection                                       │
│      └── Finds devices, handles auth, detects architecture  │
├─────────────────────────────────────────────────────────────┤
│  3️⃣  Root & SELinux Analysis                                │
│      └── Checks root access, attempts permissive mode       │
├─────────────────────────────────────────────────────────────┤
│  4️⃣  Frida Server Deployment                                │
│      └── Downloads, pushes, starts with 3-layer validation  │
├─────────────────────────────────────────────────────────────┤
│  5️⃣  App Enumeration                                        │
│      └── Lists installed apps with PID status               │
├─────────────────────────────────────────────────────────────┤
│  6️⃣  Script Injection                                       │
│      └── Built-in bypasses or custom scripts                │
└─────────────────────────────────────────────────────────────┘
```

---

## 📜 Built-in Scripts

| Script | Description | Use Case |
|--------|-------------|----------|
| `ssl_pinning_bypass.js` | Universal SSL/TLS certificate pinning bypass | Intercept HTTPS traffic |
| `root_bypass.js` | Root detection bypass for sensitive apps | Banking, payment apps |
| `flutter_ssl_bypass.js` | Specialized bypass for Flutter/Dart apps | Flutter-based apps |
| `anti_debug_bypass.js` | Anti-debugging and emulator detection bypass | Protected apps |

### Adding Custom Scripts

Place your custom `.js` files in the `scripts/` directory:

```
auto-frida/
├── auto_frida.py
├── scripts/
│   ├── ssl_pinning_bypass.js
│   ├── root_bypass.js
│   ├── flutter_ssl_bypass.js
│   └── your_custom_script.js  ← Add here
└── logs/
```

---

## 🎯 Execution Modes

### 🚀 Spawn Mode (Recommended)
- Launches app fresh with Frida attached from start
- Captures all initialization code
- **Requires rooted device**

### 🔗 Attach Mode (PID-based)
- Connects to already running app using PID
- Works on non-rooted devices
- May miss initialization code

---

## 🔧 Troubleshooting

<details>
<summary><b>❌ "Device unauthorized" error</b></summary>

Accept the RSA key fingerprint prompt on your Android device. If no prompt appears:
1. Revoke USB debugging authorizations in Developer Options
2. Disconnect and reconnect USB cable
3. Run `adb kill-server && adb devices`
</details>

<details>
<summary><b>❌ "need Gadget to attach" error</b></summary>

This occurs when trying to Spawn on a non-rooted device:
- Use **Attach mode** instead of Spawn
- Root your device with Magisk
- Ensure Frida server runs as root: `su -c /data/local/tmp/fridaserver -D`
</details>

<details>
<summary><b>❌ Frida server crashes or doesn't respond</b></summary>

SELinux may be blocking Frida:
```bash
adb shell su -c setenforce 0
```
Or use Magisk's SELinux permissive mode setting.
</details>

<details>
<summary><b>❌ Version mismatch between Frida client and server</b></summary>

1. Delete local `frida-server-*` files
2. Remove server from device: `adb shell rm /data/local/tmp/fridaserver`
3. Run Auto Frida again to re-download
</details>

---

## 👨‍💻 Author

**Omkar Mirkute**  
Security Researcher & Developer

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ommirkute)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://in.linkedin.com/in/omkar-mirkute)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

> **This tool is for authorized security testing only.** Unauthorized use against systems you don't own or have permission to test is illegal. The author is not responsible for any misuse of this tool.

---

<div align="center">

### ⭐ Found this useful? Give it a star!

Made with ❤️ by Omkar Mirkute

**Auto Frida v1.0** • 2026

</div>