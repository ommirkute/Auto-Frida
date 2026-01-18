<div align="center">

```
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     █████╗ ██╗   ██╗████████╗ ██████╗     ███████╗██████╗ ██╗██████╗  █████╗  ║
║    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗    ██╔════╝██╔══██╗██║██╔══██╗██╔══██╗ ║
║    ███████║██║   ██║   ██║   ██║   ██║    █████╗  ██████╔╝██║██║  ██║███████║ ║
║    ██╔══██║██║   ██║   ██║   ██║   ██║    ██╔══╝  ██╔══██╗██║██║  ██║██╔══██║ ║
║    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝    ██║     ██║  ██║██║██████╔╝██║  ██║ ║
║    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝     ╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝ ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

# 🚀 Auto Frida v1.0 by Omkar Mirkute

### Complete Android Security Testing Automation for Windows

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Frida](https://img.shields.io/badge/Frida-16+-EF6C00?style=for-the-badge&logo=frida&logoColor=white)](https://frida.re/)
[![License](https://img.shields.io/badge/License-MIT-00C853?style=for-the-badge)](LICENSE)

<img src="https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white" />
<img src="https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=hackaday&logoColor=white" />
<img src="https://img.shields.io/badge/Frida_CodeShare-FF6F00?style=for-the-badge&logo=firebase&logoColor=white" />

---

**Auto Frida** is a powerful, all-in-one automation toolkit that handles everything from Frida installation to script injection. Zero manual setup required – just connect your device and start testing.

[Features](#-key-features) •
[Installation](#-installation) •
[Usage](#-quick-start) •
[Scripts](#-built-in-scripts) •
[CodeShare](#-frida-codeshare-integration) •
[Author](#%E2%80%8D-author)

</div>

---

## ⚡ Key Features

<table>
<tr>
<td width="50%">

### 🔧 Auto Installation
Automatically installs Frida tools on Windows and deploys matching Frida server to your Android device. Detects device architecture (ARM64/ARM/x86) automatically.

### 🔓 SSL Pinning Bypass
Universal SSL/TLS certificate pinning bypass for intercepting HTTPS traffic. Works with most Android applications out of the box.

### 🛡️ Root Detection Bypass
Bypass root detection mechanisms used by banking apps and security-sensitive applications including SafetyNet and RootBeer.

</td>
<td width="50%">

### 🦋 Flutter SSL Bypass
Specialized script for bypassing SSL pinning in Flutter/Dart applications using libflutter.so hooks.

### 🌐 Frida CodeShare
Run scripts directly from [Frida CodeShare](https://codeshare.frida.re/) using native `--codeshare` flag. No download required!

### 📜 Custom Scripts
Load and execute your own Frida scripts with full spawn/attach mode support.

</td>
</tr>
</table>

### 🎯 Additional Features

| Feature | Description |
|---------|-------------|
| **3-Layer Validation** | Robust Frida server management with process, port (27042), and protocol validation |
| **PID-based Attach** | Reliable attachment using process ID instead of package name |
| **Smart Lifecycle** | Idempotent server management - only starts/restarts when needed |
| **SELinux Handling** | Automatic SELinux permissive mode for rooted devices |
| **Interactive Navigation** | Go back & exit options available in all phases |

---

## 📋 Requirements

<table>
<tr>
<td width="50%">

### 💻 Windows Host
- ✅ Python 3.8 or higher
- ✅ pip package manager
- ✅ ADB (Android Debug Bridge)
- ✅ Internet connection (for downloads)

</td>
<td width="50%">

### 📱 Android Device
- ✅ USB Debugging enabled
- ✅ Rooted device (for Spawn mode)
- ℹ️ Non-rooted works with Attach mode
- ✅ ARM64 / ARM / x86 / x86_64 CPU

</td>
</tr>
</table>

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/ommirkute/Auto-Frida.git

# Navigate to directory
cd Auto-Frida

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
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1   │  Environment Validation                                        │
│            │  └── Checks Python, pip, Frida. Auto-installs if needed        │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 2   │  Device Detection                                              │
│            │  └── Finds devices, handles auth, detects architecture         │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 3   │  Device Analysis                                               │
│            │  └── Checks root access, SELinux status, attempts permissive   │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 4   │  Smart Frida Server Lifecycle                                  │
│            │  └── Downloads, pushes, starts with 3-layer validation         │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 5   │  App Enumeration                                               │
│            │  └── Lists installed apps with PID status                      │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 6   │  Target Selection                                              │
│            │  └── Filter all/running apps, select target with back option   │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 7   │  Script Selection                                              │
│            │  └── Built-in scripts, CodeShare, or custom local scripts      │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 8   │  Script Execution                                              │
│            │  └── Spawn or Attach mode with full error handling             │
└────────────┴────────────────────────────────────────────────────────────────┘
```

---

## 📜 Built-in Scripts

| Script | Description | Use Case |
|--------|-------------|----------|
| 🔓 `ssl_pinning_bypass.js` | Universal SSL/TLS certificate pinning bypass | Intercept HTTPS traffic |
| 🛡️ `root_bypass.js` | Root detection bypass for sensitive apps | Banking, payment apps |
| 🦋 `flutter_ssl_bypass.js` | Specialized bypass for Flutter/Dart apps | Flutter-based apps |
| 🔍 `anti_debug_bypass.js` | Anti-debugging and emulator detection bypass | Protected apps |

### Adding Custom Scripts

Place your custom `.js` files in the `scripts/` directory:

```
Auto-Frida/
├── auto_frida.py
├── scripts/
│   ├── ssl_pinning_bypass.js
│   ├── root_bypass.js
│   ├── flutter_ssl_bypass.js
│   ├── anti_debug_bypass.js
│   └── your_custom_script.js  ← Add here
└── logs/
```

Or select **"C. Custom script options"** during runtime to enter a path to any `.js` file.

---

## 🌐 Frida CodeShare Integration

Auto Frida supports running scripts directly from [Frida CodeShare](https://codeshare.frida.re/) using the native `--codeshare` flag!

### How to Use

1. Select **"C. Custom script options"** in Script Selection
2. Choose **"1. Frida CodeShare"**
3. Enter the script name in format: `author/script-name`

### Popular CodeShare Scripts

| Script | Description |
|--------|-------------|
| `pcipolloni/universal-android-ssl-pinning-bypass-with-frida` | Universal SSL Pinning Bypass |
| `dzonerzy/fridantiroot` | Root Detection Bypass |
| `akabe1/frida-multiple-unpinning` | Multiple SSL Unpinning |
| `masbog/frida-android-unpinning-ssl` | Android SSL Unpinning |
| `sowdust/universal-android-ssl-pinning-bypass-2` | Universal SSL Bypass v2 |

### Example

```bash
# When prompted for CodeShare script name:
> pcipolloni/universal-android-ssl-pinning-bypass-with-frida

# Auto Frida builds the command:
frida -U --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida -f com.target.app
```

---

## 🎯 Execution Modes

<table>
<tr>
<td width="50%">

### 🚀 Spawn Mode
**Recommended for rooted devices**

- Launches app fresh with Frida attached from start
- Captures all initialization code
- Automatically kills existing app instance
- **Requires rooted device**

```bash
frida -U -f com.app.package -l script.js
```

</td>
<td width="50%">

### 🔗 Attach Mode
**Works on non-rooted devices**

- Connects to already running app using PID
- Reliable PID-based targeting
- May miss initialization code
- **Works on non-rooted devices**

```bash
frida -U -p <PID> -l script.js
```

</td>
</tr>
</table>

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
3. Run Auto Frida again to re-download matching version
</details>

<details>
<summary><b>❌ "Unable to find process" error</b></summary>

The app may have crashed or closed:
1. Manually start the app on device
2. Use Attach mode instead of Spawn
3. Check if the package name is correct
</details>

---

## 👨‍💻 Author

<div align="center">

<img src="https://img.shields.io/badge/Created%20By-Omkar%20Mirkute-00C853?style=for-the-badge" />

**Security Researcher & Developer**

[![GitHub](https://img.shields.io/badge/GitHub-ommirkute-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/ommirkute)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Omkar%20Mirkute-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://in.linkedin.com/in/omkar-mirkute)

</div>

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

<div align="center">

> **⚠️ This tool is for authorized security testing only.**
> 
> Unauthorized use against systems you don't own or have explicit permission to test is **illegal**.
> The author is not responsible for any misuse of this tool.
> Always obtain proper authorization before testing any application.

</div>

---

<div align="center">

### ⭐ Found this useful? Give it a star!

Made with ❤️ by **Omkar Mirkute**

**Auto Frida v1.0** • 2026

[![Star](https://img.shields.io/github/stars/ommirkute/Auto-Frida?style=social)](https://github.com/ommirkute/Auto-Frida)

</div>
