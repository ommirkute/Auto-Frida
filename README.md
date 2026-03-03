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

# 🚀 Auto Frida v2.0 by Omkar Mirkute

### Complete Android Security Testing Automation

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-0078D6?style=for-the-badge)](https://github.com/ommirkute/Auto-Frida)
[![Frida](https://img.shields.io/badge/Frida-16+-EF6C00?style=for-the-badge&logo=frida&logoColor=white)](https://frida.re/)
[![License](https://img.shields.io/badge/License-MIT-00C853?style=for-the-badge)](LICENSE)
[![Version](https://img.shields.io/badge/Version-2.0-FF6F00?style=for-the-badge)](https://github.com/ommirkute/Auto-Frida)

<img src="https://img.shields.io/badge/Android-3DDC84?style=for-the-badge&logo=android&logoColor=white" />
<img src="https://img.shields.io/badge/Security-FF0000?style=for-the-badge&logo=hackaday&logoColor=white" />
<img src="https://img.shields.io/badge/Auto_Analyzer-v2-9C27B0?style=for-the-badge" />

---

**Auto Frida v2.0** is a powerful, all-in-one Android security testing automation toolkit. Connect your device and let Auto Frida handle everything — from Frida installation to intelligent protection detection and bypass script generation.

[What's New](#-whats-new-in-v20) •
[Features](#-key-features) •
[Installation](#-installation) •
[Usage](#-quick-start) •
[Auto Analyzer](#-auto-analyzer-v2) •
[Scripts](#-built-in-scripts) •
[CodeShare](#-frida-codeshare-integration) •
[Author](#author)

</div>

---

## 🆕 What's New in v2.0

v2.0 is a major upgrade over v1.0. Here's a summary of everything that's new:

### 🤖 Auto Analyzer v2 (Core Feature)
The flagship feature of v2.0. Auto Analyzer automatically detects what protections an app uses and generates a tailored bypass script — no manual analysis needed.

- **Spawn-mode detection** — hooks are installed *before* any app code runs, eliminating race conditions that caused missed detections in v1.0
- **Weighted pattern analysis** — a multi-signal confidence scoring engine classifies protections with accuracy percentages
- **Consolidated bypass generation** — each native symbol and Java method is hooked *exactly once*, preventing the double-hook crashes present in older approaches
- **Post-generation menu** — execute, verify, re-analyze, or merge with a custom script after generation

### 🛡️ Massively Expanded Bypass Coverage
v2.0 adds **11 new bypass modules** beyond what v1.0 had:

| New Module | What It Bypasses |
|---|---|
| `bypass_adb_debug.js` | ADB / developer options detection |
| `bypass_build_props.js` | `android.os.Build` field spoofing (emulator & device fingerprint) |
| `bypass_biometric.js` | `BiometricManager` / `KeyguardManager` authentication gates |
| `bypass_dynamic_dex.js` | `DexClassLoader` / `InMemoryDexClassLoader` dynamic code loading |
| `bypass_httpsurlconnection.js` | `HttpsURLConnection`, Volley, Retrofit |
| `bypass_kill.js` | `System.exit()` / `Runtime.halt()` protection kill switches |
| `bypass_network_security.js` | `NetworkSecurityConfig` / `PinSet` |
| `bypass_safetynet.js` | SafetyNet Attestation + Play Integrity API |
| `bypass_ssl_native.js` | Native `libssl.so` / `libboringssl.so` pinning |
| `bypass_trustmanager.js` | `TrustManagerImpl`, Conscrypt, `SSLContext.init` |
| `bypass_xamarin.js` | Xamarin / Mono SSL verification |

### 🏗️ Architecture Overhaul
- **Modular JS design** — all bypass scripts are now standalone `.js` files in `js_scripts/`, independently editable and version-controlled
- **`BypassPlan` dataclass** — replaces 12+ ad-hoc boolean variables with a clean, structured bypass plan built from detected findings
- **`ProtectionClassifier`** — a dedicated classification engine with 80+ regex rules across 10 protection categories
- **`DeviceManager` & `FridaServerManager`** — device and server lifecycle logic extracted into dedicated classes, making the codebase far easier to maintain and extend
- **`_native_resolver.js`** — a shared native symbol resolver loaded first, ensuring all subsequent native hooks find their targets reliably

### 🔧 Engine Improvements
- **Consolidated native hooks** — `open`, `fgets`, `fopen`, `strstr`, `strcmp`, `__system_property_get`, `access`, `stat`, `kill`, `realpath` all merged into a single hook layer with no conflicts
- **Consolidated Java hooks** — `PackageManager`, `File`, `Class.forName`, `RootBeer`, `Debug`, `Settings.Global/Secure/System` each hooked once with merged logic from all relevant modules
- **Safe `BufferedReader` filter** — fixed a recursive `readLine()` stack overflow bug from v1 by returning empty strings instead of re-calling
- **Android 16 / spawn-mode safe `SSLContext.init`** — no `registerClass`, no `Java.use()` at top level; thread guard prevents WebView/Chromium SIGSEGV during startup
- **Delayed class scans** — custom `TrustManager` and generic root method scans run at 2–3s after startup, catching lazy-loaded protections
- **Multi-device support** — automatically prompts to select when multiple USB devices are connected

### 🎯 Detection Improvements
- **50+ hook detection patterns** tracking SSL, root, emulator, anti-debug, Frida detection, dynamic code loading, biometric, and more
- **Hook synthesis** — even when no JSON events are captured, observed hook activations are converted directly into `ProtectionFinding` objects
- **Multi-signal confidence boost** — findings sharing a protection type automatically receive a +10% confidence boost
- **Configurable analysis duration** — choose from Quick (30s), Standard (45s), Deep (60s), Extended (90s), or Max (120s)

---

## ⚡ Key Features

<table>
<tr>
<td width="50%">

### 🤖 Auto Analyzer v2
Automatically detects protections and generates a comprehensive, conflict-free bypass script. Supports spawn mode, weighted classification, and built-in verification.

### 🔓 SSL Pinning Bypass
Covers OkHttp3, OkHttp2, TrustManager, Conscrypt, NetworkSecurityConfig, WebView, HttpsURLConnection, Xamarin, Flutter, and native libssl/BoringSSL.

### 🛡️ Root Detection Bypass
Bypasses RootBeer, SafetyNet, Play Integrity, file/exec/process root checks, ADB detection, and dynamic class-based root checks.

### 🦋 Flutter SSL Bypass
Dedicated detection and bypass for Flutter's `libflutter.so` BoringSSL implementation, including a runtime Flutter detector.

</td>
<td width="50%">

### 🔍 Anti-Debug & Anti-Frida
Bypasses `android.os.Debug`, `ptrace`/`TracerPid`, Frida port scanning, `/proc/self/maps` inspection, string comparison anti-Frida, and Java stack trace filtering.

### 📱 Emulator Detection Bypass
Spoofs `TelephonyManager`, `android.os.Build` fields, `__system_property_get`, `Settings.Secure android_id`, and `Settings.Global` developer flags.

### 🌐 Frida CodeShare
Run scripts directly from [Frida CodeShare](https://codeshare.frida.re/) via the native `--codeshare` flag. No download required.

### 📜 Custom & Merged Scripts
Load your own `.js` files, or use the Auto Analyzer's merge feature to combine a generated bypass with your own custom script.

</td>
</tr>
</table>

### 🎯 Additional Features

| Feature | Description |
|---------|-------------|
| **3-Layer Server Validation** | Validates Frida server by process presence, port 27042 binding, and `frida-ps` protocol handshake |
| **Smart Server Lifecycle** | Only downloads/restarts the server when actually needed |
| **Spawn-mode Detection** | Hooks installed *before* app code runs — no missed initializations |
| **Verification Mode** | After bypass generation, auto-launches the app and live-monitors which hooks trigger |
| **SELinux Handling** | Automatically sets SELinux to Permissive on rooted devices |
| **Cross-Platform** | Works on Windows, Linux, and macOS |
| **Comprehensive Logging** | Full session logs written to `logs/auto_frida.log` |

---

## 📋 Requirements

<table>
<tr>
<td width="50%">

### 💻 Host Machine
- ✅ Python 3.8 or higher
- ✅ pip package manager
- ✅ ADB (Android Debug Bridge)
- ✅ Internet connection (for first-time downloads)

</td>
<td width="50%">

### 📱 Android Device
- ✅ USB Debugging enabled
- ✅ Rooted device (recommended for full functionality)
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

> 💡 **Note:** Auto Frida will automatically install `frida` and `frida-tools` via pip if not already present.

### Manual dependency install

```bash
pip install -r requirements.txt
```

---

## ⚡ Quick Start

```bash
# 1. Connect your Android device via USB
# 2. Enable USB Debugging on your device
# 3. Run Auto Frida

python auto_frida.py

# Auto Frida handles everything:
#   ✓ Validates Python, pip, Frida — installs if needed
#   ✓ Detects device and architecture
#   ✓ Downloads and starts matching Frida server
#   ✓ Lists all installed apps
#   ✓ Detects protections (Auto Analyzer) or injects your script
```

---

## 🔄 How It Works

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHASE 1   │  Environment Validation                                        │
│            │  └── Checks Python, pip, Frida. Auto-installs if needed        │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 2   │  ADB & Device Detection                                        │
│            │  └── Finds devices, handles auth, multi-device selection       │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 3   │  Device Analysis                                               │
│            │  └── Detects architecture, checks root, handles SELinux        │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 4   │  Smart Frida Server Lifecycle                                  │
│            │  └── 3-layer validation → download → push → start              │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 5   │  App Enumeration                                               │
│            │  └── Lists all installed apps with running PID status          │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 6   │  Target Selection                                              │
│            │  └── Filter all/running, search by name or package             │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 7   │  Script Selection                                              │
│            │  └── Auto Analyzer, built-in scripts, CodeShare, or custom     │
├────────────┼────────────────────────────────────────────────────────────────┤
│  PHASE 8   │  Execution                                                     │
│            │  └── Spawn or Attach mode with full error handling             │
└────────────┴────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Auto Analyzer v2

Auto Analyzer is the centerpiece of v2.0. It fully automates the process of finding what protections an app uses and generating a bypass.

### How It Works

```
Phase 0  ─  Anti-Frida shield included in all generated bypasses
Phase 1  ─  App is spawned via Frida (hooks in place before any app code runs)
            Detection script monitors for 30–120 seconds
Phase 2  ─  Weighted pattern analysis classifies captured events
            50+ hook patterns × confidence scoring → ProtectionFinding list
Phase 3  ─  Consolidated bypass script generated
            Each symbol/method hooked exactly once — no crashes
```

### Usage

When prompted for a script, enter `AA`:

```
> AA
```

You'll be asked to choose a monitoring duration:

| Option | Duration | Best For |
|--------|----------|----------|
| Quick | 30s | Fast apps, simple protections |
| Standard | 45s | Most apps |
| Deep | 60s | Apps with lazy-loaded checks |
| Extended | 90s | Complex multi-layer protections |
| Max | 120s | Heavily obfuscated apps |

Interact with the app during monitoring to trigger as many protection checks as possible (login, navigate, make network requests).

### Detection Coverage

Auto Analyzer classifies protections across 10 categories:

| Category | Examples Detected |
|---|---|
| SSL Pinning | OkHttp3, OkHttp2, TrustManager, Conscrypt, Flutter, NetworkSecurityConfig, WebView, HttpsURLConnection, Xamarin, native libssl |
| Root Detection | RootBeer, SafetyNet, Play Integrity, file/exec/process checks, custom root classes |
| Frida Detection | Port scanning (27042), `/proc/self/maps` inspection, native string comparison |
| Anti-Debug | `android.os.Debug`, `ptrace`/`TracerPid` |
| Emulator Detection | `TelephonyManager`, `android.os.Build` fields |
| Tamper Detection | Package signature checks, `MessageDigest` hash verification |
| Dynamic Code Loading | `DexClassLoader`, `InMemoryDexClassLoader` |
| Biometric Gate | `BiometricManager`, `KeyguardManager` |
| Protection Kill Switch | `System.exit()`, `Runtime.halt()` |
| ADB/Dev Options | `Settings.Global` ADB flags, developer settings |

### Generated Script Structure

Generated scripts are saved to `generated_bypasses/` and follow this layered architecture:

```
Layer -1  Native symbol resolver (_native_resolver.js)
Layer 0a  Shared constants (root paths, packages, keywords)
Layer 0b  Consolidated native hooks (open, fgets, fopen, strstr, __system_property_get, ...)
Layer 0c  Non-conflicting native modules (Flutter SSL, native libssl)
Layer 0d  Anti-Frida Java hooks (500ms timeout)
Layer 1   Main Java.perform block (1000ms timeout)
          ├─ Build field spoofing
          ├─ Consolidated SSL bypass (TrustManager + HttpsURLConnection)
          ├─ OkHttp3, NetworkSecurityConfig, WebView, Xamarin
          ├─ Consolidated root/ADB/debug/PM/signature bypass
          └─ SafetyNet, Emulator, Biometric, Kill-switch, Dynamic class hooks
Layer 2   Delayed class scans (2–3s)
          ├─ Custom TrustManager scan
          └─ Generic root method scan
```

### Post-Generation Options

After script generation you can:

1. **Execute & verify** — launches the app and live-monitors which bypass hooks trigger
2. **Execute without verification** — direct Frida session
3. **Re-run analysis** — choose a different duration
4. **Merge with custom script** — combine with your own `.js` file
5. **Save and return** — keep the script for later use

---

## 📁 Project Structure

```
Auto-Frida/
├── auto_frida.py           # Main application
├── requirements.txt        # Python dependencies
├── README.md
│
├── js_scripts/             # All Frida bypass/detection scripts
│   ├── _native_resolver.js          # Shared native symbol resolver
│   ├── detection_script.js          # Auto Analyzer detection hooks
│   ├── detect_flutter.js            # Flutter runtime detector
│   ├── bypass_anti_frida.js         # Frida detection bypass
│   ├── bypass_flutter_ssl.js        # Flutter libflutter.so SSL
│   ├── bypass_okhttp3.js            # OkHttp3 CertificatePinner
│   ├── bypass_trustmanager.js       # TrustManagerImpl / Conscrypt
│   ├── bypass_network_security.js   # NetworkSecurityConfig
│   ├── bypass_webview.js            # WebViewClient SSL errors
│   ├── bypass_httpsurlconnection.js # HttpsURLConnection / Volley
│   ├── bypass_xamarin.js            # Xamarin / Mono
│   ├── bypass_ssl_native.js         # Native libssl / BoringSSL
│   ├── bypass_rootbeer.js           # RootBeer library
│   ├── bypass_generic_root.js       # File/exec/process root checks
│   ├── bypass_safetynet.js          # SafetyNet + Play Integrity
│   ├── bypass_anti_debug.js         # Debug / ptrace detection
│   ├── bypass_emulator.js           # TelephonyManager emulator
│   ├── bypass_build_props.js        # android.os.Build spoofing
│   ├── bypass_adb_debug.js          # ADB / developer options
│   ├── bypass_signature.js          # Signature / tamper checks
│   ├── bypass_dynamic_dex.js        # DexClassLoader
│   ├── bypass_biometric.js          # BiometricManager / Keyguard
│   └── bypass_kill.js               # System.exit / Runtime.halt
│
├── scripts/                # Built-in general-purpose scripts
│   ├── ssl_pinning_bypass.js
│   ├── root_bypass.js
│   ├── flutter_ssl_bypass.js
│   ├── anti_debug_bypass.js
│   └── scripts.json
│
├── generated_bypasses/     # Auto Analyzer output (created at runtime)
└── logs/
    └── auto_frida.log
```

---

## 📜 Built-in Scripts

| Script | Description | Use Case |
|--------|-------------|----------|
| 🔓 `ssl_pinning_bypass.js` | Universal SSL/TLS certificate pinning bypass | Intercept HTTPS traffic |
| 🛡️ `root_bypass.js` | Root detection bypass | Banking, payment apps |
| 🦋 `flutter_ssl_bypass.js` | Specialized bypass for Flutter/Dart apps | Flutter-based apps |
| 🔍 `anti_debug_bypass.js` | Anti-debugging and emulator detection bypass | Protected apps |

### Adding Custom Scripts

Place your `.js` files in the `scripts/` directory, or select **"C. Custom"** at runtime to enter any path.

---

## 🔐 Recommended Proxy: Reqable

For the best SSL pinning bypass success rate, use **[Reqable](https://reqable.com/)** as your proxy with its root certificate installed on your device. Reqable is a modern HTTP debugging proxy purpose-built for mobile testing, and it works significantly better than alternatives like Burp Suite or Charles when combined with Auto Frida's bypass scripts.

### Why Reqable?

| Feature | Benefit |
|---|---|
| Built-in root certificate manager | One-tap cert install directly to the Android trust store |
| Modern TLS support | Handles TLS 1.3, HTTP/2, and QUIC — no missed traffic |
| Android-aware | Designed with mobile app testing in mind |
| Real-time traffic view | Instant visibility as bypass hooks fire |

### Setup Guide

**Step 1 — Install Reqable**

Download Reqable from [reqable.com](https://reqable.com/) and install it on your computer.

**Step 2 — Install the Reqable Root Certificate on your Android device**

1. Open Reqable on your computer and go to **Settings → SSL → Export Root Certificate**
2. Push the certificate to your device:
   ```bash
   adb push reqable-ca.crt /sdcard/Download/reqable-ca.crt
   ```
3. On the device go to **Settings → Security → Install from storage** and install the certificate
4. For rooted devices, install it as a **system certificate** for maximum compatibility:
   ```bash
   # Convert to system cert format
   openssl x509 -inform PEM -subject_hash_old -in reqable-ca.crt | head -1
   # Returns a hash, e.g. "a1b2c3d4" — rename file accordingly
   adb push a1b2c3d4.0 /system/etc/security/cacerts/
   adb shell chmod 644 /system/etc/security/cacerts/a1b2c3d4.0
   ```

**Step 3 — Configure your device Wi-Fi proxy**

Point your Android device's Wi-Fi proxy to your computer's IP on Reqable's port (default `11888`):

1. On Android go to **Settings → Wi-Fi → Long press your network → Modify network**
2. Set **Proxy → Manual**, enter your computer's local IP and port `11888`

**Step 4 — Run Auto Frida**

Now run Auto Frida and use the **Auto Analyzer** or any SSL bypass script. With Reqable's cert installed and Auto Frida's bypass active, you get two layers of SSL interception working together — dramatically improving success rates on apps with heavy pinning.

```bash
python auto_frida.py
# Select your app → AA (Auto Analyzer) → interact with the app
# Watch decrypted traffic appear in Reqable in real time
```

> 💡 **Tip:** Installing the certificate as a **system certificate** (step 2, rooted path) is strongly recommended. Many apps explicitly check that the intercepting certificate is in the system store rather than the user store, and will reject user-installed certs even after pinning is bypassed.

---

## 🌐 Frida CodeShare Integration

Auto Frida supports running scripts directly from [Frida CodeShare](https://codeshare.frida.re/) using the native `--codeshare` flag.

### How to Use

1. Select **"C. Custom"** in Script Selection
2. Choose **"1. CodeShare"**
3. Enter the script in format: `author/script-name`

### Popular CodeShare Scripts

| Script | Description |
|--------|-------------|
| `pcipolloni/universal-android-ssl-pinning-bypass-with-frida` | Universal SSL Pinning Bypass |
| `dzonerzy/fridantiroot` | Root Detection Bypass |
| `akabe1/frida-multiple-unpinning` | Multiple SSL Unpinning |
| `masbog/frida-android-unpinning-ssl` | Android SSL Unpinning |
| `sowdust/universal-android-ssl-pinning-bypass-2` | Universal SSL Bypass v2 |

---

## 🎯 Execution Modes

<table>
<tr>
<td width="50%">

### 🚀 Spawn Mode
**Recommended for rooted devices**

- Launches app fresh with Frida attached from start
- Hooks installed before any app code runs
- Captures all initialization checks
- Required for Auto Analyzer

```bash
frida -U -f com.app.package -l script.js
```

</td>
<td width="50%">

### 🔗 Attach Mode
**Works on non-rooted devices**

- Attaches to already-running app by PID
- May miss early initialization code
- Useful for apps that detect spawn mode

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
2. Disconnect and reconnect the USB cable
3. Run `adb kill-server && adb devices`
</details>

<details>
<summary><b>❌ "need Gadget to attach" error</b></summary>

Trying to spawn on a non-rooted device:
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
Auto Frida handles this automatically on rooted devices. Alternatively, use Magisk's SELinux permissive mode setting.
</details>

<details>
<summary><b>❌ Version mismatch between Frida client and server</b></summary>

1. Delete local `frida-server-*` files from the project directory
2. Remove server from device: `adb shell rm /data/local/tmp/fridaserver`
3. Run Auto Frida again to download the matching version automatically
</details>

<details>
<summary><b>❌ Auto Analyzer detected 0 protections</b></summary>

Try the following:
- Choose a longer duration (Deep 60s or Extended 90s) and interact with more app features
- The app may have anti-Frida that prevented hooks — retry, the Anti-Frida shield is always included
- Use **"2. Generate generic bypass"** for a broad-spectrum script when detection fails
- Some apps use native-only protections; ensure you navigate through login and main screens during monitoring
</details>

<details>
<summary><b>❌ Missing JS files error on startup</b></summary>

The `js_scripts/` folder must be in the same directory as `auto_frida.py`. If files are missing, re-clone the repository:
```bash
git clone https://github.com/ommirkute/Auto-Frida.git
```
</details>

---

<a name="author"></a>
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
> Unauthorized use against applications or systems you do not own or have explicit written permission to test is **illegal**.
> The author is not responsible for any misuse of this tool.
> Always obtain proper authorization before testing any application.

</div>

---

<div align="center">

### ⭐ Found this useful? Give it a star!

Made with ❤️ by **Omkar Mirkute**

**Auto Frida v2.0** • 2026

[![Star](https://img.shields.io/github/stars/ommirkute/Auto-Frida?style=social)](https://github.com/ommirkute/Auto-Frida)

</div>
