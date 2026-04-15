#!/usr/bin/env python3
"""
__title__     = "Auto Frida"
__version__   = "2.0"
__author__    = "Omkar Mirkute"
__license__   = "MIT"
__copyright__ = "Copyright 2026 Omkar Mirkute"
"""

import subprocess
import sys
import os
import re
import json
import time
import lzma
import shutil
import logging
import tempfile
import threading
import queue
import uuid
from pathlib import Path
from typing import Optional, List, Tuple, Dict, Set, NoReturn
from dataclasses import dataclass, field
from datetime import datetime
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

__version__ = "2.0"
__author__ = "Omkar Mirkute"

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "auto_frida.log", encoding="utf-8"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Windows console UTF-8 support
# ---------------------------------------------------------------------------
if sys.platform == "win32":
    os.system("")
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Terminal colours
# ---------------------------------------------------------------------------
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    PURPLE = "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    END    = "\033[0m"


# ---------------------------------------------------------------------------
# Data-classes
# ---------------------------------------------------------------------------
@dataclass
class DeviceInfo:
    serial: str
    state: str
    model: str = ""
    architecture: str = ""
    is_rooted: bool = False
    selinux_enforcing: bool = True


@dataclass
class AppInfo:
    pid: Optional[int]
    name: str
    identifier: str


@dataclass
class FridaServerStatus:
    process_running: bool = False
    process_pid: Optional[int] = None
    port_bound: bool = False
    protocol_ok: bool = False
    error_message: str = ""

    @property
    def is_fully_operational(self) -> bool:
        return self.process_running and self.port_bound and self.protocol_ok

    @property
    def needs_restart(self) -> bool:
        return self.process_running and (not self.port_bound or not self.protocol_ok)


@dataclass
class DetectionEvent:
    timestamp: float
    event_type: str
    method_name: str
    class_name: str
    stack_trace: List[str]
    thread_id: int
    extra_data: Dict = field(default_factory=dict)


@dataclass
class ProtectionFinding:
    protection_type: str
    implementation: str
    target_class: str
    target_method: str
    confidence: int
    evidence: List[str]
    bypass_strategy: str

    def __hash__(self):
        return hash((self.protection_type, self.implementation, self.bypass_strategy))

    def __eq__(self, other):
        if not isinstance(other, ProtectionFinding):
            return False
        return (
            self.protection_type == other.protection_type
            and self.implementation == other.implementation
            and self.bypass_strategy == other.bypass_strategy
        )


# Sentinel to indicate the Auto Analyzer flow was requested
class AutoAnalyzerSentinel:
    pass


# ---------------------------------------------------------------------------
# Bypass plan dataclass (replaces 12 has_* boolean variables)
# ---------------------------------------------------------------------------
@dataclass
class BypassPlan:
    # --- Anti-detection shields ---
    anti_frida: bool = False          # Frida port/maps/string detection
    # --- SSL / TLS ---
    flutter: bool = False             # Flutter libflutter.so BoringSSL
    okhttp3: bool = False             # OkHttp3 CertificatePinner
    okhttp2: bool = False             # OkHttp2 (com.squareup.okhttp)
    trustmanager: bool = False        # TrustManagerImpl / Conscrypt / SSLContext
    network_security: bool = False    # NetworkSecurityConfig / PinSet
    webview: bool = False             # WebViewClient.onReceivedSslError
    https_url_connection: bool = False  # HttpsURLConnection / Volley / Retrofit
    xamarin: bool = False             # Xamarin / Mono apps
    ssl_native: bool = False          # Native libssl.so / libboringssl.so
    # --- Root / integrity ---
    rootbeer: bool = False            # RootBeer library
    generic_root: bool = False        # File/exec/process/property root checks
    safetynet: bool = False           # SafetyNet + Play Integrity API
    # --- Emulator / device ---
    emulator: bool = False            # TelephonyManager emulator checks
    build_props: bool = False         # android.os.Build field spoofing
    # --- Anti-debug ---
    anti_debug: bool = False          # android.os.Debug + ptrace + TracerPid
    # --- Tamper / signature ---
    signature: bool = False           # PackageManager signature + MessageDigest
    # --- Advanced (v2 new) ---
    dynamic_code_load: bool = False   # DexClassLoader / InMemoryDexClassLoader
    biometric_gate: bool = False      # BiometricManager / KeyguardManager gate bypass
    protection_kill: bool = False     # System.exit / Runtime.halt interception
    unity: bool = False               # Unity apps
    adb_debug: bool = False            # ADB / developer options detection
    # --- Dynamic ---
    dynamic_classes: List[str] = field(default_factory=list)

    @classmethod
    def from_findings(cls, findings: List[ProtectionFinding], detected_hooks: Set[str]) -> "BypassPlan":
        strategies = {f.bypass_strategy for f in findings}
        prot_types = {f.protection_type for f in findings}

        def _s(strategy: str) -> bool:
            return strategy in strategies

        def _h(*hooks: str) -> bool:
            return any(h in detected_hooks for h in hooks)

        any_ssl = (
            _s("flutter_ssl") or _s("okhttp3_v4") or _s("okhttp2_bypass")
            or _s("custom_trustmanager") or _s("webview") or _s("network_security")
            or _s("https_url_bypass") or _s("xamarin_bypass") or _s("ssl_native_bypass")
            or _h("flutter", "okhttp3", "okhttp2", "trustmanager", "sslcontext", "conscrypt",
                  "network_security", "webview", "httpsurlconn", "native_ssl")
            or "ssl_pinning" in prot_types
        )
        any_root = (
            _s("rootbeer_specific") or _s("generic_root") or _s("safetynet_bypass")
            or "root_detection" in prot_types
        )
        any_emulator = (
            "emulator_detection" in prot_types
            or _h("telephony", "build_props", "emulator")
            or _s("emulator_bypass") or _s("build_props_bypass")
        )
        any_frida = (
            _s("anti_frida") or _h("anti_frida") or "frida_detection" in prot_types
        )

        def _is_hookable_class(cls: str) -> bool:
            """Return False for class names that Java.use() cannot handle."""
            if not cls or cls in ("unknown", "native"):
                return False
            # Array descriptors: [Lsome.Class; or [[B etc — not Java.use()-able
            if cls.startswith("["):
                return False
            # Primitive type names
            if cls in ("int", "long", "boolean", "byte", "char", "short", "float", "double", "void"):
                return False
            # Must look like a valid Java class name (contains at least one letter)
            if not any(c.isalpha() for c in cls):
                return False
            return True

        dyn_classes = [
            f.target_class for f in findings
            if f.bypass_strategy == "dynamic_hook" and _is_hookable_class(f.target_class)
        ]

        return cls(
            anti_frida=any_frida,
            flutter=_s("flutter_ssl") or _h("flutter"),
            okhttp3=_s("okhttp3_v4") or _h("okhttp3"),
            okhttp2=_s("okhttp2_bypass") or _h("okhttp2"),
            trustmanager=_s("custom_trustmanager") or any_ssl or _h("trustmanager", "sslcontext", "conscrypt"),
            network_security=_s("network_security") or any_ssl or _h("network_security"),
            webview=_s("webview") or _h("webview"),
            https_url_connection=any_ssl or _s("https_url_bypass") or _h("httpsurlconn"),
            xamarin=_s("xamarin_bypass") or _h("xamarin") or "xamarin_ssl" in prot_types,
            ssl_native=_s("ssl_native_bypass") or "native_ssl" in prot_types or _h("native_ssl"),
            rootbeer=_s("rootbeer_specific") or _h("rootbeer"),
            generic_root=True,  # always include — safe on all apps, essential when rooted
            adb_debug=True,     # always include — ADB/dev options bypass always needed
            safetynet=_s("safetynet_bypass") or _h("safetynet", "play_integrity"),
            emulator=any_emulator,
            build_props=any_emulator or any_root,
            anti_debug=_s("anti_debug_bypass") or _h("anti_debug"),
            signature=_s("signature_bypass") or _h("signature", "message_digest", "installer"),
            dynamic_code_load="dynamic_code_load" in prot_types or _h("dexclassloader"),
            biometric_gate="biometric_gate" in prot_types or _h("biometric", "keyguard"),
            protection_kill="protection_triggered" in prot_types or _h("system_exit"),
            unity=_h("unity") or "unity_ssl" in prot_types,
            dynamic_classes=dyn_classes,
        )


# ---------------------------------------------------------------------------
# Protection classifier (pure logic, no I/O)
# ---------------------------------------------------------------------------
class ProtectionClassifier:

    CLASSIFICATION_RULES: Dict = {
        "ssl_pinning": {
            "okhttp3": {
                "class_patterns": [
                    r"okhttp3\.CertificatePinner",
                    r"okhttp3\.internal\.tls",
                    r"okhttp3\.OkHttpClient\$Builder.*certificatePinner",
                    r"com\.squareup\.okhttp.*Certificate",
                ],
                "method_patterns": [r"check", r"certificatePinner", r"pin"],
                "base_confidence": 95,
            },
            "trustmanager": {
                "class_patterns": [
                    r"com\.android\.org\.conscrypt\.TrustManagerImpl",
                    r"javax\.net\.ssl\.X509TrustManager",
                    r"javax\.net\.ssl\.SSLContext",
                    r"org\.conscrypt",
                ],
                "method_patterns": [r"verifyChain", r"checkServerTrusted", r"init"],
                "base_confidence": 90,
            },
            "flutter": {
                "class_patterns": [r"libflutter\.so"],
                "method_patterns": [r"ssl_verify", r"verify_cert"],
                "native_module": "libflutter.so",
                "base_confidence": 90,
            },
            "react_native": {
                "class_patterns": [r"com\.facebook\.react"],
                "native_module": "libhermes.so",
                "method_patterns": [],
                "base_confidence": 75,
            },
            "conscrypt": {
                "class_patterns": [
                    r"org\.conscrypt\.ConscryptFileDescriptorSocket",
                    r"org\.conscrypt\.Platform",
                ],
                "method_patterns": [r"verifyCertificateChain", r"checkServerTrusted"],
                "base_confidence": 88,
            },
            "network_security": {
                "class_patterns": [
                    r"android\.security\.net\.config\.NetworkSecurityConfig",
                    r"android\.security\.net\.config\.PinSet",
                ],
                "method_patterns": [r"isCleartextTrafficPermitted", r"getPins"],
                "base_confidence": 85,
            },
            "webview": {
                "class_patterns": [r"android\.webkit\.WebViewClient"],
                "method_patterns": [r"onReceivedSslError"],
                "base_confidence": 85,
            },
            "custom_pinning": {
                "class_patterns": [
                    r".*[Pp]inn(ing|er).*",
                    r".*[Cc]ert.*[Vv]erif.*",
                    r".*[Ss]sl.*[Pp]in.*",
                ],
                "method_patterns": [r"verify", r"check", r"validate", r"pin"],
                "base_confidence": 60,
            },
        },
        "root_detection": {
            "rootbeer": {
                "class_patterns": [r"com\.scottyab\.rootbeer"],
                "method_patterns": [r"isRooted"],
                "base_confidence": 98,
            },
            "safetynet": {
                "class_patterns": [
                    r"com\.google\.android\.gms\.safetynet",
                    r"com\.google\.android\.play\.core\.integrity",
                ],
                "method_patterns": [r"attest", r"requestIntegrityToken"],
                "base_confidence": 95,
            },
            "file_check": {
                "class_patterns": [r"java\.io\.File"],
                "method_patterns": [r"exists"],
                "event_type_match": "root_detection",
                "base_confidence": 70,
            },
            "command_exec": {
                "class_patterns": [r"java\.lang\.Runtime", r"java\.lang\.ProcessBuilder"],
                "method_patterns": [r"exec", r"start"],
                "event_type_match": "root_detection",
                "base_confidence": 75,
            },
            "package_check": {
                "class_patterns": [r"android\.app\.ApplicationPackageManager"],
                "method_patterns": [r"getPackageInfo"],
                "event_type_match": "root_detection",
                "base_confidence": 72,
            },
            "custom_root": {
                "class_patterns": [
                    r".*[Rr]oot.*[Dd]etect.*",
                    r".*[Rr]oot.*[Cc]heck.*",
                    r".*[Dd]evice.*[Ii]ntegrity.*",
                ],
                "method_patterns": [r"isRoot", r"check", r"detect"],
                "base_confidence": 65,
            },
        },
        "tamper_detection": {
            "signature_check": {
                "class_patterns": [r"android\.app.*PackageManager"],
                "method_patterns": [r"getPackageInfo"],
                "event_type_match": "signature_check",
                "base_confidence": 80,
            },
            "hash_verification": {
                "class_patterns": [r"java\.security\.MessageDigest"],
                "method_patterns": [r"digest"],
                "event_type_match": "hash_check",
                "base_confidence": 70,
            },
            "custom_integrity": {
                "class_patterns": [
                    r".*[Ii]ntegrity.*",
                    r".*[Tt]amper.*",
                    r".*[Ss]ignature.*[Vv]erif.*",
                ],
                "method_patterns": [r"verify", r"check", r"validate"],
                "base_confidence": 60,
            },
        },
        "debugger_detection": {
            "android_debug": {
                "class_patterns": [r"android\.os\.Debug"],
                "method_patterns": [r"isDebuggerConnected", r"waitingForDebugger"],
                "base_confidence": 90,
            },
            "tracer_pid": {
                "class_patterns": [r"native"],
                "method_patterns": [r"TracerPid"],
                "event_type_match": "debugger_detection",
                "base_confidence": 85,
            },
        },
        "emulator_detection": {
            "build_check": {
                "class_patterns": [r"android\.os\.Build"],
                "event_type_match": "emulator_detection",
                "method_patterns": [],
                "base_confidence": 70,
            },
            "telephony_check": {
                "class_patterns": [r"android\.telephony\.TelephonyManager"],
                "method_patterns": [r"getDeviceId", r"getSimOperatorName", r"getNetworkOperatorName"],
                "event_type_match": "emulator_detection",
                "base_confidence": 75,
            },
        },
        "frida_detection": {
            "port_scan": {
                "class_patterns": [r"java\.net\.Socket", r"java\.net\.InetSocketAddress"],
                "method_patterns": [r"connect"],
                "event_type_match": "frida_detection",
                "base_confidence": 90,
            },
            "maps_check": {
                "class_patterns": [r"native"],
                "method_patterns": [r"open", r"fgets"],
                "event_type_match": "frida_detection",
                "base_confidence": 88,
            },
            "native_hook_detect": {
                "class_patterns": [r"native"],
                "method_patterns": [r"strstr", r"strcmp"],
                "event_type_match": "frida_detection",
                "base_confidence": 85,
            },
        },
        # --- Universal / framework-specific rules ---
        "xamarin_ssl": {
            "xamarin_tls": {
                "class_patterns": [r"mono\.android\.ssl", r"xamarin\.android\.net",
                                   r"libmono\.so", r"libmonosgen", r"libxamarin"],
                "method_patterns": [r"verifyServerCertificate", r"checkServerTrusted"],
                "event_type_match": "xamarin_ssl",
                "base_confidence": 88,
            },
        },
        "unity_ssl": {
            "unity_tls": {
                "class_patterns": [r"libunity\.so"],
                "method_patterns": [],
                "event_type_match": "unity_ssl",
                "base_confidence": 80,
            },
        },
        "react_native": {
            "hermes_jsc": {
                "class_patterns": [r"libhermes\.so", r"libjsc\.so"],
                "method_patterns": [],
                "event_type_match": "react_native",
                "base_confidence": 78,
            },
        },
        "dynamic_hook": {
            "custom_obfuscated": {
                "class_patterns": [r".*"],  # catches any class
                "method_patterns": [r"check", r"detect", r"verify", r"isRoot", r"isEmul",
                                    r"isDebug", r"pin", r"attest", r"sign", r"cert", r"trust"],
                "event_type_match": "dynamic_hook",
                "base_confidence": 65,
            },
        },
        "native_ssl": {
            "openssl_boring": {
                "class_patterns": [r"native_ssl"],
                "method_patterns": [r"SSL_CTX_set_verify", r"SSL_get_verify_result",
                                    r"X509_verify_cert", r"SSL_CTX_set_cert_verify_callback"],
                "event_type_match": "ssl_pinning",
                "base_confidence": 92,
            },
        },
        "lazy_class_found": {
            "lazy_protection": {
                "class_patterns": [r".*"],
                "method_patterns": [],
                "event_type_match": "lazy_class_found",
                "base_confidence": 55,
            },
        },
        "native_module": {
            "security_library": {
                "class_patterns": [r"native"],
                "method_patterns": [r"libssl", r"libflutter", r"libhermes",
                                    r"libsgmain", r"libDexHelper", r"libjiagu"],
                "event_type_match": "native_module",
                "base_confidence": 75,
            },
        },
    }

    HOOK_MAPPING: Dict[str, str] = {
        "okhttp3": "okhttp3",
        "trustmanager": "trustmanager",
        "flutter": "flutter",
        "rootbeer": "rootbeer",
        "file_check": "file_exists",
        "network_security": "network_security",
        "webview": "webview",
        "conscrypt": "sslcontext",
    }

    STRATEGY_MAP: Dict[Tuple, str] = {
        ("ssl_pinning", "okhttp3"): "okhttp3_v4",
        ("ssl_pinning", "trustmanager"): "custom_trustmanager",
        ("ssl_pinning", "flutter"): "flutter_ssl",
        ("ssl_pinning", "react_native"): "custom_trustmanager",
        ("ssl_pinning", "conscrypt"): "custom_trustmanager",
        ("ssl_pinning", "network_security"): "network_security",
        ("ssl_pinning", "webview"): "webview",
        ("ssl_pinning", "custom_pinning"): "custom_trustmanager",
        ("root_detection", "rootbeer"): "rootbeer_specific",
        ("root_detection", "safetynet"): "safetynet_bypass",
        ("root_detection", "file_check"): "generic_root",
        ("root_detection", "command_exec"): "generic_root",
        ("root_detection", "package_check"): "generic_root",
        ("root_detection", "custom_root"): "generic_root",
        ("tamper_detection", "signature_check"): "signature_bypass",
        ("tamper_detection", "hash_verification"): "signature_bypass",
        ("tamper_detection", "custom_integrity"): "signature_bypass",
        ("debugger_detection", "android_debug"): "anti_debug_bypass",
        ("debugger_detection", "tracer_pid"): "anti_debug_bypass",
        ("emulator_detection", "build_check"): "emulator_bypass",
        ("emulator_detection", "telephony_check"): "emulator_bypass",
        ("frida_detection", "port_scan"): "anti_frida",
        ("frida_detection", "maps_check"): "anti_frida",
        ("frida_detection", "native_hook_detect"): "anti_frida",
        ("xamarin_ssl", "xamarin_tls"): "xamarin_bypass",
        ("unity_ssl", "unity_tls"): "custom_trustmanager",
        ("react_native", "hermes_jsc"): "custom_trustmanager",
        ("dynamic_hook", "custom_obfuscated"): "dynamic_hook",
        ("native_ssl", "openssl_boring"): "ssl_native_bypass",
        ("lazy_class_found", "lazy_protection"): "generic_root",
        ("native_module", "security_library"): "anti_frida",
    }

    @classmethod
    def classify(cls, event: DetectionEvent, detected_hooks: Set[str]) -> Optional[ProtectionFinding]:
        best_match: Optional[ProtectionFinding] = None
        best_score = 0
        for prot_type, implementations in cls.CLASSIFICATION_RULES.items():
            for impl_name, rules in implementations.items():
                score = 0
                evidence: List[str] = []
                for pattern in rules.get("class_patterns", []):
                    if re.search(pattern, event.class_name, re.IGNORECASE):
                        score += 40
                        evidence.append("class:" + event.class_name)
                        break
                for pattern in rules.get("method_patterns", []):
                    if re.search(pattern, event.method_name, re.IGNORECASE):
                        score += 30
                        evidence.append("method:" + event.method_name)
                        break
                if "event_type_match" in rules and event.event_type == rules["event_type_match"]:
                    score += 20
                    evidence.append("event_type:" + event.event_type)
                mapped_hook = cls.HOOK_MAPPING.get(impl_name)
                if mapped_hook and mapped_hook in detected_hooks:
                    score += 10
                    evidence.append("hook_installed")
                if score > best_score and score >= 30:
                    best_score = score
                    raw_conf = rules["base_confidence"] * (score / 100)
                    confidence = max(50, min(rules["base_confidence"], int(raw_conf)))
                    strategy = cls.STRATEGY_MAP.get((prot_type, impl_name), "generic_root")
                    best_match = ProtectionFinding(
                        protection_type=prot_type,
                        implementation=impl_name,
                        target_class=event.class_name,
                        target_method=event.method_name,
                        confidence=confidence,
                        evidence=evidence,
                        bypass_strategy=strategy,
                    )
        return best_match


# ---------------------------------------------------------------------------
# JS bypass scripts — loaded from the js_scripts/ folder at runtime.
# Each script is a standalone .js file so they can be edited, version-
# controlled, and reused independently of this Python code.
# ---------------------------------------------------------------------------
class BypassScripts:
    """
    Loads Frida JS bypass/detection scripts from the ``js_scripts/`` directory
    that lives alongside this Python file.  All attributes are lazy-loaded on
    first access so the files are only read when actually needed.

    File map
    --------
    bypass_anti_frida.js    -> ANTI_FRIDA
    bypass_flutter_ssl.js   -> FLUTTER_SSL
    bypass_okhttp3.js       -> OKHTTP3
    bypass_trustmanager.js  -> TRUSTMANAGER
    bypass_network_security.js -> NETWORK_SECURITY
    bypass_webview.js       -> WEBVIEW
    bypass_rootbeer.js      -> ROOTBEER
    bypass_generic_root.js  -> GENERIC_ROOT
    bypass_safetynet.js     -> SAFETYNET
    bypass_anti_debug.js    -> ANTI_DEBUG
    bypass_emulator.js      -> EMULATOR
    bypass_signature.js     -> SIGNATURE
    detection_script.js     -> DETECTION_SCRIPT
    """

    # Directory containing all .js files (same folder as this script)
    JS_DIR: Path = Path(__file__).parent / "js_scripts"

    # Mapping: attribute name  ->  filename inside JS_DIR
    _FILE_MAP: Dict[str, str] = {
        "ANTI_FRIDA":           "bypass_anti_frida.js",
        "FLUTTER_SSL":          "bypass_flutter_ssl.js",
        "OKHTTP3":              "bypass_okhttp3.js",
        "TRUSTMANAGER":         "bypass_trustmanager.js",
        "NETWORK_SECURITY":     "bypass_network_security.js",
        "WEBVIEW":              "bypass_webview.js",
        "ROOTBEER":             "bypass_rootbeer.js",
        "GENERIC_ROOT":         "bypass_generic_root.js",
        "SAFETYNET":            "bypass_safetynet.js",
        "ANTI_DEBUG":           "bypass_anti_debug.js",
        "EMULATOR":             "bypass_emulator.js",
        "SIGNATURE":            "bypass_signature.js",
        "HTTPS_URL_CONNECTION": "bypass_httpsurlconnection.js",
        "XAMARIN":              "bypass_xamarin.js",
        "SSL_NATIVE":           "bypass_ssl_native.js",
        "BUILD_PROPS":          "bypass_build_props.js",
        # --- v4 new ---
        "DYNAMIC_DEX":          "bypass_dynamic_dex.js",
        "BIOMETRIC":            "bypass_biometric.js",
        "KILL_BYPASS":          "bypass_kill.js",
        "NATIVE_RESOLVER":      "_native_resolver.js",
        "ADB_DEBUG":            "bypass_adb_debug.js",
        "DETECT_FLUTTER":       "detect_flutter.js",
        "DETECTION_SCRIPT":     "detection_script.js",
    }

    # Internal cache so each file is read only once per session
    _cache: Dict[str, str] = {}

    @classmethod
    def _load(cls, attr: str) -> str:
        """Return the JS content for *attr*, reading from disk on first access."""
        if attr not in cls._cache:
            filename = cls._FILE_MAP[attr]
            path = cls.JS_DIR / filename
            if not path.exists():
                raise FileNotFoundError(
                    f"[BypassScripts] Required JS file not found: {path}\n"
                    f"Make sure the 'js_scripts/' folder is present next to auto_frida.py."
                )
            cls._cache[attr] = path.read_text(encoding="utf-8")
            logger.debug("Loaded JS script: %s", path)
        return cls._cache[attr]

    # ---- Public accessors (lazy-loaded from js_scripts/ on first call) ----
    # NOTE: @classmethod + @property stacking is broken in Python < 3.11.
    # Use as: BypassScripts.ANTI_FRIDA()  (with parentheses)

    @classmethod
    def ANTI_FRIDA(cls) -> str:        return cls._load("ANTI_FRIDA")
    @classmethod
    def FLUTTER_SSL(cls) -> str:       return cls._load("FLUTTER_SSL")
    @classmethod
    def OKHTTP3(cls) -> str:           return cls._load("OKHTTP3")
    @classmethod
    def TRUSTMANAGER(cls) -> str:      return cls._load("TRUSTMANAGER")
    @classmethod
    def NETWORK_SECURITY(cls) -> str:  return cls._load("NETWORK_SECURITY")
    @classmethod
    def WEBVIEW(cls) -> str:           return cls._load("WEBVIEW")
    @classmethod
    def ROOTBEER(cls) -> str:          return cls._load("ROOTBEER")
    @classmethod
    def GENERIC_ROOT(cls) -> str:      return cls._load("GENERIC_ROOT")
    @classmethod
    def SAFETYNET(cls) -> str:         return cls._load("SAFETYNET")
    @classmethod
    def ANTI_DEBUG(cls) -> str:        return cls._load("ANTI_DEBUG")
    @classmethod
    def EMULATOR(cls) -> str:          return cls._load("EMULATOR")
    @classmethod
    def SIGNATURE(cls) -> str:         return cls._load("SIGNATURE")
    @classmethod
    def DETECTION_SCRIPT(cls) -> str:  return cls._load("DETECTION_SCRIPT")
    @classmethod
    def HTTPS_URL_CONNECTION(cls) -> str: return cls._load("HTTPS_URL_CONNECTION")
    @classmethod
    def XAMARIN(cls) -> str:           return cls._load("XAMARIN")
    @classmethod
    def SSL_NATIVE(cls) -> str:        return cls._load("SSL_NATIVE")
    @classmethod
    def BUILD_PROPS(cls) -> str:       return cls._load("BUILD_PROPS")
    # --- v4 new ---
    @classmethod
    def DYNAMIC_DEX(cls) -> str:       return cls._load("DYNAMIC_DEX")
    @classmethod
    def BIOMETRIC(cls) -> str:         return cls._load("BIOMETRIC")
    @classmethod
    def KILL_BYPASS(cls) -> str:       return cls._load("KILL_BYPASS")
    @classmethod
    def NATIVE_RESOLVER(cls) -> str:    return cls._load("NATIVE_RESOLVER")
    @classmethod
    def ADB_DEBUG(cls) -> str:          return cls._load("ADB_DEBUG")
    @classmethod
    def DETECT_FLUTTER(cls) -> str:    return cls._load("DETECT_FLUTTER")

    @classmethod
    def validate_all(cls) -> bool:
        """Check all expected JS files exist. Returns True if all present."""
        missing = []
        for attr, filename in cls._FILE_MAP.items():
            if not (cls.JS_DIR / filename).exists():
                missing.append(filename)
        if missing:
            logger.error("Missing JS files in %s: %s", cls.JS_DIR, missing)
            return False
        return True



# ---------------------------------------------------------------------------
# Output-reading helper (shared by analysis and verification)
# ---------------------------------------------------------------------------
def _read_pipe_into_queue(
    pipe,
    out_queue: queue.Queue,
    stop_event: threading.Event,
) -> None:
    """Read lines from *pipe* and push them onto *out_queue* until stopped."""
    try:
        while not stop_event.is_set():
            try:
                line = pipe.readline()
                if line:
                    if isinstance(line, bytes):
                        line = line.decode("utf-8", errors="replace")
                    out_queue.put(line.strip())
                elif pipe.closed:
                    break
                else:
                    time.sleep(0.05)
            except Exception as exc:
                logger.debug("Pipe-reader error: %s", exc)
                break
    except Exception as exc:
        logger.debug("Pipe-reader outer error: %s", exc)


def _terminate_process(proc: subprocess.Popen) -> None:
    """Gracefully terminate then forcefully kill *proc*."""
    if proc and proc.poll() is None:
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def _make_popen_kwargs() -> dict:
    """Return platform-appropriate kwargs for subprocess.Popen."""
    kwargs: dict = dict(
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    if sys.platform == "win32":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["startupinfo"] = si
    return kwargs


# ---------------------------------------------------------------------------
# Auto Analyzer module
# ---------------------------------------------------------------------------

# Output-line patterns used to identify which hooks fired during analysis.
# Kept as a class constant so it's compiled once, not rebuilt per loop iteration.
_HOOK_DETECTION_PATTERNS: Dict[str, str] = {
    # SSL / TLS
    "Flutter detected":              "flutter",
    "OkHttp3":                       "okhttp3",
    "OkHttp2":                       "okhttp2",
    "TrustManager":                  "trustmanager",
    "TrustManagerImpl":              "trustmanager",
    "Conscrypt":                     "conscrypt",
    "SSLContext":                    "sslcontext",
    "NetworkSecurityConfig":         "network_security",
    "PinSet":                        "network_security",
    "WebViewClient":                 "webview",
    "HttpsURLConnection":            "httpsurlconn",
    "HurlStack":                     "httpsurlconn",
    "Retrofit":                      "httpsurlconn",
    "CronetEngine":                  "cronet",
    "Xamarin":                       "xamarin",
    "NotifyingX509TrustManager":     "xamarin",
    "libunity":                      "unity",
    "libmono":                       "xamarin",
    "React Native":                  "react_native",
    "SSL_CTX_set_verify":            "native_ssl",
    "X509_verify_cert":              "native_ssl",
    "SSL_get_verify_result":         "native_ssl",
    # Root / integrity
    "RootBeer":                      "rootbeer",
    "isRooted":                      "rootbeer",
    "checkRoot":                     "rootbeer",
    "isDeviceRooted":                "rootbeer",
    "canExecute":                    "file_check",
    "canWrite":                      "file_check",
    "FileInputStream":               "file_check",
    "getInstalledPackages":          "package_check",
    "getInstalledApplications":      "package_check",
    "getenv":                        "root_detection",
    "adb_enabled":                   "adb_detection",
    "development_settings_enabled":  "adb_detection",
    "Settings.Global":               "adb_detection",
    "isRunningInTestHarness":        "adb_detection",
    "/proc/mounts":                  "mount_check",
    "/proc/self/maps":               "maps_check",
    "kill.*sig.*0":                  "process_probe",
    "File.exists":                   "file_exists",
    "Runtime.exec":                  "runtime_exec",
    "ProcessBuilder":                "processbuilder",
    "PackageManager":                "packagemanager",
    "SafetyNet":                     "safetynet",
    "Play Integrity":                "play_integrity",
    # Signature / tamper
    "Signature":                     "signature",
    "MessageDigest":                 "message_digest",
    "getInstallerPackageName":       "installer",
    "getInstallSourceInfo":          "installer",
    # Emulator
    "TelephonyManager":              "telephony",
    "Build fields spoofed":          "build_props",
    "Native prop override":          "build_props",
    # Anti-debug
    "Debug.isDebuggerConnected":     "anti_debug",
    "waitingForDebugger":            "anti_debug",
    "ptrace":                        "anti_debug",
    # Frida detection
    "AA-Shield":                     "anti_frida",
    "Native access":                 "native_access",
    "Native property":               "native_property",
    "dlopen":                        "dlopen",
    "connect() port":                "anti_frida",
    # Dynamic / advanced (v4)
    "DexClassLoader":                "dexclassloader",
    "InMemoryDexClassLoader":        "dexclassloader",
    "Dynamic hook":                  "dynamic_hooks",
    "System.exit":                   "system_exit",
    "Runtime.halt":                  "system_exit",
    "BiometricManager":              "biometric",
    "KeyguardManager":               "keyguard",
    "Method.invoke":                 "reflection",
}

_AA_LOG_PREFIXES = ("[AutoAnalyzer]", "[AA]", "[AA-Shield]")


class AutoAnalyzerModule:
    """
    Detects and generates bypass scripts for Android app protections.
    Previously named GuardBreakerModule.
    """

    def __init__(self, auto_frida_instance: "AutoFrida") -> None:
        self.af = auto_frida_instance
        self.findings: List[ProtectionFinding] = []
        self.suspicious_classes: List[str] = []
        self.current_target: Optional[AppInfo] = None
        self.temp_script_path: Optional[Path] = None
        self.frida_major_version: int = 0
        self.detected_hooks: Set[str] = set()
        self.analysis_duration: int = 30
        self._detect_frida_version()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _detect_frida_version(self) -> None:
        try:
            v = self.af.frida_version
            if v:
                self.frida_major_version = int(v.split(".")[0])
        except Exception:
            self.frida_major_version = 16

    def _parse_detection_event(self, raw: str) -> Optional[DetectionEvent]:
        """Parse a JSON line emitted by the detection script into a DetectionEvent.

        The Frida CLI wraps every console.log() call in an envelope:
            {"type":"log","level":"info","payload":"<our JSON string>"}
        So we must unwrap the payload first, then parse our actual event JSON.
        """
        try:
            outer = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

        # Unwrap Frida log envelope: {"type":"log","payload":"<inner json>"}
        if isinstance(outer, dict) and outer.get("type") == "log":
            payload = outer.get("payload", "")
            if not isinstance(payload, str) or "{" not in payload:
                return None
            try:
                data = json.loads(payload)
            except (json.JSONDecodeError, ValueError):
                return None
        elif isinstance(outer, dict):
            # Direct JSON (no envelope) — fallback for programmatic frida usage
            data = outer
        else:
            return None

        if not data.get("autoanalyzer"):
            return None

        return DetectionEvent(
            timestamp=time.time(),
            event_type=data.get("type", "unknown"),
            method_name=data.get("method", "unknown"),
            class_name=data.get("class", "unknown"),
            stack_trace=data.get("stack", "").split(",") if data.get("stack") else [],
            thread_id=data.get("tid", 0),
            extra_data=data.get("extra", {}),
        )

    def _wait_for_app(self, identifier: str, timeout: int = 15) -> Optional[int]:
        """Poll for *identifier* PID, returning it once found or None on timeout."""
        for _ in range(timeout * 2):
            pid = self.af._get_app_pid(identifier)
            if pid:
                return pid
            time.sleep(0.5)
        return None

    # ------------------------------------------------------------------
    # Frida session runner
    # ------------------------------------------------------------------

    def _run_frida_attach(self, pid: int, script_path: Path, duration: int = 30) -> Optional[List[DetectionEvent]]:
        events: List[DetectionEvent] = []
        cmd = ["frida", "-U", "-p", str(pid), "-l", str(script_path)]
        logger.info("Attaching frida: %s", " ".join(cmd))
        print(f"{Colors.CYAN}[*] {' '.join(cmd)}{Colors.END}")
        print(f"{Colors.GREEN}[*] Interact with app! ({duration}s){Colors.END}\n")

        stop_event = threading.Event()
        output_queue: queue.Queue = queue.Queue()
        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(cmd, **_make_popen_kwargs())
            reader = threading.Thread(
                target=_read_pipe_into_queue,
                args=(proc.stdout, output_queue, stop_event),
                daemon=True,
            )
            reader.start()
            start = time.time()
            last_update = 0

            while time.time() - start < duration:
                elapsed = int(time.time() - start)
                if elapsed - last_update >= 5:
                    remaining = duration - elapsed
                    print(
                        f"\r{Colors.CYAN}    {remaining}s remaining | "
                        f"Events: {len(events)} | "
                        f"Suspicious: {len(self.suspicious_classes)}{Colors.END}    ",
                        end="", flush=True,
                    )
                    last_update = elapsed

                try:
                    line = output_queue.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None:
                        self._drain_queue(output_queue, events)
                        if proc.returncode != 0 and not events and not self.detected_hooks:
                            logger.warning("Frida exited with code %d", proc.returncode)
                            print(f"\n{Colors.YELLOW}[!] Frida exited: {proc.returncode}{Colors.END}")
                            return None
                        break
                    continue

                if not line:
                    continue

                # Extract payload from Frida log envelope for display
                display_line = line
                if line.startswith("{"):
                    try:
                        envelope = json.loads(line)
                        if isinstance(envelope, dict) and envelope.get("type") == "log":
                            display_line = envelope.get("payload", line)
                    except (json.JSONDecodeError, ValueError):
                        pass

                if any(p in display_line for p in _AA_LOG_PREFIXES):
                    cleaned = display_line.replace("\\u2713", "+").replace("\\u2717", "x")
                    print(f"\n{Colors.CYAN}    {cleaned}{Colors.END}")
                    self._update_hooks_from_line(display_line)
                    if "-> " in display_line:
                        cn = display_line.split("-> ")[-1].strip()
                        if cn and "." in cn:
                            self.suspicious_classes.append(cn)

                if "{" in line:
                    event = self._parse_detection_event(line)
                    if event:
                        events.append(event)
                        print(f"\n{Colors.GREEN}    [+] {event.event_type} - {event.method_name}{Colors.END}")

            print()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
            return events if events else None
        except Exception as exc:
            logger.error("Frida attach error: %s", exc)
            print(f"\n{Colors.RED}[!] Error: {exc}{Colors.END}")
            return events if events else None
        finally:
            stop_event.set()
            _terminate_process(proc)

        return events


    def _run_frida_spawn(self, package: str, script_path: Path, duration: int = 30) -> Optional[List[DetectionEvent]]:
        """
        Spawn the target app via Frida and inject the detection script before
        any app code runs.  Using spawn mode (-f) guarantees hooks are in place
        before SSL/root checks execute — solving the race condition that caused
        0 events when attaching to an already-running process.
        """
        events: List[DetectionEvent] = []
        cmd = ["frida", "-U", "-f", package, "-l", str(script_path)]
        logger.info("Spawning via frida: %s", " ".join(cmd))
        print(f"{Colors.CYAN}[*] {' '.join(cmd)}{Colors.END}")
        print(f"{Colors.GREEN}[*] App spawned — interact with it now! ({duration}s){Colors.END}\n")

        stop_event = threading.Event()
        output_queue: queue.Queue = queue.Queue()
        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(cmd, **_make_popen_kwargs())
            reader = threading.Thread(
                target=_read_pipe_into_queue,
                args=(proc.stdout, output_queue, stop_event),
                daemon=True,
            )
            reader.start()
            start = time.time()
            last_update = 0

            while time.time() - start < duration:
                elapsed = int(time.time() - start)
                if elapsed - last_update >= 5:
                    remaining = duration - elapsed
                    print(
                        f"\r{Colors.CYAN}    {remaining}s remaining | "
                        f"Events: {len(events)} | "
                        f"Hooks: {len(self.detected_hooks)} | "
                        f"Suspicious: {len(self.suspicious_classes)}{Colors.END}    ",
                        end="", flush=True,
                    )
                    last_update = elapsed

                try:
                    line = output_queue.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None:
                        self._drain_queue(output_queue, events)
                        if proc.returncode != 0 and not events and not self.detected_hooks:
                            logger.warning("Frida spawn exited with code %d", proc.returncode)
                            print(f"\n{Colors.YELLOW}[!] Frida exited with code {proc.returncode}{Colors.END}")
                            print(f"{Colors.YELLOW}    Tip: Check that the device is connected and the package exists.{Colors.END}")
                            return None
                        break
                    continue

                if not line:
                    continue

                # Frida CLI wraps console.log as:
                #   {"type":"log","level":"info","payload":"<text>"}
                # Extract the payload text for display and hook detection.
                display_line = line
                if line.startswith("{"):
                    try:
                        envelope = json.loads(line)
                        if isinstance(envelope, dict) and envelope.get("type") == "log":
                            display_line = envelope.get("payload", line)
                    except (json.JSONDecodeError, ValueError):
                        pass

                # Print AA log lines cleanly
                if any(p in display_line for p in _AA_LOG_PREFIXES):
                    cleaned = display_line.replace("\\u2713", "+").replace("\\u2717", "x")
                    print(f"\n{Colors.CYAN}    {cleaned}{Colors.END}")
                    self._update_hooks_from_line(display_line)
                    if "-> " in display_line:
                        cn = display_line.split("-> ")[-1].strip()
                        if cn and "." in cn:
                            self.suspicious_classes.append(cn)
                elif display_line and not display_line.startswith("{"):
                    # Show frida errors/warnings for debugging
                    if any(kw in display_line.lower() for kw in ("error", "warning", "exception", "failed", "unable")):
                        print(f"\n{Colors.YELLOW}    [frida] {display_line}{Colors.END}")

                # Try to parse as a detection event (handles Frida envelope automatically)
                if "{" in line:
                    try:
                        event = self._parse_detection_event(line)
                        if event:
                            events.append(event)
                            print(f"\n{Colors.GREEN}    [+] Detected: {event.event_type} — {event.method_name}{Colors.END}")
                    except Exception:
                        pass

            print()

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
            return events if events else None
        except Exception as exc:
            logger.error("Frida spawn error: %s", exc)
            print(f"\n{Colors.RED}[!] Error: {exc}{Colors.END}")
            return events if events else None
        finally:
            stop_event.set()
            _terminate_process(proc)
            # Ensure app is cleaned up after analysis
            try:
                self.af.kill_app(package)
            except Exception:
                pass

        return events

    def _drain_queue(self, out_queue: queue.Queue, events: List[DetectionEvent]) -> None:
        """Consume any remaining lines in *out_queue* after the process exits."""
        while True:
            try:
                line = out_queue.get_nowait()
                if line and "{" in line:
                    event = self._parse_detection_event(line)
                    if event:
                        events.append(event)
            except queue.Empty:
                break

    def _update_hooks_from_line(self, line: str) -> None:
        """Check the line against known hook patterns and update detected_hooks."""
        line_lower = line.lower()
        if not ("installed" in line_lower or "detected" in line_lower or "active" in line_lower):
            return
        for pattern, hook in _HOOK_DETECTION_PATTERNS.items():
            if pattern in line:
                self.detected_hooks.add(hook)

    # ------------------------------------------------------------------
    # Analysis phases
    # ------------------------------------------------------------------

    def run_analysis_flow(self, target: AppInfo, duration: int = 30) -> bool:
        self.current_target = target
        self.detected_hooks = set()
        self.suspicious_classes = []
        self.findings = []
        self.analysis_duration = duration

        if not self._confirm_analysis():
            return False

        self._print_phase("Phase 0 - Self-Protection Shield")
        print(f"{Colors.CYAN}[*] Anti-Frida shield will be included in bypass script{Colors.END}")

        self._print_phase(f"Phase 1 - Dynamic Detection ({self.analysis_duration}s)")
        events = self._detection_phase(self.analysis_duration)
        if not events and not self.detected_hooks and not self.suspicious_classes:
            return self._handle_detection_failure()

        self._print_phase("Phase 2 - Weighted Pattern Analysis")
        self.findings = self._analyze_events(events or [])
        if not self.findings and not self.detected_hooks:
            return self._handle_detection_failure()

        self._display_findings()

        self._print_phase("Phase 3 - Script Generation")
        script_path = self._generate_bypass_script()
        return self._post_generation_menu(script_path)

    def _print_phase(self, label: str) -> None:
        print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  AUTO ANALYZER: {label}{Colors.END}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.END}")

    def _confirm_analysis(self) -> bool:
        print(f"\n{Colors.CYAN}Auto Analyzer v2 Analysis Mode{Colors.END}")
        print(f"{Colors.CYAN}{'-' * 50}{Colors.END}")
        print(f"Target: {Colors.YELLOW}{self.current_target.identifier}{Colors.END}")
        print(f"\nThis will:")
        for step in [
            "0. Install Anti-Frida shield",
            "1. Enumerate ALL loaded classes",
            "2. Attach with enhanced detection hooks",
            f"3. Monitor for {self.analysis_duration} seconds",
            "4. Classify with weighted analysis",
            "5. Generate comprehensive bypass",
        ]:
            print(f"  {step}")
        print(f"\n{Colors.YELLOW}Interact with the app during monitoring!{Colors.END}")
        print(f"\n{Colors.CYAN}Duration:{Colors.END}")
        print(f"  1. Quick (30s)  2. Standard (45s)  3. Deep (60s)  4. Extended (90s)  5. Max (120s)  N. Cancel")
        is_num, choice = self.af.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 5, allow_special=["n"])
        if not is_num and choice == "n":
            return False
        self.analysis_duration = {1: 30, 2: 45, 3: 60, 4: 90, 5: 120}.get(choice, 30)
        print(f"{Colors.GREEN}[+] Duration: {self.analysis_duration}s{Colors.END}")
        return True

    def _detection_phase(self, duration: int = 30) -> Optional[List[DetectionEvent]]:
        self._cleanup_environment()
        _fd, _tmp = tempfile.mkstemp(suffix=".js", prefix="aa_detect_")
        os.close(_fd)
        self.temp_script_path = Path(_tmp)
        self.temp_script_path.write_text(BypassScripts.DETECTION_SCRIPT(), encoding="utf-8")

        logger.info("Detection script: %s", self.temp_script_path)
        print(f"{Colors.BLUE}[*] Preparing detection hooks...{Colors.END}")

        # Kill any existing instance so we can spawn fresh
        self.af.kill_app(self.current_target.identifier)
        time.sleep(1)
        print(f"{Colors.BLUE}[*] Spawning app via Frida (hooks installed before app code runs)...{Colors.END}")
        events = self._run_frida_spawn(self.current_target.identifier, self.temp_script_path, duration)

        try:
            self.af.kill_app(self.current_target.identifier)
        except Exception as exc:
            logger.debug("Kill app after detection: %s", exc)

        if self.temp_script_path and self.temp_script_path.exists():
            try:
                self.temp_script_path.unlink()
            except Exception as exc:
                logger.debug("Temp script cleanup: %s", exc)

        if events is None:
            return None

        print(f"{Colors.GREEN}[+] {len(events)} events captured{Colors.END}")
        if self.detected_hooks:
            print(f"{Colors.CYAN}[*] Hooks: {', '.join(sorted(self.detected_hooks))}{Colors.END}")
        if self.suspicious_classes:
            print(f"{Colors.CYAN}[*] Suspicious classes: {len(self.suspicious_classes)}{Colors.END}")
        return events

    def _analyze_events(self, events: List[DetectionEvent]) -> List[ProtectionFinding]:
        seen: Set[str] = set()
        unique: List[DetectionEvent] = []
        for e in events:
            sig = f"{e.event_type}:{e.class_name}:{e.method_name}"
            if sig not in seen:
                seen.add(sig)
                unique.append(e)

        print(f"{Colors.BLUE}[*] Analyzing {len(unique)} unique events...{Colors.END}")
        findings: List[ProtectionFinding] = []

        for ev in unique:
            f = ProtectionClassifier.classify(ev, self.detected_hooks)
            if f and f not in findings:
                findings.append(f)

        # Boost findings from class enumeration events
        for sc in (e for e in unique if e.event_type == "suspicious_class"):
            if not any(sc.class_name in f.target_class or f.target_class in sc.class_name for f in findings):
                f = ProtectionClassifier.classify(sc, self.detected_hooks)
                if f and f not in findings:
                    f.evidence.append("class_enumeration")
                    findings.append(f)

        # Synthesise findings from directly observed hooks
        hook_map: Dict[str, ProtectionFinding] = {
            "flutter":        ProtectionFinding("ssl_pinning",       "Flutter_Native",   "libflutter.so",                       "ssl_verify",              90, ["Flutter detected", "Flutter SSL"], "flutter_ssl"),
            "okhttp3":        ProtectionFinding("ssl_pinning",       "OkHttp3",          "okhttp3.CertificatePinner",            "check",                   95, ["OkHttp3 installed"],          "okhttp3_v4"),
            "okhttp2":        ProtectionFinding("ssl_pinning",       "OkHttp2",          "com.squareup.okhttp.CertificatePinner","check",                   88, ["OkHttp2 installed"],          "okhttp2_bypass"),
            "trustmanager":   ProtectionFinding("ssl_pinning",       "TrustManager",     "TrustManagerImpl",                    "verifyChain",             90, ["TrustManager installed"],     "custom_trustmanager"),
            "conscrypt":      ProtectionFinding("ssl_pinning",       "Conscrypt",        "ConscryptFDSocket",                   "verifyCertChain",         88, ["Conscrypt installed"],        "custom_trustmanager"),
            "httpsurlconn":   ProtectionFinding("ssl_pinning",       "HttpsURLConn",     "javax.net.ssl.HttpsURLConnection",     "setSSLSocketFactory",     82, ["HttpsURLConn hook"],          "https_url_bypass"),
            "network_security":ProtectionFinding("ssl_pinning",      "NetworkSecurity",  "android.security.net.config.NetworkSecurityConfig","isCleartextTrafficPermitted",85,["NSC installed"],"network_security"),
            "webview":        ProtectionFinding("ssl_pinning",       "WebView",          "android.webkit.WebViewClient",        "onReceivedSslError",      83, ["WebView hook"],               "webview"),
            "native_ssl":     ProtectionFinding("native_ssl",        "LibSSL_Boring",    "native_ssl",                          "SSL_CTX_set_verify",      92, ["Native SSL hook"],            "ssl_native_bypass"),
            "xamarin":        ProtectionFinding("xamarin_ssl",       "Xamarin_Mono",     "mono.android.ssl",                    "checkServerTrusted",      85, ["Xamarin hook"],               "xamarin_bypass"),
            "unity":          ProtectionFinding("unity_ssl",         "Unity",            "libunity.so",                         "SSL",                     80, ["Unity detected"],             "custom_trustmanager"),
            "rootbeer":       ProtectionFinding("root_detection",    "RootBeer",         "RootBeer",                            "isRooted",                98, ["RootBeer installed"],         "rootbeer_specific"),
            "safetynet":      ProtectionFinding("root_detection",    "SafetyNet",        "SafetyNetClient",                     "attest",                  95, ["SafetyNet installed"],        "safetynet_bypass"),
            "play_integrity": ProtectionFinding("root_detection",    "PlayIntegrity",    "IntegrityManager",                    "requestToken",            95, ["PlayIntegrity installed"],    "safetynet_bypass"),
            "file_exists":    ProtectionFinding("root_detection",    "FileCheck",        "java.io.File",                        "exists",                  75, ["File.exists hook"],           "generic_root"),
            "anti_debug":     ProtectionFinding("debugger_detection","AndroidDebug",     "android.os.Debug",                    "isDebuggerConnected",     90, ["Debug installed"],            "anti_debug_bypass"),
            "anti_frida":     ProtectionFinding("frida_detection",   "AntiFrida",        "native",                              "various",                 88, ["Anti-frida detected"],        "anti_frida"),
            "build_props":    ProtectionFinding("emulator_detection","BuildProps",       "android.os.Build",                    "FINGERPRINT",             78, ["Build props detected"],       "build_props_bypass"),
            "telephony":      ProtectionFinding("emulator_detection","TelephonyManager", "android.telephony.TelephonyManager",  "getImei",                 82, ["TelephonyManager hook"],      "emulator_bypass"),
            "signature":      ProtectionFinding("tamper_detection",  "SignatureCheck",   "PackageManager",                      "getPackageInfo",          80, ["Signature hook"],             "signature_bypass"),
            "message_digest": ProtectionFinding("tamper_detection",  "MessageDigest",    "java.security.MessageDigest",         "digest",                  72, ["MessageDigest hook"],         "signature_bypass"),
            "installer":      ProtectionFinding("tamper_detection",  "InstallerCheck",   "PackageManager",                      "getInstallerPackageName", 78, ["Installer hook"],             "signature_bypass"),
            "dexclassloader": ProtectionFinding("dynamic_code_load", "DexClassLoader",   "dalvik.system.DexClassLoader",        "<init>",                  85, ["DexClassLoader hook"],        "dynamic_code_load"),
            "biometric":      ProtectionFinding("biometric_gate",    "Biometric",        "android.hardware.biometrics.BiometricManager","canAuthenticate", 80, ["Biometric hook"],            "biometric_bypass"),
            "keyguard":       ProtectionFinding("biometric_gate",    "Keyguard",         "android.app.KeyguardManager",         "isDeviceSecure",          78, ["Keyguard hook"],              "biometric_bypass"),
            "system_exit":    ProtectionFinding("protection_triggered","SystemExit",      "java.lang.System",                    "exit",                    90, ["System.exit hook"],           "protection_kill_bypass"),
            "dynamic_hooks":  ProtectionFinding("dynamic_hook",      "CustomClass",      "unknown",                             "various",                 65, ["Dynamic hook"],               "dynamic_hook"),
        }
        for hk, pf in hook_map.items():
            if hk in self.detected_hooks and pf not in findings:
                findings.append(pf)

        # Multi-signal confidence boost
        type_counts: Dict[str, int] = {}
        for pf in findings:
            type_counts[pf.protection_type] = type_counts.get(pf.protection_type, 0) + 1
        for pf in findings:
            if type_counts.get(pf.protection_type, 0) > 1:
                pf.confidence = min(99, pf.confidence + 10)
                if "multi_signal_boost" not in pf.evidence:
                    pf.evidence.append("multi_signal_boost")

        findings.sort(key=lambda x: x.confidence, reverse=True)
        return findings

    def _display_findings(self) -> None:
        print(f"\n{Colors.GREEN}Detected Protections:{Colors.END}")
        print(f"{Colors.CYAN}{'-' * 90}{Colors.END}")
        print(f"{'#':<4} {'Type':<22} {'Implementation':<20} {'Confidence':<12} {'Strategy':<22} Evidence")
        print(f"{Colors.CYAN}{'-' * 90}{Colors.END}")
        for i, pf in enumerate(self.findings, 1):
            cc = Colors.GREEN if pf.confidence >= 80 else Colors.YELLOW if pf.confidence >= 60 else Colors.RED
            ev = ", ".join(pf.evidence[:2])
            print(f"{i:<4} {pf.protection_type:<22} {pf.implementation:<20} {cc}{pf.confidence}%{Colors.END}{'':>5} {pf.bypass_strategy:<22} {ev}")
        print(f"{Colors.CYAN}{'-' * 90}{Colors.END}")
        if self.detected_hooks:
            print(f"\n{Colors.CYAN}Hooks: {', '.join(sorted(self.detected_hooks))}{Colors.END}")
        if self.suspicious_classes:
            print(f"{Colors.CYAN}Suspicious: {len(self.suspicious_classes)}{Colors.END}")
            for c in self.suspicious_classes[:10]:
                print(f"  {Colors.YELLOW}-> {c}{Colors.END}")
        summary: Dict[str, int] = {}
        for pf in self.findings:
            summary[pf.protection_type] = summary.get(pf.protection_type, 0) + 1
        print(f"\n{Colors.CYAN}Summary:{Colors.END}")
        for pt, cnt in summary.items():
            print(f"  {pt}: {cnt}")
        print(f"\n{Colors.YELLOW}[*] Generating COMPREHENSIVE bypass for ALL protections{Colors.END}")

    # ------------------------------------------------------------------
    # Script generation — CONSOLIDATED (no duplicate hooks)
    # ------------------------------------------------------------------

    def _generate_bypass_script(self) -> Path:
        """Generate a single bypass script with NO duplicate hooks.

        Architecture
        ~~~~~~~~~~~~
        Instead of naively concatenating standalone JS files (which causes
        double-hooking crashes), this method:

        1. Generates **consolidated** inline JS for conflict groups —
           each native symbol and Java method hooked exactly once with
           merged logic from all relevant bypass modules.
        2. Loads **non-conflicting** modules from external JS files
           (okhttp3, webview, flutter, xamarin, safetynet, emulator,
           biometric, kill, ssl_native, network_security).

        Conflict groups resolved
        ~~~~~~~~~~~~~~~~~~~~~~~~
        - **Native**: open, fgets, fopen, strstr, strcmp, __system_property_get,
          access, stat, kill, realpath  (anti_frida + build_props + generic_root)
        - **SSL Java**: SSLContext.init, setDefaultHostnameVerifier
          (trustmanager + httpsurlconnection)
        - **Root Java**: File.*, PM.*, Runtime.exec, Debug.*, Class.forName,
          SystemProperties, BufferedReader, RootBeer, Settings.*
          (generic_root + rootbeer + adb_debug + anti_debug + signature + dynamic_dex)
        """
        output_dir = Path("generated_bypasses")
        output_dir.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        pkg = self.current_target.identifier.replace(".", "_")
        fn = f"aa_{pkg}_{ts}.js"
        out = output_dir / fn

        plan = BypassPlan.from_findings(self.findings, self.detected_hooks)

        parts: List[str] = []
        count = 0

        def _add(script: str, label: str) -> None:
            nonlocal count
            parts.append(script)
            count += 1
            print(f"{Colors.GREEN}    + {label}{Colors.END}")

        # ── Header ────────────────────────────────────────────────────
        header = (
            f"// Auto Analyzer v4 Comprehensive Bypass (Consolidated)\n"
            f"// Target:      {self.current_target.identifier}\n"
            f"// Generated:   {datetime.now().isoformat()}\n"
            f"// Protections: {len(self.findings)}\n"
            f"// Usage:       frida -U -l {fn} -f {self.current_target.identifier}\n\n"
            f'"use strict";\n'
            f'console.log("[AA v4] Bypass Active - {self.current_target.identifier}");\n'
            f'console.log("[AA v4] {len(self.findings)} protections detected");\n\n'
        )

        # ── Layer -1: Native resolver (always first) ──────────────────
        _add(BypassScripts.NATIVE_RESOLVER(), "Native symbol resolver")

        # ── Layer 0a: Shared constants ────────────────────────────────
        _add(self._gen_shared_constants_js(), "Shared constants (root paths, packages)")

        # ── Layer 0b: Consolidated native hooks ───────────────────────
        # Replaces: bypass_anti_frida.js (native), bypass_build_props.js (native),
        #           bypass_generic_root.js (native sections 10-12)
        _add(self._gen_native_hooks_js(plan), "Consolidated native hooks")

        # ── Layer 0c: Non-conflicting pre-Java native modules ─────────
        if plan.ssl_native:
            _add(BypassScripts.SSL_NATIVE(), "Native SSL (libssl/BoringSSL)")
        if plan.flutter:
            _add(BypassScripts.DETECT_FLUTTER(), "Flutter detection")
            _add(BypassScripts.FLUTTER_SSL(), "Flutter SSL")

        # ── Layer 0d: Anti-frida Java (early, 500ms) ──────────────────
        if plan.anti_frida:
            _add(self._gen_anti_frida_java_js(), "Anti-Frida Java (StackTrace + Socket)")

        # ── Layer 1: Main Java.perform block (1000ms) ─────────────────
        # Contains ALL Java hooks. Each method hooked exactly once.
        java_parts: List[str] = []
        java_count = 0

        def _java(script: str, label: str) -> None:
            nonlocal java_count
            java_parts.append(script)
            java_count += 1
            print(f"{Colors.GREEN}    + {label}{Colors.END}")

        # Build props Java (MUST be inside Java.perform for spawn mode)
        if plan.build_props:
            _java(self._gen_build_props_java_js(), "Build field spoofing")

        # Consolidated SSL — replaces trustmanager + httpsurlconnection
        if plan.trustmanager or plan.https_url_connection:
            _java(self._gen_ssl_bypass_js(plan), "Consolidated SSL bypass")

        # Non-conflicting SSL modules (loaded from external JS files)
        if plan.okhttp3 or plan.okhttp2:
            _java(BypassScripts.OKHTTP3(), "OkHttp3 / OkHttp2")
        if plan.network_security:
            _java(BypassScripts.NETWORK_SECURITY(), "NetworkSecurityConfig / PinSet")
        if plan.webview:
            _java(BypassScripts.WEBVIEW(), "WebView SSL")
        if plan.xamarin:
            _java(BypassScripts.XAMARIN(), "Xamarin / Mono")

        # Consolidated root + ADB + debug + PM + signature
        # Replaces: generic_root, rootbeer, adb_debug, anti_debug, signature, dynamic_dex
        _java(
            self._gen_root_adb_bypass_js(plan),
            "Consolidated root/ADB/debug/PM/signature bypass",
        )

        # Non-conflicting modules
        if plan.safetynet:
            _java(BypassScripts.SAFETYNET(), "SafetyNet / Play Integrity")
        if plan.emulator:
            _java(BypassScripts.EMULATOR(), "Emulator TelephonyManager")
        if plan.biometric_gate:
            _java(BypassScripts.BIOMETRIC(), "Biometric / Keyguard gate")
        if plan.protection_kill:
            _java(BypassScripts.KILL_BYPASS(), "System.exit / Runtime.halt interceptor")

        # Dynamic class bypass (auto-generated for obfuscated classes)
        if plan.dynamic_classes:
            dyn_js = self._generate_dynamic_class_bypass(plan.dynamic_classes)
            if dyn_js:
                java_parts.append(dyn_js)
                java_count += 1
                print(f"{Colors.GREEN}    + Dynamic bypass for "
                      f"{len(plan.dynamic_classes)} class(es){Colors.END}")

        total = count + java_count
        java_block = (
            '\nsetTimeout(function() {\n'
            '    Java.perform(function() {\n'
            '        console.log("[AA v2] Installing Java bypasses...");\n\n'
            + "\n".join(java_parts)
            + f'\n\n        console.log("[AA v2] All {total} bypass modules installed!");\n'
            '    });\n'
            '}, 1000);\n'
        )
        parts.append(java_block)
        count += java_count

        # ── Layer 2: Delayed class scans (2-3s) ──────────────────────
        _add(self._gen_delayed_scans_js(plan), "Delayed class scans")

        # ── Write output ──────────────────────────────────────────────
        out.write_text(header + "\n".join(parts), encoding="utf-8")
        logger.info("Generated consolidated bypass: %s (%d modules)", out, count)
        print(f"\n{Colors.GREEN}[+] Script: {out}{Colors.END}")
        print(f"{Colors.CYAN}    Modules: {count} | Protections: {len(self.findings)}{Colors.END}")
        return out

    @staticmethod
    def _generate_dynamic_class_bypass(dynamic_classes: List[str]) -> str:
        """Generate hooks for dynamically-detected custom protection classes.

        These classes are usually obfuscated, so we hook suspicious method
        names heuristically and return a safe default based on the overload's
        declared return type.
        """
        cleaned: List[str] = []
        seen: Set[str] = set()
        for class_name in dynamic_classes:
            if not class_name or class_name in seen:
                continue
            seen.add(class_name)
            cleaned.append(class_name)

        if not cleaned:
            return ""

        class_list_js = json.dumps(cleaned)
        return f'''
// ======================================================================
// DYNAMIC / OBFUSCATED CLASS BYPASS
// Auto-generated from analysis findings
// ======================================================================
(function() {{
    var TARGET_CLASSES = {class_list_js};
    var NAME_PATTERNS = [
        /check/i, /detect/i, /verify/i, /isRoot/i, /isEmul/i,
        /isDebug/i, /pin/i, /attest/i, /sign/i, /cert/i,
        /trust/i, /integrity/i, /tamper/i, /secure/i
    ];

    function shouldHook(name) {{
        if (!name || name.charAt(0) === "$") return false;
        for (var i = 0; i < NAME_PATTERNS.length; i++) {{
            if (NAME_PATTERNS[i].test(name)) return true;
        }}
        return false;
    }}

    function safeReturn(returnType, args) {{
        if (!returnType) return null;
        if (returnType === "void") return;
        if (returnType === "boolean" || returnType === "java.lang.Boolean") return false;
        if (returnType === "int" || returnType === "java.lang.Integer" ||
            returnType === "short" || returnType === "java.lang.Short" ||
            returnType === "byte" || returnType === "java.lang.Byte") return 0;
        if (returnType === "long" || returnType === "java.lang.Long") return 0;
        if (returnType === "float" || returnType === "java.lang.Float") return 0.0;
        if (returnType === "double" || returnType === "java.lang.Double") return 0.0;
        if (returnType === "char" || returnType === "java.lang.Character") return 0;
        if (returnType === "java.lang.String") return "";
        if (returnType.indexOf("[") === 0) {{
            if (args && args.length > 0 && args[0] !== null) return args[0];
            return null;
        }}
        if (returnType.indexOf("java.util.List") !== -1 ||
            returnType.indexOf("java.util.Collection") !== -1) {{
            try {{ return Java.use("java.util.ArrayList").$new(); }} catch(e) {{ return null; }}
        }}
        if (returnType.indexOf("java.util.Map") !== -1) {{
            try {{ return Java.use("java.util.HashMap").$new(); }} catch(e) {{ return null; }}
        }}
        if (returnType.indexOf("javax.net.ssl") !== -1 ||
            returnType.indexOf("java.security.cert") !== -1) {{
            if (args && args.length > 0) return args[0];
        }}
        return null;
    }}

    TARGET_CLASSES.forEach(function(cn) {{
        try {{
            var C = Java.use(cn);
            var declared = C.class.getDeclaredMethods();
            var seenMethods = {{}};
            var installed = 0;
            for (var i = 0; i < declared.length; i++) {{
                var methodName = declared[i].getName();
                if (seenMethods[methodName]) continue;
                seenMethods[methodName] = true;
                if (!shouldHook(methodName)) continue;
                try {{
                    if (!C[methodName] || typeof C[methodName].overloads === "undefined") continue;
                    C[methodName].overloads.forEach(function(ol) {{
                        if (!ol || typeof ol.implementation === "undefined") return;
                        var rt = (ol.returnType && ol.returnType.className) ? ol.returnType.className : "";
                        ol.implementation = function() {{
                            console.log("[AA] -> Dynamic bypass: " + cn + "." + methodName);
                            return safeReturn(rt, arguments);
                        }};
                        installed += 1;
                    }});
                }} catch (hookErr) {{}}
            }}
            if (installed > 0) {{
                console.log("[AA] + Dynamic class bypass installed: " + cn + " (" + installed + " overloads)");
            }}
        }} catch (classErr) {{
            console.log("[AA] Dynamic class skipped: " + cn + " (" + classErr + ")");
        }}
    }});
}})();'''

    # ==================================================================
    # Consolidated JS generators
    # Each native symbol / Java method hooked EXACTLY ONCE.
    # ==================================================================

    @staticmethod
    def _gen_shared_constants_js() -> str:
        """Shared root paths, packages, keywords, and helper functions.

        Used by both native and Java hooks — defined once at global scope
        so every subsequent section can call isRootPath(), isRootPkg(), etc.
        """
        return r'''
// ======================================================================
// SHARED CONSTANTS
// ======================================================================
var ROOT_PATHS = [
    "/sbin/su","/system/bin/su","/system/xbin/su","/system/bin/.ext/su",
    "/system/xbin/sudo","/data/local/xbin/su","/data/local/bin/su",
    "/data/local/su","/su/bin/su","/su/bin","/system/bin/failsafe/su",
    "/system/sd/xbin/su","/magisk/.core/bin/su",
    "/sbin/magisk","/sbin/.magisk","/system/bin/magisk",
    "/data/adb/magisk","/data/adb/ksu","/init.magisk.rc",
    "/sbin/.core/mirror","/sbin/.core/img","/sbin/.core/db-0/magisk",
    "/system/xbin/daemonsu","/system/xbin/sugote","/system/xbin/sugote-mksh",
    "/system/bin/app_process.orig",
    "/system/xbin/busybox","/system/bin/busybox","/sbin/busybox","/data/busybox",
    "/system/framework/XposedBridge.jar","/system/bin/app_process.xposed",
    "/data/data/de.robv.android.xposed.installer",
    "/data/app/de.robv.android.xposed.installer",
    "/data/adb/ksud","/data/adb/ksu/bin/ksud",
    "/system/app/Superuser.apk","/system/app/SuperSU.apk",
    "/system/app/Kinguser.apk","/data/local/tmp/","/system/csk"
];
var ROOT_KEYWORDS = [
    "magisk","supersu","superuser","busybox","xposed","lsposed","edxposed",
    "riru","kernelsu","ksud","daemonsu","sugote","rootcloak","substrate",
    "chainfire","apatch","kingroot","kingo","framaroot","towelroot",
    "titaniumbackup","lucky_patcher"
];
var ROOT_PKGS = [
    "com.topjohnwu.magisk","io.github.lsposed.manager","org.lsposed.manager",
    "me.weishu.kernelsu","me.weishu.exp","eu.chainfire.supersu",
    "com.koushikdutta.superuser","com.noshufou.android.su",
    "com.noshufou.android.su.elite","com.thirdparty.superuser",
    "com.yellowes.su","com.kingroot.kinguser","com.kingo.root",
    "com.smedialink.oneclickroot","com.zhiqupk.root.global",
    "com.alephzain.framaroot","com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license","com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch","com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro","de.robv.android.xposed.installer",
    "com.saurik.substrate","com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus","com.amphoras.hidemyroot",
    "com.formyhm.hideroot","com.zachspong.temprootremovejb",
    "com.accessoriesdreams.rootremover","com.qasico.magiskhide",
    "io.github.vvb2060.magisk"
];
var ROOT_CLASSES = [
    "com.noshufou.android.su.EliteVersion",
    "de.robv.android.xposed.XposedBridge",
    "de.robv.android.xposed.XC_MethodHook",
    "de.robv.android.xposed.XC_MethodReplacement",
    "com.saurik.substrate.MS$MethodPointer",
    "me.weishu.exposed.Container",
    "io.github.lsposed.lspd.ILSPManagerService",
    "com.topjohnwu.magisk.core.su.SuCallHandler"
];
var BLOCKED_CMDS = [
    "which su","which magisk","which busybox",
    "/system/xbin/su","/system/bin/su","/sbin/su",
    "id","getprop ro.build.tags","getprop ro.debuggable",
    "mount","cat /proc/mounts","cat /proc/self/maps",
    "ls /sbin","ls /system/xbin","ls /data/adb","pm list packages"
];
var DEBUG_PATHS = [
    "/sys/kernel/debug","/sys/kernel/debug/usb",
    "/proc/net/unix","/sys/class/android_usb/android0/enable"
];
var ADB_INT_KEYS = [
    "adb_enabled","development_settings_enabled","stay_on_while_plugged_in",
    "usb_configuration","mock_location","allow_mock_location",
    "install_non_market_apps","package_verifier_enable"
];
var ROOTBEER_METHODS = [
    "isRooted","isRootedWithoutBusyBoxCheck","isRootedWithBusyBoxCheck",
    "detectRootManagementApps","detectPotentiallyDangerousApps",
    "detectTestKeys","checkForBusyBoxBinary","checkForSuBinary",
    "checkSuExists","checkForRWPaths","checkForDangerousProps",
    "checkForRootNative","detectRootCloakingApps","checkForMagiskBinary",
    "isSelinuxFlagInEnabled","checkSELinuxEnforcing",
    "checkForSuInPath","checkForDangerousProperties","checkForRWSystem"
];

function isRootPath(p) {
    if (!p) return false; var pl = p.toLowerCase();
    for (var i = 0; i < ROOT_PATHS.length; i++)
        if (pl === ROOT_PATHS[i] || pl.indexOf(ROOT_PATHS[i]) === 0) return true;
    for (var j = 0; j < ROOT_KEYWORDS.length; j++)
        if (pl.indexOf(ROOT_KEYWORDS[j]) !== -1) return true;
    return false;
}
function isRootPkg(pkg) {
    if (!pkg) return false;
    for (var i = 0; i < ROOT_PKGS.length; i++) if (pkg === ROOT_PKGS[i]) return true;
    return false;
}
function isBlockedCmd(cmd) {
    var cl = cmd.toLowerCase().trim();
    for (var i = 0; i < BLOCKED_CMDS.length; i++)
        if (cl.indexOf(BLOCKED_CMDS[i]) !== -1) return true;
    return isRootPath(cl);
}
function isDebugPath(p) {
    if (!p) return false;
    for (var i = 0; i < DEBUG_PATHS.length; i++)
        if (p.indexOf(DEBUG_PATHS[i]) === 0) return true;
    return false;
}
function isSensitivePath(p) { return isRootPath(p) || isDebugPath(p); }
function isAdbKey(name) {
    for (var i = 0; i < ADB_INT_KEYS.length; i++) if (name === ADB_INT_KEYS[i]) return true;
    return false;
}

// Thread guard — pure native, zero JNI
var _mainThreadId = Process.getCurrentThreadId();
var _safeAfterMs  = Date.now() + 4000;
function _isMainThread() {
    if (Date.now() > _safeAfterMs) return true;
    return Process.getCurrentThreadId() === _mainThreadId;
}
'''

    @staticmethod
    def _gen_native_hooks_js(plan: "BypassPlan") -> str:
        """ALL native hooks — each symbol hooked exactly once.

        Merges logic from: bypass_anti_frida.js, bypass_build_props.js,
        bypass_generic_root.js (native sections 10-12).
        """
        # Build the merged property overrides map dynamically
        prop_entries = [
            '"ro.debuggable":"0"', '"ro.secure":"1"',
            '"ro.build.selinux":"1"', '"ro.build.tags":"release-keys"',
            '"ro.build.type":"user"',
            '"init.svc.adbd":"stopped"', '"init.svc.adbd_root":"stopped"',
            '"service.adb.root":"0"', '"ro.adb.secure":"1"',
            '"persist.service.adb.enable":"0"',
            '"persist.sys.usb.config":"mtp"', '"sys.usb.state":"mtp"',
            '"sys.usb.config":"mtp"', '"init.svc.qemu-props":""',
            '"ro.kernel.qemu":"0"', '"ro.kernel.qemu.avd_name":""',
            '"ro.boot.qemu":"0"', '"ro.boot.qemu.avd_name":""',
        ]
        if plan.build_props:
            prop_entries.extend([
                '"ro.build.fingerprint":"google/oriole/oriole:12/SP1A.210812.016.A1/7961137:user/release-keys"',
                '"ro.product.model":"Pixel 6"',
                '"ro.product.manufacturer":"Google"',
                '"ro.product.brand":"google"',
                '"ro.product.device":"oriole"',
                '"ro.product.name":"oriole"',
                '"ro.hardware":"oriole"',
            ])
        prop_map_js = "{" + ",".join(prop_entries) + "}"

        af = plan.anti_frida

        # Build the anti-frida lines conditionally
        open_af_line = (
            'if(p.indexOf("/proc/net/tcp")!==-1||p.indexOf("frida")!==-1) this._block=true;'
            if af else ""
        )
        fgets_af_line = (
            'if(line.indexOf("frida")!==-1||line.indexOf("27042")!==-1||'
            'line.indexOf("linjector")!==-1) return orig(buf,sz,fp);'
            if af else ""
        )

        # strstr/strcmp blocks only included if anti_frida is active
        strstr_block = r'''
// ── strstr() — anti-frida ──
(function() {
    try {
        var sPtr = _findNativeSym("strstr"); if (!sPtr) return;
        var orig = new NativeFunction(sPtr, "pointer", ["pointer","pointer"]);
        Interceptor.replace(sPtr, new NativeCallback(function(h, n) {
            try {
                var s = n.isNull() ? "" : (n.readCString() || "");
                if (s==="frida"||s==="gadget"||s==="gum-js-loop") return ptr(0);
            } catch(e) {}
            return orig(h, n);
        }, "pointer", ["pointer","pointer"]));
        console.log("[AA] + strstr() anti-frida hook");
    } catch(e) {}
})();

// ── strcmp() — anti-frida ──
(function() {
    try {
        var cPtr = _findNativeSym("strcmp"); if (!cPtr) return;
        var orig = new NativeFunction(cPtr, "int", ["pointer","pointer"]);
        Interceptor.replace(cPtr, new NativeCallback(function(a, b) {
            try {
                var s1 = a.isNull()?"":a.readCString()||"";
                var s2 = b.isNull()?"":b.readCString()||"";
                if ((s1+s2).indexOf("frida")!==-1) return -1;
            } catch(e) {}
            return orig(a, b);
        }, "int", ["pointer","pointer"]));
        console.log("[AA] + strcmp() anti-frida hook");
    } catch(e) {}
})();
''' if af else ""

        return f'''
// ======================================================================
// CONSOLIDATED NATIVE HOOKS — each symbol hooked EXACTLY ONCE
// Merges: anti-frida + build-props + generic-root native sections
// ======================================================================
console.log("[AA] Installing consolidated native hooks...");

// ── __system_property_get — single Interceptor.replace ──
(function() {{
    var ALL_PROPS = {prop_map_js};
    try {{
        var ptr = _findNativeSym("__system_property_get");
        if (!ptr) {{ console.log("[AA] __system_property_get not found"); return; }}
        var orig = new NativeFunction(ptr, "int", ["pointer","pointer"]);
        Interceptor.replace(ptr, new NativeCallback(function(nPtr, vPtr) {{
            var n = ""; try {{ n = nPtr.readCString() || ""; }} catch(e) {{}}
            if (n && ALL_PROPS.hasOwnProperty(n)) {{
                try {{ vPtr.writeUtf8String(ALL_PROPS[n]); return ALL_PROPS[n].length; }} catch(e) {{}}
            }}
            return orig(nPtr, vPtr);
        }}, "int", ["pointer","pointer"]));
        console.log("[AA] + __system_property_get hook installed");
    }} catch(e) {{ console.log("[AA] __system_property_get skipped: " + e.message); }}
}})();

// ── open() — single Interceptor.attach (safe for variadic args) ──
(function() {{
    try {{
        var ptr = _findNativeSym("open");
        if (!ptr) return;
        Interceptor.attach(ptr, {{
            onEnter: function(args) {{
                this._block = false;
                try {{
                    var p = args[0].readCString() || "";
                    {open_af_line}
                    if (isSensitivePath(p)) this._block = true;
                }} catch(e) {{}}
            }},
            onLeave: function(ret) {{ if (this._block) ret.replace(-1); }}
        }});
        console.log("[AA] + open() hook installed");
    }} catch(e) {{}}
}})();

// ── open64 / __open_2 — root/debug paths only ──
["open64","__open_2"].forEach(function(sym) {{
    try {{
        var p = _findNativeSym(sym); if (!p) return;
        Interceptor.attach(p, {{
            onEnter: function(a) {{
                this._block = false;
                try {{ if (isSensitivePath(a[0].readCString())) this._block = true; }} catch(e) {{}}
            }},
            onLeave: function(r) {{ if (this._block) r.replace(-1); }}
        }});
    }} catch(e) {{}}
}});

// ── fopen() — single Interceptor.replace ──
(function() {{
    try {{
        var fptr = _findNativeSym("fopen"); if (!fptr) return;
        var orig = new NativeFunction(fptr, "pointer", ["pointer","pointer"]);
        Interceptor.replace(fptr, new NativeCallback(function(pPtr, mPtr) {{
            var p = ""; try {{ p = pPtr.readCString() || ""; }} catch(e) {{}}
            if (isSensitivePath(p)) return ptr(0);
            if (p==="/proc/net/unix"||p==="/proc/net/tcp"||p==="/proc/net/tcp6"
                ||p.indexOf("/proc/self/maps")!==-1) return ptr(0);
            return orig(pPtr, mPtr);
        }}, "pointer", ["pointer","pointer"]));
        console.log("[AA] + fopen() hook installed");
    }} catch(e) {{}}
}})();

// ── fgets() — single Interceptor.replace (anti-frida scrub + mount scrub) ──
(function() {{
    try {{
        var fptr = _findNativeSym("fgets"); if (!fptr) return;
        var orig = new NativeFunction(fptr, "pointer", ["pointer","int","pointer"]);
        Interceptor.replace(fptr, new NativeCallback(function(buf, sz, fp) {{
            var r = orig(buf, sz, fp);
            if (r.isNull()) return r;
            try {{
                var line = buf.readCString() || "";
                {fgets_af_line}
                if ((line.indexOf(" rw,")!==-1||line.indexOf(" rw ")!==-1) &&
                    (line.indexOf("/system")!==-1||line.indexOf("/ ")!==-1||
                     line.indexOf("rootfs")!==-1||line.indexOf("tmpfs /sbin")!==-1))
                    try {{ buf.writeUtf8String(line.replace(" rw,"," ro,").replace(" rw "," ro ")); }} catch(e2) {{}}
                if (line.indexOf("magisk")!==-1||line.indexOf("/sbin/.core")!==-1||
                    line.indexOf("/.magisk")!==-1)
                    try {{ buf.writeUtf8String("tmpfs /dev tmpfs rw,seclabel 0 0\\n"); }} catch(e2) {{}}
            }} catch(e) {{}}
            return r;
        }}, "pointer", ["pointer","int","pointer"]));
        console.log("[AA] + fgets() hook installed");
    }} catch(e) {{}}
}})();

{strstr_block}

// ── access / faccessat ──
["access","faccessat"].forEach(function(sym) {{
    try {{
        var p = _findNativeSym(sym); if (!p) return;
        Interceptor.attach(p, {{
            onEnter: function(a) {{
                this._block = false;
                var idx = (sym==="faccessat") ? 1 : 0;
                try {{ if (isSensitivePath(a[idx].readCString())) this._block = true; }} catch(e) {{}}
            }},
            onLeave: function(r) {{ if (this._block) r.replace(-1); }}
        }});
    }} catch(e) {{}}
}});

// ── stat / lstat variants ──
["stat","stat64","lstat","lstat64"].forEach(function(sym) {{
    try {{
        var p = _findNativeSym(sym); if (!p) return;
        Interceptor.attach(p, {{
            onEnter: function(a) {{
                this._block = false;
                try {{ if (isSensitivePath(a[0].readCString())) this._block = true; }} catch(e) {{}}
            }},
            onLeave: function(r) {{ if (this._block) r.replace(-1); }}
        }});
    }} catch(e) {{}}
}});
["__xstat","__xstat64"].forEach(function(sym) {{
    try {{
        var p = _findNativeSym(sym); if (!p) return;
        Interceptor.attach(p, {{
            onEnter: function(a) {{
                this._block = false;
                try {{ if (isSensitivePath(a[1].readCString())) this._block = true; }} catch(e) {{}}
            }},
            onLeave: function(r) {{ if (this._block) r.replace(-1); }}
        }});
    }} catch(e) {{}}
}});

// ── kill() — safe mode (do NOT blanket-block sig=0) ──
(function() {{
    try {{
        var kptr = _findNativeSym("kill"); if (!kptr) return;
        Interceptor.attach(kptr, {{
            onEnter: function(a) {{ this._block = false; }},
            onLeave: function(r) {{ if (this._block) r.replace(-1); }}
        }});
        console.log("[AA] + kill() hook installed (safe mode)");
    }} catch(e) {{}}
}})();

// ── realpath() ──
(function() {{
    try {{
        var rptr = _findNativeSym("realpath"); if (!rptr) return;
        Interceptor.attach(rptr, {{
            onEnter: function(a) {{
                this._block = false; this._out = a[1];
                try {{ if (isRootPath(a[0].readCString())) this._block = true; }} catch(e) {{}}
            }},
            onLeave: function(r) {{
                if (this._block) {{
                    if (this._out && !this._out.isNull())
                        try {{ this._out.writeUtf8String(""); }} catch(e) {{}}
                    r.replace(ptr(0));
                }}
            }}
        }});
    }} catch(e) {{}}
}})();

console.log("[AA] Consolidated native hooks installed.");
'''

    @staticmethod
    def _gen_anti_frida_java_js() -> str:
        """Anti-frida Java hooks — early setTimeout (500ms)."""
        return '''
// ======================================================================
// ANTI-FRIDA JAVA (500ms — before main Java.perform)
// ======================================================================
setTimeout(function() {
    Java.perform(function() {
        try {
            var Thread = Java.use("java.lang.Thread");
            Thread.getStackTrace.implementation = function() {
                var t = this.getStackTrace.call(this), o = [];
                for (var i = 0; i < t.length; i++) {
                    var f = t[i].toString();
                    if (f.indexOf("frida")===-1 && f.indexOf("gadget")===-1) o.push(t[i]);
                }
                return o;
            };
            console.log("[AA-Shield] + StackTrace filter installed");
        } catch(e) {}
        try {
            var Socket = Java.use("java.net.Socket");
            var _si = Socket.$init.overload("java.lang.String","int");
            _si.implementation = function(h, p) {
                if (p===27042||p===27043)
                    throw Java.use("java.io.IOException").$new("Connection refused");
                return _si.call(this, h, p);
            };
            console.log("[AA-Shield] + Socket filter installed");
        } catch(e) {}
    });
}, 500);
console.log("[AA-Shield] Anti-Frida shield active");
'''

    @staticmethod
    def _gen_build_props_java_js() -> str:
        """Build field spoofing — inside Java.perform (spawn-mode safe).

        FIX: Original had Java.use() at top level which fails in spawn mode
        because the Java VM isn't ready yet.
        """
        return '''
// ── Build fields (inside Java.perform — safe for spawn mode) ──
try {
    var Build = Java.use("android.os.Build");
    var _bp = {
        FINGERPRINT:"google/oriole/oriole:12/SP1A.210812.016.A1/7961137:user/release-keys",
        MANUFACTURER:"Google",BRAND:"google",MODEL:"Pixel 6",DEVICE:"oriole",
        PRODUCT:"oriole",HARDWARE:"oriole",BOARD:"oriole",TAGS:"release-keys",
        TYPE:"user",HOST:"abfarm-release-rbe-64-00026",BOOTLOADER:"slider-1.0-8077218"
    };
    Object.keys(_bp).forEach(function(k) { try { Build[k].value = _bp[k]; } catch(e) {} });
    console.log("[AA] + Build fields spoofed");
} catch(e) { console.log("[AA] Build fields: " + e.message); }

// ── Settings.Secure android_id — combined with ADB key check ──
try {
    var _SS = Java.use("android.provider.Settings$Secure");
    var _ssGS = _SS.getString.overload("android.content.ContentResolver","java.lang.String");
    _ssGS.implementation = function(cr, name) {
        if (name === "android_id") return "a1b2c3d4e5f60718";
        if (isAdbKey(name)) return "0";
        return _ssGS.call(this, cr, name);
    };
    console.log("[AA] + Settings.Secure bypass installed");
} catch(e) {}
'''

    @staticmethod
    def _gen_ssl_bypass_js(plan: "BypassPlan") -> str:
        """Consolidated SSL Java hooks.

        Replaces both bypass_trustmanager.js AND bypass_httpsurlconnection.js.
        Each method (SSLContext.init, setDefaultHostnameVerifier, etc.) is
        hooked exactly once with merged logic from both modules.
        """
        return '''
// ======================================================================
// CONSOLIDATED SSL / TLS BYPASS
// Merges: trustmanager + httpsurlconnection (no duplicate hooks)
// ======================================================================

// ── TrustManagerImpl (Conscrypt) ──
try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TMI.verifyChain.overloads.forEach(function(ol) {
        if (!ol || typeof ol.implementation === "undefined") return;
        ol.implementation = function() {
            console.log("[AA] -> TrustManagerImpl.verifyChain bypassed");
            return arguments[0];
        };
    });
    console.log("[AA] + TrustManagerImpl bypass installed");
} catch(e) {}

// ── Conscrypt sockets ──
["org.conscrypt.ConscryptFileDescriptorSocket",
 "org.conscrypt.ConscryptEngineSocket"].forEach(function(cls) {
    try {
        var C = Java.use(cls);
        C.verifyCertificateChain.overloads.forEach(function(ol) {
            if (!ol || typeof ol.implementation === "undefined") return;
            ol.implementation = function() {
                console.log("[AA] -> " + cls + ".verifyCertificateChain bypassed");
            };
        });
    } catch(e) {}
});

// ── SSLContext.init — SINGLE HOOK (no registerClass, Android 16 safe) ──
// FIX: Was hooked separately by trustmanager and httpsurlconnection scripts.
// Now a single hook that patches TrustManagers in-place, skips WebView/Chromium
// callers during startup to prevent SIGSEGV.
try {
    var SSLCtx = Java.use("javax.net.ssl.SSLContext");
    var _sslInit = SSLCtx.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );
    _sslInit.implementation = function(km, tms, sr) {
        // Skip non-main threads during startup (WebView/Chromium safety)
        if (!_isMainThread()) return _sslInit.call(this, km, tms, sr);
        // Patch each TrustManager in-place
        if (tms !== null) {
            try {
                for (var j = 0; j < tms.length; j++) {
                    var tm = tms[j]; if (!tm) continue;
                    var cn = tm.getClass().getName();
                    try {
                        var TC = Java.use(cn);
                        if (TC.checkServerTrusted) {
                            TC.checkServerTrusted.overloads.forEach(function(ol) {
                                if (!ol || typeof ol.implementation === "undefined") return;
                                ol.implementation = function() {
                                    console.log("[AA] -> " + cn + ".checkServerTrusted bypassed");
                                };
                            });
                        }
                        if (TC.checkClientTrusted) {
                            TC.checkClientTrusted.overloads.forEach(function(ol) {
                                if (!ol || typeof ol.implementation === "undefined") return;
                                ol.implementation = function() {};
                            });
                        }
                    } catch(e2) {}
                }
            } catch(e) {}
        }
        console.log("[AA] -> SSLContext.init: TrustManagers patched");
        return _sslInit.call(this, km, tms, sr);
    };
    console.log("[AA] + SSLContext.init consolidated bypass installed");
} catch(e) { console.log("[AA] SSLContext: " + e.message); }

// ── HttpsURLConnection — SINGLE set of hooks ──
// FIX: setSSLSocketFactory and setDefaultHostnameVerifier were each hooked
// by both trustmanager and httpsurlconnection scripts. Now hooked once.
try {
    var HTTPS = Java.use("javax.net.ssl.HttpsURLConnection");
    try {
        var _setSSL = HTTPS.setSSLSocketFactory.overload("javax.net.ssl.SSLSocketFactory");
        _setSSL.implementation = function(f) {
            console.log("[AA] -> HttpsURLConnection.setSSLSocketFactory bypassed");
            return _setSSL.call(this, f);
        };
    } catch(e) {}
    // setDefaultHostnameVerifier — ONCE with in-place patching
    HTTPS.setDefaultHostnameVerifier.implementation = function(hv) {
        if (hv !== null) {
            try {
                var hvCn = hv.getClass().getName();
                var HVC = Java.use(hvCn);
                HVC.verify.overloads.forEach(function(ol) {
                    if (!ol || typeof ol.implementation === "undefined") return;
                    ol.implementation = function() {
                        console.log("[AA] -> HV.verify bypassed");
                        return true;
                    };
                });
            } catch(e2) {}
        }
        return this.setDefaultHostnameVerifier.call(this, hv);
    };
    // Instance setHostnameVerifier
    try {
        var _setHV = HTTPS.setHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
        _setHV.implementation = function(v) {
            console.log("[AA] -> HttpsURLConnection.setHostnameVerifier bypassed");
            return _setHV.call(this, v);
        };
    } catch(e) {}
    console.log("[AA] + HttpsURLConnection consolidated bypass installed");
} catch(e) {}

// ── SSLSocket.startHandshake ──
try {
    var SSLSock = Java.use("javax.net.ssl.SSLSocket");
    var _sh = SSLSock.startHandshake.overload();
    _sh.implementation = function() {
        console.log("[AA] -> SSLSocket.startHandshake");
        return _sh.call(this);
    };
} catch(e) {}

// ── Volley HurlStack ──
try {
    var HS = Java.use("com.android.volley.toolbox.HurlStack");
    var _cc = HS.createConnection.overload("java.net.URL");
    _cc.implementation = function(u) {
        console.log("[AA] -> Volley HurlStack");
        return _cc.call(this, u);
    };
} catch(e) {}
'''

    @staticmethod
    def _gen_root_adb_bypass_js(plan: "BypassPlan") -> str:
        """Consolidated root + ADB + debug + PM + signature Java bypass.

        Replaces ALL of these individually-conflicting scripts:
        - bypass_generic_root.js  (Java sections 1-9, 12)
        - bypass_rootbeer.js
        - bypass_adb_debug.js
        - bypass_anti_debug.js
        - bypass_signature.js
        - bypass_dynamic_dex.js  (Class.forName part)

        Each Java method is hooked EXACTLY ONCE with merged logic.
        """
        # Conditionally include anti_debug hooks
        anti_debug_section = r'''
// ── Anti-debug: ptrace-related (handled in native hooks above) ──
// Debug.isDebuggerConnected + waitingForDebugger already hooked below.
''' if plan.anti_debug else ""

        # Conditionally include signature monitoring
        sig_section = r'''
// ── MessageDigest monitoring ──
try {
    var MD = Java.use("java.security.MessageDigest");
    var _md0 = MD.digest.overload();
    _md0.implementation = function() {
        console.log("[AA] -> MessageDigest.digest() (" + this.getAlgorithm() + ")");
        return _md0.call(this);
    };
    try {
        var _mdB = MD.digest.overload("[B");
        _mdB.implementation = function(inp) {
            console.log("[AA] -> MessageDigest.digest(bytes) (" + this.getAlgorithm() + ")");
            return _mdB.call(this, inp);
        };
    } catch(e) {}
    console.log("[AA] + MessageDigest monitor installed");
} catch(e) {}
''' if plan.signature else ""

        # Conditionally include dynamic code loading
        dex_section = r'''
// ── DexClassLoader / InMemoryDexClassLoader ──
try {
    var DCL = Java.use("dalvik.system.DexClassLoader");
    DCL.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log("[AA] -> DexClassLoader: " + dexPath);
        return this.$init(dexPath, optDir, libPath, parent);
    };
    console.log("[AA] + DexClassLoader hook installed");
} catch(e) {}
try {
    var IDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
    IDCL.$init.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> InMemoryDexClassLoader used");
            return ol.apply(this, arguments);
        };
    });
    console.log("[AA] + InMemoryDexClassLoader hook installed");
} catch(e) {}
''' if plan.dynamic_code_load else ""

        return f'''
// ======================================================================
// CONSOLIDATED ROOT + ADB + DEBUG + PM + SIGNATURE BYPASS
// Each Java method hooked EXACTLY ONCE with merged logic.
// Replaces: generic_root, rootbeer, adb_debug, anti_debug, signature
// ======================================================================

// ── File API — single hook per method (root + debug paths merged) ──
// FIX: Was hooked in generic_root then overwritten by adb_debug
try {{
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return false;
        return File.exists.call(this);
    }};
    File.canExecute.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return false;
        return File.canExecute.call(this);
    }};
    File.canRead.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return false;
        return File.canRead.call(this);
    }};
    File.canWrite.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        var pl = p.toLowerCase();
        if (pl==="/system"||pl==="/system/"||pl.indexOf("/system/bin")===0
            ||pl.indexOf("/sbin")===0||pl==="/data/local/tmp"||isSensitivePath(p))
            return false;
        return File.canWrite.call(this);
    }};
    File.length.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return 0;
        return File.length.call(this);
    }};
    File.isFile.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return false;
        return File.isFile.call(this);
    }};
    File.isDirectory.implementation = function() {{
        var p = this.getAbsolutePath().toString();
        if (isSensitivePath(p)) return false;
        return File.isDirectory.call(this);
    }};
    console.log("[AA] + File API consolidated bypass installed");
}} catch(e) {{ console.log("[AA] File error: " + e); }}

// ── FileInputStream / FileReader ──
try {{
    var FIS = Java.use("java.io.FileInputStream");
    FIS.$init.overload("java.lang.String").implementation = function(path) {{
        if (isSensitivePath(path))
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        return FIS.$init.overload("java.lang.String").call(this, path);
    }};
    FIS.$init.overload("java.io.File").implementation = function(file) {{
        var path = file.getAbsolutePath().toString();
        if (isSensitivePath(path))
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        return FIS.$init.overload("java.io.File").call(this, file);
    }};
}} catch(e) {{}}
try {{
    var FR = Java.use("java.io.FileReader");
    FR.$init.overload("java.lang.String").implementation = function(path) {{
        if (isSensitivePath(path))
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        return FR.$init.overload("java.lang.String").call(this, path);
    }};
}} catch(e) {{}}

// ── Runtime.exec — all overloads ──
try {{
    var RT = Java.use("java.lang.Runtime");
    var IOEx = Java.use("java.io.IOException");
    RT.exec.overload("java.lang.String").implementation = function(cmd) {{
        if (isBlockedCmd(cmd)) throw IOEx.$new("No such file or directory");
        return RT.exec.overload("java.lang.String").call(this, cmd);
    }};
    RT.exec.overload("[Ljava.lang.String;").implementation = function(cmds) {{
        if (isBlockedCmd(Array.prototype.join.call(cmds, " ")))
            throw IOEx.$new("No such file or directory");
        return RT.exec.overload("[Ljava.lang.String;").call(this, cmds);
    }};
    try {{
        RT.exec.overload("java.lang.String","[Ljava.lang.String;").implementation = function(cmd, env) {{
            if (isBlockedCmd(cmd)) throw IOEx.$new("No such file or directory");
            return RT.exec.overload("java.lang.String","[Ljava.lang.String;").call(this, cmd, env);
        }};
    }} catch(e) {{}}
    try {{
        RT.exec.overload("java.lang.String","[Ljava.lang.String;","java.io.File").implementation = function(cmd, env, dir) {{
            if (isBlockedCmd(cmd)) throw IOEx.$new("No such file or directory");
            return RT.exec.overload("java.lang.String","[Ljava.lang.String;","java.io.File").call(this, cmd, env, dir);
        }};
    }} catch(e) {{}}
    console.log("[AA] + Runtime.exec bypass installed");
}} catch(e) {{}}

// ── ProcessBuilder ──
try {{
    var PB = Java.use("java.lang.ProcessBuilder");
    PB.start.overload().implementation = function() {{
        var cmd = this.command().toString();
        if (isBlockedCmd(cmd)) throw Java.use("java.io.IOException").$new("No such file or directory");
        return PB.start.overload().call(this);
    }};
}} catch(e) {{}}

// ── PackageManager — SINGLE consolidated hook ──
// FIX: Was hooked separately by generic_root (root blocking),
// signature (monitoring), and adb_debug (FLAG_DEBUGGABLE clearing).
// Now a single hook per method with all three concerns merged.
try {{
    var PM = Java.use("android.app.ApplicationPackageManager");
    var NNFE = Java.use("android.content.pm.PackageManager$NameNotFoundException");

    // getPackageInfo(String, int) — root blocking + signature monitoring
    var _gpi = PM.getPackageInfo.overload("java.lang.String","int");
    _gpi.implementation = function(pkg, flags) {{
        if (isRootPkg(pkg)) throw NNFE.$new(pkg);
        if ((flags & 0x40) !== 0 || (flags & 0x8000000) !== 0)
            console.log("[AA] -> Signature check: " + pkg);
        return _gpi.call(this, pkg, flags);
    }};

    // getPackageInfo API 33+ variants
    try {{
        PM.getPackageInfo.overloads.forEach(function(ol) {{
            if (!ol || typeof ol.implementation === "undefined") return;
            var types = ol.argumentTypes.map(function(t) {{ return t.className; }});
            if (types.length === 2 && types[0] === "java.lang.String" && types[1] !== "int") {{
                ol.implementation = function() {{
                    var pkg = arguments[0] ? arguments[0].toString() : "";
                    if (isRootPkg(pkg)) throw NNFE.$new(pkg);
                    return ol.apply(this, arguments);
                }};
            }}
        }});
    }} catch(e) {{}}

    // getApplicationInfo(String, int) — root blocking + FLAG_DEBUGGABLE clearing
    try {{
        var _gai = PM.getApplicationInfo.overload("java.lang.String","int");
        _gai.implementation = function(pkg, flags) {{
            if (isRootPkg(pkg)) throw NNFE.$new(pkg);
            var info = _gai.call(this, pkg, flags);
            if (info !== null) {{
                try {{
                    var cf = info.flags.value;
                    if ((cf & 0x2) !== 0) info.flags.value = cf & ~0x2;
                }} catch(e2) {{}}
            }}
            return info;
        }};
    }} catch(e) {{}}

    // getApplicationInfo API 33+
    try {{
        PM.getApplicationInfo.overloads.forEach(function(ol) {{
            if (!ol || typeof ol.implementation === "undefined") return;
            var types = ol.argumentTypes.map(function(t) {{ return t.className; }});
            if (types.length === 2 && types[0] === "java.lang.String" && types[1] !== "int") {{
                ol.implementation = function() {{
                    var pkg = arguments[0] ? arguments[0].toString() : "";
                    if (isRootPkg(pkg)) throw NNFE.$new(pkg);
                    return ol.apply(this, arguments);
                }};
            }}
        }});
    }} catch(e) {{}}

    // getInstallerPackageName — spoof to Play Store
    try {{
        PM.getInstallerPackageName.overload("java.lang.String").implementation = function(pkg) {{
            return "com.android.vending";
        }};
    }} catch(e) {{}}

    // getInstallSourceInfo (API 30+)
    try {{
        var _gisi = PM.getInstallSourceInfo.overload("java.lang.String");
        _gisi.implementation = function(pkg) {{ return _gisi.call(this, pkg); }};
    }} catch(e) {{}}

    // getLaunchIntentForPackage — null for root apps
    try {{
        var _lint = PM.getLaunchIntentForPackage.overload("java.lang.String");
        _lint.implementation = function(pkg) {{
            if (isRootPkg(pkg)) return null;
            return _lint.call(this, pkg);
        }};
    }} catch(e) {{}}

    // getInstalledPackages — filter root packages
    try {{
        var _gips = PM.getInstalledPackages.overload("int");
        _gips.implementation = function(flags) {{
            var list = _gips.call(this, flags);
            var filtered = Java.use("java.util.ArrayList").$new();
            for (var i = 0; i < list.size(); i++) {{
                var pi = list.get(i);
                if (!isRootPkg(pi.packageName.toString())) filtered.add(pi);
            }}
            return filtered;
        }};
    }} catch(e) {{}}

    // getInstalledApplications — filter root apps
    try {{
        var _gias = PM.getInstalledApplications.overload("int");
        _gias.implementation = function(flags) {{
            var list = _gias.call(this, flags);
            var filtered = Java.use("java.util.ArrayList").$new();
            for (var i = 0; i < list.size(); i++) {{
                var ai = list.get(i);
                if (!isRootPkg(ai.packageName.toString())) filtered.add(ai);
            }}
            return filtered;
        }};
    }} catch(e) {{}}

    console.log("[AA] + PackageManager consolidated bypass installed");
}} catch(e) {{ console.log("[AA] PM error: " + e); }}

// ── SystemProperties ──
try {{
    var SP = Java.use("android.os.SystemProperties");
    var _SP_MAP = {{
        "ro.debuggable":"0","ro.secure":"1","ro.build.selinux":"1",
        "ro.build.tags":"release-keys","ro.build.type":"user",
        "ro.kernel.qemu":"0","ro.boot.qemu":"0",
        "ro.kernel.qemu.avd_name":"","ro.boot.qemu.avd_name":"",
        "init.svc.adbd":"stopped","service.adb.root":"0"
    }};
    function _spLookup(k) {{ return _SP_MAP.hasOwnProperty(k) ? _SP_MAP[k] : null; }}
    SP.get.overload("java.lang.String").implementation = function(k) {{
        var s = _spLookup(k); if (s !== null) return s;
        return SP.get.overload("java.lang.String").call(this, k);
    }};
    SP.get.overload("java.lang.String","java.lang.String").implementation = function(k, d) {{
        var s = _spLookup(k); if (s !== null) return s;
        return SP.get.overload("java.lang.String","java.lang.String").call(this, k, d);
    }};
    try {{
        SP.getBoolean.overload("java.lang.String","boolean").implementation = function(k, d) {{
            if (k==="ro.debuggable") return false;
            if (k==="ro.secure") return true;
            return SP.getBoolean.overload("java.lang.String","boolean").call(this, k, d);
        }};
    }} catch(e) {{}}
    try {{
        SP.getInt.overload("java.lang.String","int").implementation = function(k, d) {{
            if (k==="ro.debuggable") return 0; if (k==="ro.secure") return 1;
            return SP.getInt.overload("java.lang.String","int").call(this, k, d);
        }};
    }} catch(e) {{}}
    console.log("[AA] + SystemProperties bypass installed");
}} catch(e) {{}}

// ── System.getenv ──
try {{
    var SysE = Java.use("java.lang.System");
    var _genv = SysE.getenv.overload("java.lang.String");
    _genv.implementation = function(key) {{
        var val = _genv.call(this, key);
        if (key === "PATH" && val) {{
            var parts = val.split(":");
            var clean = parts.filter(function(p) {{ return !isRootPath(p) && p.indexOf("/sbin")!==0; }});
            return clean.join(":");
        }}
        if (key === "LD_LIBRARY_PATH" && val && isRootPath(val)) return "";
        return val;
    }};
}} catch(e) {{}}

// ── Debug.isDebuggerConnected — SINGLE hook ──
// FIX: Was hooked in generic_root AND adb_debug
try {{
    var Dbg = Java.use("android.os.Debug");
    Dbg.isDebuggerConnected.implementation = function() {{ return false; }};
    try {{ Dbg.waitingForDebugger.implementation = function() {{ return false; }}; }} catch(e) {{}}
    console.log("[AA] + Debug bypass installed");
}} catch(e) {{}}

// ── Class.forName — SINGLE hook with merged logic ──
// FIX: Was hooked in generic_root (root class blocking) AND
// dynamic_dex (suspicious class monitoring). Now one hook does both.
try {{
    var Cls = Java.use("java.lang.Class");
    var _cfn1 = Cls.forName.overload("java.lang.String");
    _cfn1.implementation = function(name) {{
        for (var i = 0; i < ROOT_CLASSES.length; i++)
            if (name === ROOT_CLASSES[i])
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
        if (/protect|guard|check|detect|verify|integr|tamper|root|frida|hook/i.test(name))
            console.log("[AA] -> Class.forName suspicious: " + name);
        return _cfn1.call(this, name);
    }};
    var _cfn3 = Cls.forName.overload("java.lang.String","boolean","java.lang.ClassLoader");
    _cfn3.implementation = function(name, init, loader) {{
        for (var i = 0; i < ROOT_CLASSES.length; i++)
            if (name === ROOT_CLASSES[i])
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
        return _cfn3.call(this, name, init, loader);
    }};
    console.log("[AA] + Class.forName consolidated bypass installed");
}} catch(e) {{}}

// ── RootBeer — SINGLE hook ──
// FIX: Was hooked in generic_root AND rootbeer sections
["com.scottyab.rootbeer.RootBeer",
 "com.scottyab.rootbeer.RootBeerNative"].forEach(function(cls) {{
    try {{
        var RB = Java.use(cls);
        ROOTBEER_METHODS.forEach(function(m) {{
            try {{
                if (!RB[m] || typeof RB[m].overloads === "undefined") return;
                RB[m].overloads.forEach(function(ol) {{
                    if (!ol || typeof ol.implementation === "undefined") return;
                    var rt = ol.returnType ? ol.returnType.className : "boolean";
                    ol.implementation = function() {{
                        if (rt==="boolean"||rt==="Boolean") return false;
                        if (rt==="int"||rt==="Integer") return 0;
                        if (rt==="java.lang.String") return "";
                        return null;
                    }};
                }});
            }} catch(e2) {{}}
        }});
        console.log("[AA] + RootBeer bypass: " + cls);
    }} catch(e) {{}}
}});

// ── BufferedReader.readLine — safe (no infinite recursion) ──
// FIX: Original called readLine() recursively to skip lines, which
// could cause stack overflow if many consecutive lines match.
// Now returns empty string instead.
try {{
    var BR = Java.use("java.io.BufferedReader");
    var _rl = BR.readLine.overload();
    _rl.implementation = function() {{
        var line = _rl.call(this);
        if (line !== null) {{
            var ll = line.toLowerCase();
            if (ll.indexOf("magisk")!==-1||ll.indexOf("xposed")!==-1||
                ll.indexOf("frida")!==-1||ll.indexOf("substrate")!==-1||
                ll.indexOf("/su")!==-1||ll.indexOf("supersu")!==-1)
                return "";
        }}
        return line;
    }};
    console.log("[AA] + BufferedReader filter installed (safe)");
}} catch(e) {{}}

// ── Settings.Global (ADB/dev options) ──
try {{
    var SG = Java.use("android.provider.Settings$Global");
    SG.getInt.overload("android.content.ContentResolver","java.lang.String").implementation =
        function(cr, name) {{
            if (!_isMainThread()) return SG.getInt.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
            if (isAdbKey(name)) return 0;
            return SG.getInt.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
        }};
    SG.getInt.overload("android.content.ContentResolver","java.lang.String","int").implementation =
        function(cr, name, def) {{
            if (!_isMainThread()) return SG.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
            if (isAdbKey(name)) return 0;
            return SG.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
        }};
    SG.getString.overload("android.content.ContentResolver","java.lang.String").implementation =
        function(cr, name) {{
            if (!_isMainThread()) return SG.getString.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
            if (isAdbKey(name)) return "0";
            return SG.getString.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
        }};
    console.log("[AA] + Settings.Global bypass installed");
}} catch(e) {{}}

// ── Settings.Secure (getInt only — getString already hooked in build_props) ──
try {{
    var SS2 = Java.use("android.provider.Settings$Secure");
    SS2.getInt.overload("android.content.ContentResolver","java.lang.String").implementation =
        function(cr, name) {{
            if (!_isMainThread()) return SS2.getInt.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
            if (isAdbKey(name)) return 0;
            return SS2.getInt.overload("android.content.ContentResolver","java.lang.String").call(this, cr, name);
        }};
    SS2.getInt.overload("android.content.ContentResolver","java.lang.String","int").implementation =
        function(cr, name, def) {{
            if (!_isMainThread()) return SS2.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
            if (isAdbKey(name)) return 0;
            return SS2.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
        }};
}} catch(e) {{}}

// ── Settings.System ──
try {{
    var SY = Java.use("android.provider.Settings$System");
    SY.getInt.overload("android.content.ContentResolver","java.lang.String","int").implementation =
        function(cr, name, def) {{
            if (!_isMainThread()) return SY.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
            if (isAdbKey(name)) return 0;
            return SY.getInt.overload("android.content.ContentResolver","java.lang.String","int").call(this, cr, name, def);
        }};
}} catch(e) {{}}

// ── ActivityManager ──
try {{
    var AM = Java.use("android.app.ActivityManager");
    try {{ AM.isRunningInTestHarness.implementation = function() {{ return false; }}; }} catch(e) {{}}
    try {{ AM.isUserAMonkey.implementation = function() {{ return false; }}; }} catch(e) {{}}
    try {{ AM.isRunningInUserTestHarness.implementation = function() {{ return false; }}; }} catch(e) {{}}
}} catch(e) {{}}

{anti_debug_section}
{sig_section}
{dex_section}

console.log("[AA] Consolidated root/ADB/debug/PM bypass installed.");
'''

    @staticmethod
    def _gen_delayed_scans_js(plan: "BypassPlan") -> str:
        """Delayed class scans (2-3s) for custom TrustManagers and generic root methods."""
        return '''
// ======================================================================
// DELAYED SCANS (2-3s after startup)
// ======================================================================

// Custom TrustManager scan
setTimeout(function() {
    Java.perform(function() {
        try {
            var SKIP = /^(java\\.|android\\.|javax\\.|sun\\.|dalvik\\.|kotlin\\.|androidx\\.|com\\.google\\.android\\.|org\\.conscrypt\\.|com\\.android\\.)/;
            Java.enumerateLoadedClassesSync().forEach(function(cn) {
                if (SKIP.test(cn)) return;
                if (cn.charAt(0)==="[" || cn.indexOf("$Proxy")!==-1) return;
                var cl = cn.toLowerCase();
                if (cl.indexOf("trustmanager")===-1 && cl.indexOf("x509")===-1 &&
                    cl.indexOf("certverif")===-1) return;
                try {
                    var C = Java.use(cn);
                    ["checkServerTrusted","checkClientTrusted"].forEach(function(m) {
                        try {
                            if (!C[m] || typeof C[m].overloads==="undefined") return;
                            C[m].overloads.forEach(function(ol) {
                                if (!ol || typeof ol.implementation==="undefined") return;
                                ol.implementation = function() {
                                    console.log("[AA] -> Custom TM." + m + " bypassed: " + cn);
                                };
                            });
                        } catch(e2) {}
                    });
                } catch(e) {}
            });
            console.log("[AA] + Custom TrustManager scan complete");
        } catch(e) {}
    });
}, 2000);

// Generic root method scan
setTimeout(function() {
    Java.perform(function() {
        try {
            var SKIP_RE = /^(java|android|javax|dalvik|kotlin|androidx|com\\.google\\.android|sun\\.)/;
            var TARGET_METHODS = [
                "isRooted","isDeviceRooted","checkRoot","hasRoot",
                "isJailBroken","isCompromised","isDeviceCompromised",
                "deviceIsRooted","rootDetected","isRootPresent",
                "isDeviceSecure","isDeviceIntact"
            ];
            var TARGET_PATTERNS = [
                /rootdetect/i, /rootcheck/i, /jailbreak/i,
                /deviceintegrity/i, /tamperdetect/i, /antiroot/i,
                /roothelper/i, /rootutil/i, /rootmanager/i
            ];
            Java.enumerateLoadedClassesSync().forEach(function(cn) {
                if (SKIP_RE.test(cn)) return;
                if (cn.charAt(0)==="[" || cn.indexOf("$Proxy")!==-1) return;
                try {
                    var C = Java.use(cn);
                    TARGET_METHODS.forEach(function(m) {
                        try {
                            if (!C[m] || typeof C[m].overloads==="undefined") return;
                            C[m].overloads.forEach(function(ol) {
                                if (!ol || typeof ol.implementation==="undefined") return;
                                var rt = ol.returnType ? ol.returnType.className : "";
                                ol.implementation = function() {
                                    console.log("[AA] -> Generic root bypass: " + cn + "." + m);
                                    if (rt==="boolean"||rt==="Boolean") return false;
                                    if (rt==="int"||rt==="Integer") return 0;
                                    return null;
                                };
                            });
                        } catch(e2) {}
                    });
                } catch(e) {}
            });
            console.log("[AA] + Generic root method scan complete");
        } catch(e) {}
    });
}, 3000);
'''

    # ------------------------------------------------------------------
    # Post-generation menu
    # ------------------------------------------------------------------

    def _post_generation_menu(self, script_path: Path) -> bool:
        while True:
            print(f"\n{Colors.CYAN}Options:{Colors.END}")
            print(f"  1. Execute & verify (recommended)")
            print(f"  2. Execute without verification")
            print(f"  3. Re-run analysis (different duration)")
            print(f"  4. Merge with custom script")
            print(f"  5. Save and return")
            print(f"  6. Exit")
            _, c = self.af.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 6)
            if c == 1:
                return self._execute_and_verify(script_path)
            elif c == 2:
                return self.af.execute_script(self.current_target, script_path)
            elif c == 3:
                print(f"Duration (30-120):")
                _, d = self.af.get_numeric_input("", 30, 120)
                return self.run_analysis_flow(self.current_target, duration=d)
            elif c == 4:
                r = self._merge_with_custom(script_path)
                if r:
                    return r
            elif c == 5:
                print(f"{Colors.GREEN}[+] Saved: {script_path}{Colors.END}")
                return True
            else:
                self.af._exit_program()
                return False  # unreachable; guards -> bool contract if _exit_program is mocked

    def _execute_and_verify(self, script_path: Path) -> bool:
        self._print_phase("Verification")
        self.af.kill_app(self.current_target.identifier)
        time.sleep(1)
        pid = self.af._launch_app(self.current_target.identifier)
        if not pid:
            print(f"{Colors.RED}[!] Failed to launch{Colors.END}")
            return False

        pid = self._wait_for_app(self.current_target.identifier) or pid
        cmd = ["frida", "-U", "-p", str(pid), "-l", str(script_path)]
        print(f"{Colors.GREEN}[*] Verifying bypass (20s)...{Colors.END}")
        print(f"{Colors.YELLOW}[*] Interact with app now!\n{Colors.END}")

        confirmed: List[str] = []
        failed: List[str] = []
        installed: List[str] = []
        stop_event = threading.Event()
        oq: queue.Queue = queue.Queue()
        proc: Optional[subprocess.Popen] = None

        try:
            proc = subprocess.Popen(cmd, **_make_popen_kwargs())
            threading.Thread(
                target=_read_pipe_into_queue, args=(proc.stdout, oq, stop_event), daemon=True
            ).start()
            start = time.time()
            while time.time() - start < 20:
                try:
                    line = oq.get(timeout=0.5)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                    continue
                if not line:
                    continue
                # Extract payload from Frida log envelope
                display_line = line
                if line.startswith("{"):
                    try:
                        envelope = json.loads(line)
                        if isinstance(envelope, dict) and envelope.get("type") == "log":
                            display_line = envelope.get("payload", line)
                    except (json.JSONDecodeError, ValueError):
                        pass

                if any(p in display_line for p in ("[AA]", "[AA-Shield]", "[AutoAnalyzer")):
                    if "->" in display_line:
                        confirmed.append(display_line)
                        print(f"  {Colors.GREEN}[TRIGGERED] {display_line}{Colors.END}")
                    elif "+ " in display_line or "installed" in display_line.lower():
                        installed.append(display_line)
                        print(f"  {Colors.CYAN}[INSTALLED]  {display_line}{Colors.END}")
                    elif "error" in display_line.lower() or "fail" in display_line.lower():
                        failed.append(display_line)
                        print(f"  {Colors.RED}[FAILED]     {display_line}{Colors.END}")
                    elif "not found" in display_line.lower():
                        print(f"  {Colors.YELLOW}[SKIPPED]    {display_line}{Colors.END}")
            print()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
        except Exception as exc:
            logger.error("Verification error: %s", exc)
            print(f"\n{Colors.RED}[!] Error: {exc}{Colors.END}")
        finally:
            stop_event.set()
            _terminate_process(proc)

        try:
            self.af.kill_app(self.current_target.identifier)
        except Exception as exc:
            logger.debug("Kill after verify: %s", exc)

        print(f"\n{Colors.PURPLE}  Results:{Colors.END}")
        print(f"  {Colors.CYAN}Installed:  {len(installed)}{Colors.END}")
        print(f"  {Colors.GREEN}Triggered:  {len(confirmed)}{Colors.END}")
        print(f"  {Colors.RED}Failed:     {len(failed)}{Colors.END}")
        if confirmed:
            print(f"\n{Colors.GREEN}[+] Bypass working! {len(confirmed)} bypassed.{Colors.END}")
        elif installed and not failed:
            print(f"\n{Colors.YELLOW}[*] Installed but not triggered yet. Try more interaction.{Colors.END}")
        else:
            print(f"\n{Colors.RED}[!] Issues detected. Re-run or use manual scripts.{Colors.END}")

        print(f"\n  1. Full session  2. Re-analyze  3. Menu  4. Exit")
        _, c = self.af.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 4)
        if c == 1:
            return self.af.execute_script(self.current_target, script_path)
        elif c == 2:
            return self.run_analysis_flow(self.current_target)
        elif c == 3:
            return True
        else:
            self.af._exit_program()
            return False  # unreachable; guards -> bool contract if _exit_program is mocked

    def _merge_with_custom(self, generated_path: Path) -> Optional[bool]:
        print(f"\n{Colors.CYAN}Path to custom .js (B=back):{Colors.END}")
        inp = self.af.safe_input(f"{Colors.YELLOW}> {Colors.END}")
        if not inp or inp.lower() == "b":
            return None
        cp = Path(inp.strip('"').strip("'"))
        if not cp.exists() or cp.suffix != ".js":
            print(f"{Colors.RED}[!] Invalid file{Colors.END}")
            return None
        try:
            gc = generated_path.read_text(encoding="utf-8")
            cc = cp.read_text(encoding="utf-8")
            merged = (
                gc
                + f"\n\n// === USER SCRIPT: {cp.name} ===\n"
                "setTimeout(function() {\n    Java.perform(function() {\n"
                "        console.log('[AA] Loading custom script...');\n"
                + cc
                + "\n    });\n}, 2000);\n"
            )
            mp = generated_path.parent / f"merged_{generated_path.name}"
            mp.write_text(merged, encoding="utf-8")
            print(f"{Colors.GREEN}[+] Merged: {mp}{Colors.END}")
            print(f"Execute now? (Y/N)")
            if self.af.get_valid_input(f"{Colors.YELLOW}> {Colors.END}", ["y", "n"]).lower() == "y":
                return self.af.execute_script(self.current_target, mp)
            return True
        except Exception as exc:
            logger.error("Merge failed: %s", exc)
            print(f"{Colors.RED}[!] Merge failed: {exc}{Colors.END}")
            return None

    def _handle_detection_failure(self) -> bool:
        print(f"\n{Colors.YELLOW}[!] No protections detected.{Colors.END}")
        print(f"Possible: custom protections, need more interaction, anti-Frida, lazy loading")
        if self.suspicious_classes:
            print(f"\n{Colors.CYAN}Suspicious ({len(self.suspicious_classes)}):{Colors.END}")
            for c in self.suspicious_classes[:10]:
                print(f"  {Colors.YELLOW}-> {c}{Colors.END}")
        print(f"\n  1. Retry (longer)  2. Generic bypass  3. Manual  4. Exit")
        _, c = self.af.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 4)
        if c == 1:
            print(f"  1. 60s  2. 90s  3. 120s")
            _, d = self.af.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 3)
            return self.run_analysis_flow(self.current_target, duration={1: 60, 2: 90, 3: 120}.get(d, 60))
        elif c == 2:
            return self._generate_generic_bypass()
        elif c == 3:
            return False
        else:
            self.af._exit_program()
            return False  # unreachable; guards -> bool contract if _exit_program is mocked

    def _generate_generic_bypass(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Generating generic bypass...{Colors.END}")
        self.findings = [
            ProtectionFinding("ssl_pinning",    "Generic_SSL",  "multiple", "multiple", 50, ["generic"], "custom_trustmanager"),
            ProtectionFinding("root_detection", "Generic_Root", "multiple", "multiple", 50, ["generic"], "generic_root"),
        ]
        self.detected_hooks.update(["trustmanager", "network_security", "file_exists"])
        sp = self._generate_bypass_script()
        return self._post_generation_menu(sp)

    def _cleanup_environment(self) -> None:
        try:
            self.af.kill_app(self.current_target.identifier)
        except Exception as exc:
            logger.debug("Cleanup kill: %s", exc)
        time.sleep(0.5)
        for f in Path(tempfile.gettempdir()).glob("aa_detect_*.js"):
            try:
                f.unlink()
            except Exception as exc:
                logger.debug("Cleanup temp file %s: %s", f, exc)


# ---------------------------------------------------------------------------
# Device manager (extracted from AutoFrida)
# ---------------------------------------------------------------------------
class DeviceManager:
    """Handles ADB device discovery and selection."""

    MAX_UNAUTHORIZED_RETRIES = 3

    def __init__(self, run_command_fn, safe_input_fn, get_numeric_input_fn):
        self._run_command = run_command_fn
        self._safe_input = safe_input_fn
        self._get_numeric_input = get_numeric_input_fn
        self.device: Optional[DeviceInfo] = None

    def detect(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Detecting devices...{Colors.END}")
        return self._detect_loop(retries=0)

    def _detect_loop(self, retries: int) -> bool:
        result = self._run_command(["adb", "devices", "-l"])
        lines = result.stdout.strip().split("\n")[1:]
        devices: List[DeviceInfo] = []
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            model = next((p.split(":")[1] for p in parts if p.startswith("model:")), "")
            devices.append(DeviceInfo(serial=serial, state=state, model=model))

        if not devices:
            print(f"{Colors.RED}[!] No devices connected{Colors.END}")
            return False

        unauthorized = [d for d in devices if d.state == "unauthorized"]
        if unauthorized and retries < self.MAX_UNAUTHORIZED_RETRIES:
            print(f"{Colors.YELLOW}[!] Device {unauthorized[0].serial} is unauthorized{Colors.END}")
            self._safe_input(f"{Colors.CYAN}    Press Enter after accepting RSA key...{Colors.END}")
            return self._detect_loop(retries + 1)

        connected = [d for d in devices if d.state == "device"]
        if not connected:
            print(f"{Colors.RED}[!] No authorized devices found{Colors.END}")
            return False

        if len(connected) == 1:
            self.device = connected[0]
        else:
            print(f"\n{Colors.CYAN}Multiple devices found:{Colors.END}")
            for i, dev in enumerate(connected, 1):
                print(f"  {i}. {dev.serial} ({dev.model or 'Unknown'})")
            _, value = self._get_numeric_input(
                f"\n{Colors.CYAN}Select device (1-{len(connected)}): {Colors.END}", 1, len(connected)
            )
            self.device = connected[value - 1]

        print(f"{Colors.GREEN}[+] Using device: {self.device.serial} ({self.device.model or 'Unknown'}){Colors.END}")
        return True


# ---------------------------------------------------------------------------
# Frida server manager (extracted from AutoFrida)
# ---------------------------------------------------------------------------
class FridaServerManager:
    """Handles Frida server lifecycle on the device."""

    FRIDA_SERVER_PATH = "/data/local/tmp/fridaserver"
    FRIDA_DEFAULT_PORT = 27042

    ARCH_MAP: Dict[str, str] = {
        "arm64-v8a":  "android-arm64",
        "armeabi-v7a": "android-arm",
        "x86":        "android-x86",
        "x86_64":     "android-x86_64",
    }

    def __init__(self, adb_command_fn, run_command_fn, device: DeviceInfo, frida_version: str):
        self._adb = adb_command_fn
        self._run = run_command_fn
        self.device = device
        self.frida_version = frida_version

    # ------------------------------------------------------------------
    # Status checks
    # ------------------------------------------------------------------

    def _check_process(self) -> Tuple[bool, Optional[int]]:
        print(f"{Colors.CYAN}    [Layer 1] Checking fridaserver process...{Colors.END}")
        for cmd in [
            ["shell", "pidof", "fridaserver"],
            ["shell", 'ps -A 2>/dev/null | grep -E "fridaserver|frida-server" | grep -v grep'],
        ]:
            try:
                result = self._adb(cmd, check=False, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    for token in result.stdout.strip().split():
                        try:
                            pid = int(token)
                            print(f"{Colors.GREEN}    [+] Layer 1 PASS: PID {pid}{Colors.END}")
                            return True, pid
                        except ValueError:
                            continue
            except Exception as exc:
                logger.debug("Process check cmd %s: %s", cmd, exc)
        print(f"{Colors.YELLOW}    [-] Layer 1 FAIL: process not found{Colors.END}")
        return False, None

    def _check_port(self) -> bool:
        port = self.FRIDA_DEFAULT_PORT
        print(f"{Colors.CYAN}    [Layer 2] Checking port {port}...{Colors.END}")
        for cmd in [
            f'ss -lntp 2>/dev/null | grep ":{port}"',
            f'netstat -tlnp 2>/dev/null | grep ":{port}"',
        ]:
            try:
                result = self._adb(["shell", cmd], check=False, timeout=5)
                if result.returncode == 0 and str(port) in result.stdout:
                    print(f"{Colors.GREEN}    [+] Layer 2 PASS: Port {port} listening{Colors.END}")
                    return True
            except Exception as exc:
                logger.debug("Port check: %s", exc)
        try:
            hex_port = format(port, "X").upper()
            result = self._adb(["shell", f'cat /proc/net/tcp 2>/dev/null | grep ":{hex_port}"'], check=False, timeout=5)
            if result.returncode == 0 and result.stdout.strip():
                print(f"{Colors.GREEN}    [+] Layer 2 PASS: Port found in /proc/net/tcp{Colors.END}")
                return True
        except Exception as exc:
            logger.debug("Proc/net/tcp check: %s", exc)
        print(f"{Colors.YELLOW}    [-] Layer 2 FAIL: Port not listening{Colors.END}")
        return False

    def _check_protocol(self) -> bool:
        print(f"{Colors.CYAN}    [Layer 3] Checking Frida protocol...{Colors.END}")
        try:
            result = self._run(["frida-ps", "-U", "--json"], check=False, timeout=10)
            if result.returncode != 0:
                print(f"{Colors.YELLOW}    [-] Layer 3 FAIL: frida-ps error{Colors.END}")
                return False
            output = result.stdout.strip()
            if not output or not (output.startswith("[") or output.startswith("{")):
                print(f"{Colors.YELLOW}    [-] Layer 3 FAIL: Invalid response{Colors.END}")
                return False
            parsed = json.loads(output)
            count = len(parsed) if isinstance(parsed, list) else 1
            print(f"{Colors.GREEN}    [+] Layer 3 PASS: Protocol OK ({count} processes){Colors.END}")
            return True
        except json.JSONDecodeError:
            print(f"{Colors.YELLOW}    [-] Layer 3 FAIL: JSON error{Colors.END}")
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}    [-] Layer 3 FAIL: Timeout{Colors.END}")
        except Exception as exc:
            print(f"{Colors.YELLOW}    [-] Layer 3 FAIL: {exc}{Colors.END}")
        return False

    def get_status(self) -> FridaServerStatus:
        print(f"\n{Colors.BLUE}[*] 3-layer Frida server validation...{Colors.END}")
        status = FridaServerStatus()
        running, pid = self._check_process()
        status.process_running = running
        status.process_pid = pid
        if not running:
            status.error_message = "Process not running"
            return status
        status.port_bound = self._check_port()
        if not status.port_bound:
            status.error_message = "Port not bound"
            return status
        status.protocol_ok = self._check_protocol()
        if not status.protocol_ok:
            status.error_message = "Protocol handshake failed"
        return status

    def is_running(self) -> bool:
        status = self.get_status()
        if status.is_fully_operational:
            print(f"{Colors.GREEN}[+] Frida server is fully operational!{Colors.END}")
            return True
        print(f"{Colors.YELLOW}[!] Frida server validation failed: {status.error_message}{Colors.END}")
        return False

    def kill(self) -> bool:
        print(f"{Colors.CYAN}    Killing Frida server processes...{Colors.END}")
        cmds = (
            ['shell', 'su -c "pkill -9 -f fridaserver"'],
            ['shell', 'su -c "pkill -9 -f frida-server"'],
        ) if self.device.is_rooted else (
            ['shell', 'pkill -9 -f fridaserver'],
            ['shell', 'pkill -9 -f frida-server'],
        )
        for cmd in cmds:
            try:
                self._adb(cmd, check=False, timeout=5)
            except Exception as exc:
                logger.debug("Kill frida server: %s", exc)
        time.sleep(1)
        running, _ = self._check_process()
        if not running:
            print(f"{Colors.GREEN}    [+] Killed successfully{Colors.END}")
            return True
        return False

    def is_on_device(self) -> bool:
        result = self._adb(["shell", f"ls -la {self.FRIDA_SERVER_PATH}"], check=False)
        if result.returncode == 0 and "No such file" not in result.stdout:
            print(f"{Colors.GREEN}[+] Frida server binary found on device{Colors.END}")
            return True
        print(f"{Colors.YELLOW}[!] Frida server not found on device{Colors.END}")
        return False

    def get_local_path(self) -> Optional[Path]:
        for f in Path(".").glob("frida-server-*"):
            if f.is_file() and f.suffix != ".xz":
                print(f"{Colors.GREEN}[+] Found local: {f}{Colors.END}")
                return f
        return None

    def download(self) -> Optional[Path]:
        print(f"\n{Colors.BLUE}[*] Downloading Frida server...{Colors.END}")
        filename = f"frida-server-{self.frida_version}-{self.device.architecture}.xz"
        url = f"https://github.com/frida/frida/releases/download/{self.frida_version}/{filename}"
        print(f"{Colors.CYAN}    URL: {url}{Colors.END}")
        xz_path = Path(filename)
        server_path = Path(f"frida-server-{self.frida_version}-{self.device.architecture}")
        if server_path.exists():
            print(f"{Colors.GREEN}[+] Already exists locally{Colors.END}")
            return server_path
        for attempt in range(1, 4):
            try:
                print(f"{Colors.CYAN}    Attempt {attempt}/3...{Colors.END}")
                request = Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urlopen(request, timeout=60) as response:
                    total = int(response.headers.get("content-length", 0))
                    downloaded = 0
                    with open(xz_path, "wb") as f:
                        while True:
                            chunk = response.read(8192)
                            if not chunk:
                                break
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total:
                                pct = (downloaded / total) * 100
                                bar = "#" * int(pct // 2) + "-" * (50 - int(pct // 2))
                                print(f"\r    [{bar}] {pct:.1f}%", end="", flush=True)
                    print()
                print(f"{Colors.CYAN}    Extracting...{Colors.END}")
                with lzma.open(xz_path, "rb") as xz_file:
                    with open(server_path, "wb") as out_file:
                        shutil.copyfileobj(xz_file, out_file)
                xz_path.unlink()
                print(f"{Colors.GREEN}[+] Downloaded{Colors.END}")
                return server_path
            except (URLError, HTTPError) as exc:
                logger.warning("Download attempt %d failed: %s", attempt, exc)
                print(f"{Colors.YELLOW}[!] Attempt {attempt} failed: {exc}{Colors.END}")
                if attempt < 3:
                    time.sleep(2)
            except Exception as exc:
                logger.error("Download error: %s", exc)
                print(f"{Colors.RED}[!] Error: {exc}{Colors.END}")
                if xz_path.exists():
                    xz_path.unlink(missing_ok=True)
                return None
        print(f"{Colors.RED}[!] Download failed{Colors.END}")
        return None

    def push(self, local_path: Path) -> bool:
        print(f"\n{Colors.BLUE}[*] Pushing Frida server to device...{Colors.END}")
        try:
            self._adb(["push", str(local_path), self.FRIDA_SERVER_PATH])
            print(f"{Colors.GREEN}[+] Pushed to {self.FRIDA_SERVER_PATH}{Colors.END}")
            self._adb(["shell", "chmod", "755", self.FRIDA_SERVER_PATH])
            print(f"{Colors.GREEN}[+] Permissions set{Colors.END}")
            return True
        except Exception as exc:
            logger.error("Push failed: %s", exc)
            print(f"{Colors.RED}[!] Push failed: {exc}{Colors.END}")
            return False

    def start(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Starting Frida server...{Colors.END}")
        self.kill()
        try:
            cmd_str = (
                f'su -c "{self.FRIDA_SERVER_PATH} -D"'
                if self.device.is_rooted
                else f"{self.FRIDA_SERVER_PATH} -D"
            )
            subprocess.Popen(
                ["adb", "-s", self.device.serial, "shell", cmd_str],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            for attempt in range(1, 6):
                time.sleep(2)
                print(f"{Colors.CYAN}    Validation {attempt}/5...{Colors.END}")
                status = self.get_status()
                if status.is_fully_operational:
                    print(f"{Colors.GREEN}[+] Frida server started successfully!{Colors.END}")
                    return True
                if not status.process_running and attempt > 2:
                    break
            print(f"{Colors.RED}[!] Frida server failed to start{Colors.END}")
            return False
        except Exception as exc:
            logger.error("Start frida server: %s", exc)
            print(f"{Colors.RED}[!] Error: {exc}{Colors.END}")
            return False

    def ensure(self) -> bool:
        print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.END}")
        print(f"{Colors.PURPLE}  Smart Frida Server Lifecycle{Colors.END}")
        print(f"{Colors.PURPLE}{'=' * 60}{Colors.END}")
        status = self.get_status()
        if status.is_fully_operational:
            print(f"\n{Colors.GREEN}[+] Already operational{Colors.END}")
            return True
        if status.needs_restart:
            self.kill()
            time.sleep(1)
        if self.is_on_device():
            if self.start():
                return True
        local = self.get_local_path() or self.download()
        if not local:
            return False
        if not self.push(local):
            return False
        return self.start()


# ---------------------------------------------------------------------------
# Main application class
# ---------------------------------------------------------------------------
class AutoFrida:
    """
    Orchestrates the overall Auto Frida workflow.
    Delegates device management, Frida server lifecycle, and analysis to
    dedicated sub-objects.
    """

    SCRIPTS_DIR = Path("scripts")
    LOGS_DIR    = Path("logs")
    GO_BACK       = "GO_BACK"
    EXIT_PROGRAM  = "EXIT_PROGRAM"
    CODESHARE_PREFIX = "codeshare:"

    def __init__(self) -> None:
        self.frida_version: str = ""
        self.device: Optional[DeviceInfo] = None
        self.apps: List[AppInfo] = []
        self._device_manager: Optional[DeviceManager] = None
        self._server_manager: Optional[FridaServerManager] = None
        self._ensure_directories()
        logger.info("Auto Frida v%s initialized by %s", __version__, __author__)

    def _ensure_directories(self) -> None:
        self.SCRIPTS_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # UI helpers
    # ------------------------------------------------------------------

    def _exit_program(self) -> NoReturn:
        print(f"\n{Colors.GREEN}{'=' * 60}{Colors.END}")
        print(f"{Colors.GREEN}  Auto Frida Session Complete - Goodbye!{Colors.END}")
        print(f"{Colors.GREEN}  Created by: {__author__}{Colors.END}")
        print(f"{Colors.GREEN}{'=' * 60}{Colors.END}")
        sys.exit(0)

    def safe_input(self, prompt: str) -> str:
        try:
            return input(prompt).strip()
        except EOFError:
            return ""
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[*] Operation cancelled by user{Colors.END}")
            return ""

    def get_valid_input(
        self,
        prompt: str,
        valid_options: List[str],
        case_sensitive: bool = False,
        allow_empty: bool = False,
    ) -> str:
        while True:
            user_input = self.safe_input(prompt)
            if not user_input and not allow_empty:
                print(f"{Colors.RED}[!] Please enter a valid option{Colors.END}")
                continue
            check_input = user_input if case_sensitive else user_input.lower()
            check_options = valid_options if case_sensitive else [o.lower() for o in valid_options]
            if check_input in check_options:
                return user_input
            print(f"{Colors.RED}[!] Valid options: {', '.join(valid_options)}{Colors.END}")

    def get_numeric_input(
        self,
        prompt: str,
        min_val: int,
        max_val: int,
        allow_special: Optional[List[str]] = None,
    ) -> Tuple[bool, object]:
        allow_special = allow_special or []
        while True:
            user_input = self.safe_input(prompt)
            if not user_input:
                print(f"{Colors.RED}[!] Please enter a valid option{Colors.END}")
                continue
            if allow_special and user_input.lower() in [s.lower() for s in allow_special]:
                return False, user_input.lower()
            try:
                num = int(user_input)
                if min_val <= num <= max_val:
                    return True, num
                extras = f" or {'/'.join(allow_special)}" if allow_special else ""
                print(f"{Colors.RED}[!] Enter {min_val}-{max_val}{extras}{Colors.END}")
            except ValueError:
                extras = f" or {'/'.join(allow_special)}" if allow_special else ""
                print(f"{Colors.RED}[!] Enter a number{extras}{Colors.END}")

    def print_banner(self) -> None:
        banner = f"""
{Colors.CYAN}+========================================================================+
|                                                                          |
|   {Colors.GREEN} AUTO FRIDA v{__version__} - Android Security Testing Automation{Colors.CYAN}            |
|   {Colors.YELLOW} Created by: {__author__}{Colors.CYAN}                                        |
|                                                                          |
|   {Colors.PURPLE}> Auto Frida Installation    > SSL Pinning Bypass{Colors.CYAN}                    |
|   {Colors.PURPLE}> Root Detection Bypass      > Auto Analyzer v2 (Enhanced){Colors.CYAN}           |
|   {Colors.PURPLE}> Frida CodeShare Support    > Custom Script Support{Colors.CYAN}                 |
|   {Colors.PURPLE}> Anti-Frida Shield          > Class Enumeration{Colors.CYAN}                     |
|                                                                          |
+========================================================================+{Colors.END}
"""
        print(banner)

    # ------------------------------------------------------------------
    # Command runners
    # ------------------------------------------------------------------

    def run_command(
        self,
        cmd: List[str],
        check: bool = True,
        capture: bool = True,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                cmd,
                capture_output=capture,
                text=True,
                check=check,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out: %s", " ".join(cmd))
            raise
        except subprocess.CalledProcessError as exc:
            logger.error("Command failed: %s — %s", " ".join(cmd), exc.stderr)
            raise

    def adb_command(
        self,
        args: List[str],
        check: bool = True,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess:
        cmd = ["adb"]
        if self.device:
            cmd.extend(["-s", self.device.serial])
        cmd.extend(args)
        return self.run_command(cmd, check=check, timeout=timeout)

    # ------------------------------------------------------------------
    # Environment checks
    # ------------------------------------------------------------------

    def check_python(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Checking Python version...{Colors.END}")
        v = sys.version_info
        if v.major < 3 or (v.major == 3 and v.minor < 8):
            print(f"{Colors.RED}[!] Python 3.8+ required. Current: {v.major}.{v.minor}{Colors.END}")
            return False
        print(f"{Colors.GREEN}[+] Python {v.major}.{v.minor}.{v.micro}{Colors.END}")
        return True

    def check_pip(self) -> bool:
        print(f"{Colors.BLUE}[*] Checking pip...{Colors.END}")
        try:
            self.run_command(["pip", "--version"])
            print(f"{Colors.GREEN}[+] pip available{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.RED}[!] pip not found. Install it via: python -m ensurepip --upgrade{Colors.END}")
            return False

    def check_frida(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Checking Frida installation...{Colors.END}")
        try:
            result = self.run_command(["frida", "--version"])
            self.frida_version = result.stdout.strip()
            print(f"{Colors.GREEN}[+] Frida {self.frida_version}{Colors.END}")
            try:
                if int(self.frida_version.split(".")[0]) >= 16:
                    print(f"{Colors.CYAN}    i Frida 16+ detected{Colors.END}")
            except (ValueError, IndexError):
                pass
            self.run_command(["frida-ps", "--version"])
            print(f"{Colors.GREEN}[+] Frida-tools available{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.YELLOW}[!] Frida not found. Installing...{Colors.END}")
            return self._install_frida()

    def _install_frida(self) -> bool:
        try:
            print(f"{Colors.BLUE}[*] Installing frida and frida-tools...{Colors.END}")
            self.run_command(["pip", "install", "frida", "frida-tools"], timeout=120)
            result = self.run_command(["frida", "--version"])
            self.frida_version = result.stdout.strip()
            print(f"{Colors.GREEN}[+] Installed Frida {self.frida_version}{Colors.END}")
            return True
        except Exception as exc:
            logger.error("Frida install failed: %s", exc)
            print(f"{Colors.RED}[!] Failed to install Frida: {exc}{Colors.END}")
            return False

    def check_adb(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Checking ADB...{Colors.END}")
        try:
            result = self.run_command(["adb", "version"])
            print(f"{Colors.GREEN}[+] {result.stdout.split(chr(10))[0]}{Colors.END}")
            return True
        except Exception:
            print(f"{Colors.RED}[!] ADB not found. Install Android SDK Platform Tools{Colors.END}")
            return False

    # ------------------------------------------------------------------
    # Device detection (delegates to DeviceManager)
    # ------------------------------------------------------------------

    def detect_device(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Detecting devices...{Colors.END}")
        self._device_manager = DeviceManager(self.run_command, self.safe_input, self.get_numeric_input)
        result = self._device_manager.detect()
        if result:
            self.device = self._device_manager.device
        return result

    def detect_architecture(self) -> bool:
        if self.device is None:
            logger.error("detect_architecture called before detect_device")
            return False
        print(f"\n{Colors.BLUE}[*] Detecting CPU architecture...{Colors.END}")
        result = self.adb_command(["shell", "getprop", "ro.product.cpu.abi"])
        abi = result.stdout.strip()
        arch_map = FridaServerManager.ARCH_MAP
        if abi not in arch_map:
            print(f"{Colors.RED}[!] Unknown architecture: {abi}{Colors.END}")
            return False
        self.device.architecture = arch_map[abi]
        print(f"{Colors.GREEN}[+] Architecture: {abi} -> {self.device.architecture}{Colors.END}")
        return True

    def check_root_access(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Checking root access...{Colors.END}")
        try:
            result = self.adb_command(["shell", "which su"], check=False)
            if result.returncode == 0 and result.stdout.strip():
                print(f"{Colors.GREEN}[+] Root binary found: {result.stdout.strip()}{Colors.END}")
                result = self.adb_command(["shell", "su -c id"], check=False)
                if result.returncode == 0 and "uid=0" in result.stdout:
                    print(f"{Colors.GREEN}[+] Root access confirmed{Colors.END}")
                    self.device.is_rooted = True
                    return True
                print(f"{Colors.YELLOW}[!] Root binary exists but access denied{Colors.END}")
        except subprocess.TimeoutExpired:
            print(f"{Colors.YELLOW}[!] Root check timed out{Colors.END}")
        except Exception as exc:
            logger.debug("Root check: %s", exc)
        print(f"{Colors.YELLOW}[!] Device may not be rooted{Colors.END}")
        self.device.is_rooted = False
        return True

    def check_selinux(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Checking SELinux status...{Colors.END}")
        try:
            result = self.adb_command(["shell", "getenforce"], check=False)
            status = result.stdout.strip().lower()
            if status == "enforcing":
                print(f"{Colors.YELLOW}[!] SELinux is Enforcing{Colors.END}")
                self.device.selinux_enforcing = True
                if self.device.is_rooted:
                    self.adb_command(["shell", "su -c setenforce 0"], check=False)
                    result = self.adb_command(["shell", "getenforce"], check=False)
                    if result.stdout.strip().lower() == "permissive":
                        print(f"{Colors.GREEN}[+] SELinux set to Permissive{Colors.END}")
                        self.device.selinux_enforcing = False
            elif status in ("permissive", "disabled"):
                print(f"{Colors.GREEN}[+] SELinux is {status.capitalize()}{Colors.END}")
                self.device.selinux_enforcing = False
        except Exception as exc:
            logger.warning("SELinux check failed: %s", exc)
        return True

    # ------------------------------------------------------------------
    # Frida server lifecycle (delegates to FridaServerManager)
    # ------------------------------------------------------------------

    def _get_server_manager(self) -> FridaServerManager:
        if self._server_manager is None:
            self._server_manager = FridaServerManager(
                self.adb_command, self.run_command, self.device, self.frida_version
            )
        return self._server_manager

    def ensure_frida_server(self) -> bool:
        return self._get_server_manager().ensure()

    def is_frida_server_running(self) -> bool:
        return self._get_server_manager().is_running()

    def kill_frida_server(self) -> bool:
        return self._get_server_manager().kill()

    def get_frida_server_status(self) -> FridaServerStatus:
        return self._get_server_manager().get_status()

    # ------------------------------------------------------------------
    # App management
    # ------------------------------------------------------------------

    def enumerate_apps(self) -> bool:
        print(f"\n{Colors.BLUE}[*] Enumerating apps...{Colors.END}")
        try:
            result = self.run_command(["frida-ps", "-Uai"])
            self.apps = []
            for line in result.stdout.strip().split("\n")[2:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) >= 3:
                    try:
                        pid_str = parts[0]
                        pid = int(pid_str) if pid_str != "-" else None
                        identifier = parts[-1]
                        name = " ".join(parts[1:-1])
                        self.apps.append(AppInfo(pid=pid, name=name, identifier=identifier))
                    except (ValueError, IndexError):
                        continue
            print(f"{Colors.GREEN}[+] Found {len(self.apps)} apps{Colors.END}")
            return True
        except Exception as exc:
            logger.error("App enumeration failed: %s", exc)
            print(f"{Colors.RED}[!] Failed: {exc}{Colors.END}")
            return False

    def display_apps(self, filter_running: bool = False) -> List[AppInfo]:
        apps_to_show = [a for a in self.apps if a.pid is not None] if filter_running else self.apps
        print(f"\n{Colors.CYAN}{'#':>4}  {'PID':>6}  {'Identifier':<45}  Name{Colors.END}")
        print(f"{Colors.CYAN}{'-' * 90}{Colors.END}")
        for i, app in enumerate(apps_to_show, 1):
            pid_str = str(app.pid) if app.pid else "-"
            st = f"{Colors.GREEN}*{Colors.END}" if app.pid else f"{Colors.YELLOW}o{Colors.END}"
            ident = app.identifier[:43] + ".." if len(app.identifier) > 45 else app.identifier
            nm = app.name[:30] + ".." if len(app.name) > 32 else app.name
            print(f"{i:>4}  {pid_str:>6}  {ident:<45}  {st} {nm}")
        return apps_to_show

    def select_target(self) -> Optional[AppInfo]:
        while True:
            print(f"\n{Colors.CYAN}Filter:{Colors.END}")
            print(f"  1. All apps  2. Running only  B. Refresh  X. Exit")
            fc = self.get_valid_input(f"{Colors.YELLOW}> {Colors.END}", ["1", "2", "b", "x"])
            if fc.lower() == "b":
                self.enumerate_apps()
                continue
            if fc.lower() == "x":
                self._exit_program()
            apps = self.display_apps(filter_running=(fc == "2"))
            if not apps:
                print(f"{Colors.YELLOW}[!] No apps found{Colors.END}")
                continue
            print(f"\n{Colors.CYAN}Enter number (1-{len(apps)}), package name, B=back, X=exit:{Colors.END}")
            sel = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            if not sel:
                continue
            if sel.lower() == "b":
                continue
            if sel.lower() == "x":
                self._exit_program()
            try:
                idx = int(sel)
                if 1 <= idx <= len(apps):
                    print(f"{Colors.GREEN}[+] Selected: {apps[idx-1].identifier}{Colors.END}")
                    return apps[idx - 1]
                continue
            except ValueError:
                pass
            for app in self.apps:
                if app.identifier == sel:
                    print(f"{Colors.GREEN}[+] Selected: {app.identifier}{Colors.END}")
                    return app
            matches = [a for a in self.apps if sel.lower() in a.identifier.lower()]
            if len(matches) == 1:
                print(f"{Colors.GREEN}[+] Selected: {matches[0].identifier}{Colors.END}")
                return matches[0]
            elif len(matches) > 1:
                print(f"{Colors.YELLOW}[!] Multiple matches, be more specific{Colors.END}")
            else:
                print(f"{Colors.RED}[!] Not found: {sel}{Colors.END}")

    def _get_app_pid(self, identifier: str) -> Optional[int]:
        for cmd in [
            ["shell", f"pidof {identifier}"],
            ["shell", f"ps -A 2>/dev/null | grep {identifier} | grep -v grep"],
        ]:
            try:
                result = self.adb_command(cmd, check=False, timeout=5)
                if result.returncode == 0 and result.stdout.strip():
                    for token in result.stdout.strip().split():
                        try:
                            return int(token)
                        except ValueError:
                            continue
            except Exception as exc:
                logger.debug("Get PID cmd %s: %s", cmd, exc)
        return None

    def kill_app(self, identifier: str) -> bool:
        print(f"{Colors.CYAN}    Force stopping {identifier}...{Colors.END}")
        try:
            self.adb_command(["shell", "am", "force-stop", identifier], check=False, timeout=10)
            time.sleep(1)
            pid = self._get_app_pid(identifier)
            if pid is None:
                print(f"{Colors.GREEN}    [+] Stopped{Colors.END}")
                return True
            is_rooted = self.device.is_rooted if self.device is not None else False
            kill_cmd = f'su -c "kill -9 {pid}"' if is_rooted else f"kill -9 {pid}"
            self.adb_command(["shell", kill_cmd], check=False, timeout=5)
            time.sleep(1)
            return self._get_app_pid(identifier) is None
        except Exception as exc:
            logger.warning("Kill app %s: %s", identifier, exc)
            print(f"{Colors.YELLOW}    [!] Error: {exc}{Colors.END}")
            return False

    def _launch_app(self, identifier: str) -> Optional[int]:
        print(f"{Colors.CYAN}    Launching {identifier}...{Colors.END}")
        try:
            self.adb_command(
                ["shell", "monkey", "-p", identifier, "-c", "android.intent.category.LAUNCHER", "1"],
                check=False, timeout=10,
            )
            for attempt in range(1, 6):
                time.sleep(1)
                pid = self._get_app_pid(identifier)
                if pid:
                    print(f"{Colors.GREEN}    [+] Started (PID: {pid}){Colors.END}")
                    return pid
            print(f"{Colors.YELLOW}    [!] App may not have started{Colors.END}")
            return None
        except Exception as exc:
            logger.warning("Launch app %s: %s", identifier, exc)
            print(f"{Colors.YELLOW}    [!] Error: {exc}{Colors.END}")
            return None

    # ------------------------------------------------------------------
    # Script selection
    # ------------------------------------------------------------------

    def get_available_scripts(self) -> List[Dict]:
        scripts: List[Dict] = []
        mp = self.SCRIPTS_DIR / "scripts.json"
        if mp.exists():
            try:
                with open(mp, encoding="utf-8") as f:
                    scripts = json.load(f)
            except json.JSONDecodeError as exc:
                logger.warning("scripts.json parse error: %s", exc)
        if not scripts:
            for js in self.SCRIPTS_DIR.glob("*.js"):
                scripts.append({"name": js.stem.replace("_", " ").title(), "file": js.name})
        if not scripts:
            scripts = [
                {"name": "Universal SSL Pinning Bypass", "file": "ssl_pinning_bypass.js"},
                {"name": "Root Detection Bypass",        "file": "root_bypass.js"},
                {"name": "Flutter SSL Pinning Bypass",   "file": "flutter_ssl_bypass.js"},
                {"name": "Anti Debug / Emulator Bypass", "file": "anti_debug_bypass.js"},
            ]
        return scripts

    def select_script(self) -> object:
        scripts = self.get_available_scripts()
        while True:
            print(f"\n{Colors.CYAN}Available Scripts:{Colors.END}")
            for i, s in enumerate(scripts, 1):
                sp = self.SCRIPTS_DIR / s["file"]
                ex = f"{Colors.GREEN}[+]{Colors.END}" if sp.exists() else f"{Colors.RED}[x]{Colors.END}"
                print(f"  {i}. {s['name']} {ex}")
            print(f"\n  {Colors.GREEN}AA.{Colors.END} Auto Analyzer v2 (Auto-Detect & Bypass)")
            print(f"  C. Custom  B. Back  X. Exit")
            c = self.safe_input(f"{Colors.YELLOW}> {Colors.END}").lower().strip()
            if not c:
                continue
            if c == "b":
                return None
            if c == "x":
                self._exit_program()
            if c == "aa":
                return AutoAnalyzerSentinel()
            if c == "c":
                r = self._handle_custom_script_menu()
                if r != self.GO_BACK:
                    return r
                continue
            try:
                idx = int(c)
                if 1 <= idx <= len(scripts):
                    sp = self.SCRIPTS_DIR / scripts[idx - 1]["file"]
                    if sp.exists():
                        print(f"{Colors.GREEN}[+] Selected: {scripts[idx-1]['name']}{Colors.END}")
                        return sp
                    print(f"{Colors.RED}[!] File not found: {sp}{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}[!] Invalid option{Colors.END}")

    def execute_script(self, target: AppInfo, script: object) -> bool:
        if isinstance(script, AutoAnalyzerSentinel):
            print(f"\n{Colors.CYAN}{'=' * 60}{Colors.END}")
            print(f"{Colors.CYAN}  Auto Analyzer v2 - Automatic Protection Analysis{Colors.END}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
            aa = AutoAnalyzerModule(self)
            result = aa.run_analysis_flow(target)
            if result is False:
                new_script = self.select_script()
                if new_script is None:
                    return False
                return self.execute_script(target, new_script)
            return result

        is_codeshare = isinstance(script, str) and script.startswith(self.CODESHARE_PREFIX)
        if is_codeshare:
            print(f"\n{Colors.GREEN}[*] CodeShare: {script[len(self.CODESHARE_PREFIX):]}{Colors.END}")
        else:
            print(f"\n{Colors.GREEN}[*] Script: {script}{Colors.END}")

        while True:
            current_pid = self._get_app_pid(target.identifier)
            print(f"\n{Colors.CYAN}Mode:{Colors.END}")
            print(f"  1. Spawn  2. Attach  B. Back  X. Exit")
            if current_pid:
                print(f"{Colors.GREEN}    App running (PID: {current_pid}){Colors.END}")
            else:
                print(f"{Colors.YELLOW}    App not running{Colors.END}")
            is_num, value = self.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 2, allow_special=["b", "x"])
            if not is_num:
                if value == "b":
                    return False
                if value == "x":
                    self._exit_program()
            mode = str(value)

            if is_codeshare:
                cs = script[len(self.CODESHARE_PREFIX):]
                if mode == "1":
                    if current_pid:
                        self.kill_app(target.identifier)
                        time.sleep(2)
                    cmd = ["frida", "-U", "--codeshare", cs, "-f", target.identifier]
                else:
                    if not current_pid:
                        current_pid = self._launch_app(target.identifier)
                        if not current_pid:
                            continue
                        time.sleep(2)
                    cmd = ["frida", "-U", "--codeshare", cs, "-p", str(current_pid)]
            else:
                if mode == "1":
                    if current_pid:
                        self.kill_app(target.identifier)
                        time.sleep(2)
                    cmd = ["frida", "-U", "-f", target.identifier, "-l", str(script)]
                else:
                    if not current_pid:
                        current_pid = self._launch_app(target.identifier)
                        if not current_pid:
                            continue
                        time.sleep(2)
                    cmd = ["frida", "-U", "-p", str(current_pid), "-l", str(script)]

            print(f"\n{Colors.PURPLE}[*] {' '.join(cmd)}{Colors.END}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.END}")
            print(f"{Colors.GREEN}[*] Auto Frida v{__version__} session starting...{Colors.END}")
            print(f"{Colors.YELLOW}[*] Press Ctrl+C to stop{Colors.END}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.END}\n")
            try:
                result = subprocess.run(cmd)
                if result.returncode != 0:
                    print(f"\n{Colors.YELLOW}[!] Exited with code {result.returncode}{Colors.END}")
                return True
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Session terminated{Colors.END}")
                return True
            except Exception as exc:
                em = str(exc).lower()
                if "unable to find process" in em:
                    print(f"\n{Colors.RED}[!] Process not found{Colors.END}")
                elif "gadget" in em or "jailed" in em:
                    print(f"\n{Colors.RED}[!] Not rooted - use Attach mode{Colors.END}")
                else:
                    logger.error("Frida execution error: %s", exc)
                    print(f"\n{Colors.RED}[!] Error: {exc}{Colors.END}")
                print(f"\n  1. Retry  2. Back  3. Exit")
                _, rc = self.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 3)
                if rc == 1:
                    continue
                elif rc == 2:
                    return False
                else:
                    self._exit_program()

    # ------------------------------------------------------------------
    # CodeShare helpers
    # ------------------------------------------------------------------

    def show_codeshare_examples(self) -> None:
        print(f"\n{Colors.CYAN}Popular CodeShare Scripts:{Colors.END}")
        for sid, desc in [
            ("pcipolloni/universal-android-ssl-pinning-bypass-with-frida", "Universal SSL Bypass"),
            ("dzonerzy/fridantiroot", "Root Detection Bypass"),
            ("akabe1/frida-multiple-unpinning", "Multiple SSL Unpinning"),
        ]:
            print(f"  {Colors.GREEN}*{Colors.END} {sid} - {Colors.YELLOW}{desc}{Colors.END}")

    def validate_codeshare_script(self, script_name: str) -> Optional[str]:
        script_name = script_name.strip().lstrip("@").rstrip("/")
        if "/" not in script_name:
            print(f"{Colors.RED}[!] Format: author/script-name{Colors.END}")
            return None
        parts = script_name.split("/")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            print(f"{Colors.RED}[!] Invalid format{Colors.END}")
            return None
        return script_name

    def _handle_codeshare_selection(self) -> object:
        self.show_codeshare_examples()
        while True:
            print(f"\n{Colors.CYAN}Enter CodeShare script (author/name), B=back, X=exit:{Colors.END}")
            name = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            if not name:
                continue
            if name.lower() == "b":
                return self.GO_BACK
            if name.lower() == "x":
                self._exit_program()
            validated = self.validate_codeshare_script(name)
            if validated:
                return f"{self.CODESHARE_PREFIX}{validated}"

    def _handle_local_script(self) -> object:
        while True:
            print(f"\n{Colors.CYAN}Enter path to .js file, B=back, X=exit:{Colors.END}")
            p = self.safe_input(f"{Colors.YELLOW}> {Colors.END}")
            if not p:
                continue
            if p.lower() == "b":
                return self.GO_BACK
            if p.lower() == "x":
                self._exit_program()
            path = Path(p.strip('"').strip("'"))
            if path.exists() and path.suffix == ".js":
                print(f"{Colors.GREEN}[+] Using: {path}{Colors.END}")
                return path
            print(f"{Colors.RED}[!] Invalid file{Colors.END}")

    def _handle_custom_script_menu(self) -> object:
        while True:
            print(f"\n{Colors.CYAN}Custom Script:{Colors.END}")
            print(f"  1. CodeShare  2. Local file  B. Back  X. Exit")
            c = self.get_valid_input(f"{Colors.YELLOW}> {Colors.END}", ["1", "2", "b", "x"])
            if c.lower() == "b":
                return self.GO_BACK
            if c.lower() == "x":
                self._exit_program()
            if c == "1":
                r = self._handle_codeshare_selection()
                if r != self.GO_BACK:
                    return r
            elif c == "2":
                r = self._handle_local_script()
                if r != self.GO_BACK:
                    return r

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    def run(self) -> None:
        self.print_banner()

        # Validate all JS script files exist before doing anything else
        if not BypassScripts.validate_all():
            print(f"{Colors.RED}[!] Missing JS script files in '{BypassScripts.JS_DIR}'.{Colors.END}")
            print(f"{Colors.YELLOW}    Ensure the 'js_scripts/' folder is next to auto_frida.py.{Colors.END}")
            sys.exit(1)

        def _phase(label: str) -> None:
            print(f"\n{Colors.PURPLE}{'=' * 60}{Colors.END}")
            print(f"{Colors.PURPLE}  {label}{Colors.END}")
            print(f"{Colors.PURPLE}{'=' * 60}{Colors.END}")

        _phase("PHASE 1: Environment Validation")
        if not self.check_python():
            sys.exit(1)
        if not self.check_pip():
            sys.exit(1)
        if not self.check_frida():
            sys.exit(1)

        _phase("PHASE 2: ADB & Device Detection")
        if not self.check_adb():
            sys.exit(1)
        if not self.detect_device():
            sys.exit(1)

        _phase("PHASE 3: Device Analysis")
        if not self.detect_architecture():
            sys.exit(1)
        self.check_root_access()
        self.check_selinux()
        if not self.ensure_frida_server():
            print(f"{Colors.RED}[!] Failed to setup Frida server{Colors.END}")
            sys.exit(1)

        _phase("PHASE 4: App Enumeration")
        if not self.enumerate_apps():
            sys.exit(1)

        while True:
            _phase("PHASE 5: Target Selection")
            target = self.select_target()
            if not target:
                continue
            while True:
                _phase("PHASE 6: Script Selection")
                script = self.select_script()
                if script is None:
                    break
                _phase("PHASE 7: Execution")
                done = self.execute_script(target, script)
                if not done:
                    continue
                print(f"\n{Colors.CYAN}Next:{Colors.END}")
                print(f"  1. Another script (same app)  2. Different app  3. Exit")
                _, na = self.get_numeric_input(f"{Colors.YELLOW}> {Colors.END}", 1, 3)
                if na == 1:
                    continue
                elif na == 2:
                    break
                else:
                    self._exit_program()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    af = AutoFrida()
    try:
        af.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[*] Interrupted{Colors.END}")
        sys.exit(0)
    except Exception:
        logger.exception("Unexpected error")
        sys.exit(1)


if __name__ == "__main__":
    main()
