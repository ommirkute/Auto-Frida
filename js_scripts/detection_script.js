// ==================== AUTO ANALYZER - UNIVERSAL DETECTION SCRIPT v4 ====================
// Targets: Android 12+ emulators and physical rooted devices.
// Coverage: SSL pinning • Root • Emulator • Anti-debug • Anti-Frida • Tamper •
//           Play Integrity • Biometric gate • Network security • ReactNative •
//           Flutter • Xamarin • Unity • DexGuard/iXGuard • ProGuard/R8 obfuscation •
//           Dynamic code loading • Reflection-based protection
"use strict";

// ---------------------------------------------------------------------------
// Core: dedup reporter
// ---------------------------------------------------------------------------
var _seenSigs = {};
function sendDetection(type, data) {
    try {
        var sig = type + ":" + (data.cls || "") + ":" + (data.method || "");
        if (_seenSigs[sig]) return;
        _seenSigs[sig] = true;
        console.log(JSON.stringify({
            autoanalyzer: true,
            type:      type,
            timestamp: Date.now(),
            tid:       Process.getCurrentThreadId(),
            method:    data.method  || "unknown",
            class:     data.cls     || "unknown",
            stack:     data.stack   || "",
            extra:     data.extra   || {}
        }));
    } catch(e) {}
}

function safeAttach(ptr, name, callbacks) {
    try {
        if (!ptr || ptr.isNull()) return false;
        Interceptor.attach(ptr, callbacks);
        console.log("[AA] + Native hook: " + name);
        return true;
    } catch(e) {
        console.log("[AA] ! Failed: " + name + ": " + e.message);
        return false;
    }
}
function safeReplace(ptr, name, cb) {
    try {
        if (!ptr || ptr.isNull()) return false;
        Interceptor.replace(ptr, cb);
        console.log("[AA] + Native replace: " + name);
        return true;
    } catch(e) { return false; }
}

// ---------------------------------------------------------------------------
// PHASE 0 (0ms): Instant native environment fingerprint
// ---------------------------------------------------------------------------
(function phaseZero() {
    try {
        var getPropPtr = Module.findExportByName("libc.so", "__system_property_get");
        if (!getPropPtr || getPropPtr.isNull()) return;
        var nativePropGet = new NativeFunction(getPropPtr, "int", ["pointer", "pointer"]);
        function readProp(key) {
            try {
                var kBuf = Memory.allocUtf8String(key);
                var vBuf = Memory.alloc(128);
                nativePropGet(kBuf, vBuf);
                return vBuf.readUtf8String() || "";
            } catch(e) { return ""; }
        }
        var fp   = readProp("ro.build.fingerprint");
        var tags = readProp("ro.build.tags");
        var dbg  = readProp("ro.debuggable");
        var qemu = readProp("ro.kernel.qemu");
        var qemuBoot = readProp("ro.boot.qemu");
        var avdName  = readProp("ro.kernel.qemu.avd_name");
        var hwName   = readProp("ro.hardware");
        console.log("[AA] Fingerprint: " + fp);
        console.log("[AA] Hardware:    " + hwName);

        if (/generic|unknown|sdk_gphone|emulator|vbox|genymotion|ranchu|goldfish/i.test(fp))
            sendDetection("emulator_detection", { method: "build_fingerprint", cls: "android.os.Build", extra: { fingerprint: fp } });
        if (dbg === "1")
            sendDetection("debugger_detection", { method: "ro.debuggable", cls: "native", extra: { value: "1" } });
        if (tags && tags.indexOf("test-keys") !== -1)
            sendDetection("root_detection", { method: "ro.build.tags", cls: "native", extra: { tags: tags } });
        if (qemu === "1" || qemuBoot === "1")
            sendDetection("emulator_detection", { method: "ro.kernel.qemu", cls: "native", extra: { qemu: qemu, boot: qemuBoot } });
        if (avdName && avdName.length > 0)
            sendDetection("emulator_detection", { method: "ro.kernel.qemu.avd_name", cls: "native", extra: { avd: avdName } });
        if (/ranchu|goldfish|generic/i.test(hwName))
            sendDetection("emulator_detection", { method: "ro.hardware", cls: "native", extra: { hw: hwName } });
    } catch(e) { console.log("[AA] Phase 0 error: " + e.message); }
})();

// ---------------------------------------------------------------------------
// PHASE 1 (200ms): Native module inventory
// ---------------------------------------------------------------------------
setTimeout(function phaseOne() {
    try {
        var modules = Process.enumerateModules();
        console.log("[AA] Loaded modules: " + modules.length);

        // Security / packer / framework libraries
        var SEC_KW = [
            // SSL
            "libssl","libcrypto","libboringssl","libnetssl","libcertpinner",
            // Frameworks
            "libflutter","libhermes","libjsc","libreactbridge",
            "libunity","libmono","libmonosgen","libxamarin",
            // Packers / protectors
            "libsgmain","libsgsecuritybody","libDexHelper","libprotectClass",
            "libbaiduprotect","lib360","libexec","libjiagu","libtpnsecurity",
            "libguard","libshield","libprotect","libnagain","libsecneo",
            "libdexprotect","libAPKProtect","libnesecurity","libqihoo",
            "libsafetycore","libsafetyjni","libarmorize","libpromon",
            // Anti-tamper
            "libverimatrix","libbsafenative","libdexjni","libmobisecls"
        ];

        modules.forEach(function(mod) {
            var nl = mod.name.toLowerCase();
            for (var i = 0; i < SEC_KW.length; i++) {
                if (nl.indexOf(SEC_KW[i]) !== -1) {
                    sendDetection("native_module", { method: mod.name, cls: "native",
                        extra: { base: mod.base.toString(), size: mod.size } });
                    console.log("[AA] ! Security module: " + mod.name);
                    break;
                }
            }
        });

        // Framework fast-checks
        var checks = [
            ["libflutter.so",     "flutter_ssl",   "Flutter detected"],
            ["libhermes.so",      "react_native",  "React Native (Hermes)"],
            ["libjsc.so",         "react_native",  "React Native (JSC)"],
            ["libmono.so",        "xamarin_ssl",   "Xamarin/Mono"],
            ["libmonosgen-2.0.so","xamarin_ssl",   "Xamarin/Monosgen"],
            ["libxamarin-app.so", "xamarin_ssl",   "Xamarin-app"],
            ["libunity.so",       "unity_ssl",     "Unity"],
        ];
        checks.forEach(function(c) {
            var m = Process.findModuleByName(c[0]);
            if (m) {
                sendDetection(c[1], { method: c[0], cls: c[0], extra: { base: m.base.toString() } });
                console.log("[AA] " + c[2]);
            }
        });
    } catch(e) { console.log("[AA] Phase 1 error: " + e.message); }
}, 200);

// ---------------------------------------------------------------------------
// PHASE 2 (400ms): Native hooks
// ---------------------------------------------------------------------------
setTimeout(function phaseTwo() {

    // ---- 2a. dlopen monitor ----
    try {
        var dl = Module.findExportByName(null, "dlopen");
        var secPat = ["libsgmain","libDexHelper","libtpnsecurity","libprotect","libjiagu",
            "libbaiduprotect","lib360","libcertpinner","libguard","libshield","libpromon",
            "libverimatrix","libsecneo","libdexprotect"];
        if (dl && !dl.isNull()) {
            Interceptor.attach(dl, { onEnter: function(args) {
                if (!args[0] || args[0].isNull()) return;
                try {
                    var n = args[0].readUtf8String() || "";
                    var nl = n.toLowerCase();
                    for (var i = 0; i < secPat.length; i++)
                        if (nl.indexOf(secPat[i]) !== -1) {
                            sendDetection("native_library_load", { method: "dlopen", cls: "native", extra: { library: n } });
                            console.log("[AA] -> dlopen security lib: " + n);
                            break;
                        }
                } catch(e) {}
            }});
            console.log("[AA] + dlopen monitor installed");
        }
    } catch(e) {}

    // ---- 2b. Native SSL (libssl / libboringssl) ----
    ["libssl.so", "libssl.so.1.1", "libssl.so.3", "libboringssl.so"].forEach(function(lib) {
        try {
            if (!Process.findModuleByName(lib)) return;
            console.log("[AA] Found " + lib + " — hooking SSL functions");
            safeAttach(Module.findExportByName(lib, "SSL_CTX_set_verify"), "SSL_CTX_set_verify", {
                onEnter: function(args) {
                    sendDetection("ssl_pinning", { method: "SSL_CTX_set_verify", cls: "native_ssl",
                        extra: { mode: args[1] ? args[1].toInt32() : -1 } });
                }
            });
            safeReplace(Module.findExportByName(lib, "SSL_get_verify_result"),
                "SSL_get_verify_result",
                new NativeCallback(function(ssl) {
                    sendDetection("ssl_pinning", { method: "SSL_get_verify_result", cls: "native_ssl", extra: {} });
                    return 0; // X509_V_OK
                }, "long", ["pointer"]));
            safeReplace(Module.findExportByName(lib, "X509_verify_cert"),
                "X509_verify_cert",
                new NativeCallback(function(ctx) {
                    sendDetection("ssl_pinning", { method: "X509_verify_cert", cls: "native_ssl", extra: {} });
                    return 1;
                }, "int", ["pointer"]));
        } catch(e) {}
    });

    // ---- 2c. __system_property_get monitor ----
    try {
        var pgPtr = Module.findExportByName("libc.so", "__system_property_get");
        if (pgPtr && !pgPtr.isNull()) {
            var ROOT_P  = ["ro.debuggable","ro.secure","ro.build.selinux","ro.build.tags","ro.build.type",
                "init.svc.adbd","init.svc.adbd_root","init.svc.su","service.adb.root",
                "ro.adb.secure","persist.service.adb.enable","persist.sys.usb.config",
                "sys.usb.state","sys.usb.config","ro.boot.adb.enable"];
            var EMU_P   = ["ro.product.model","ro.build.fingerprint","ro.hardware",
                           "ro.kernel.qemu","ro.boot.qemu","ro.kernel.qemu.avd_name",
                           "ro.boot.qemu.avd_name","ro.bootloader","init.svc.qemu-props"];
            var INTEG_P = ["ro.build.tags","ro.build.type","ro.build.keys"];
            var ALL_P   = ROOT_P.concat(EMU_P).concat(INTEG_P);
            Interceptor.attach(pgPtr, {
                onEnter: function(args) {
                    this.prop = "";
                    try { this.prop = args[0].readUtf8String() || ""; } catch(e) {}
                },
                onLeave: function(ret) {
                    if (ALL_P.indexOf(this.prop) === -1) return;
                    var etype = ROOT_P.indexOf(this.prop) !== -1  ? "native_root_check"
                              : EMU_P.indexOf(this.prop) !== -1   ? "emulator_detection"
                              : "native_root_check";
                    sendDetection(etype, { method: "__system_property_get", cls: "native",
                        extra: { property: this.prop } });
                }
            });
            console.log("[AA] + Native property monitor installed");
        }
    } catch(e) {}

    // ---- 2d. access() — root path checks ----
    try {
        var acPtr = Module.findExportByName("libc.so", "access");
        if (acPtr && !acPtr.isNull()) {
            Interceptor.attach(acPtr, { onEnter: function(args) {
                if (!args[0] || args[0].isNull()) return;
                try {
                    var p = args[0].readUtf8String() || "";
                    if (/\/su$|\/su\/|magisk|supersu|busybox|xposed|substrate|kingroot/i.test(p))
                        sendDetection("native_root_check", { method: "access", cls: "native", extra: { path: p } });
                } catch(e) {}
            }});
            console.log("[AA] + Native access() monitor installed");
        }
    } catch(e) {}

    // ---- 2e. stat() / stat64() ----
    ["stat","stat64","__xstat","__xstat64"].forEach(function(fn) {
        try {
            var ptr = Module.findExportByName("libc.so", fn);
            if (!ptr || ptr.isNull()) return;
            Interceptor.attach(ptr, { onEnter: function(args) {
                var pathIdx = fn.startsWith("__x") ? 1 : 0;
                try {
                    var p = args[pathIdx].readUtf8String() || "";
                    if (/\/su$|\/su\/|magisk|supersu|busybox|xposed/i.test(p))
                        sendDetection("native_root_check", { method: fn, cls: "native", extra: { path: p } });
                } catch(e) {}
            }});
        } catch(e) {}
    });
    console.log("[AA] + stat() monitors installed");

    // ---- 2f. open() — Frida self-detection & proc reads ----
    try {
        var opPtr = Module.findExportByName(null, "open");
        if (opPtr && !opPtr.isNull()) {
            Interceptor.attach(opPtr, { onEnter: function(args) {
                if (!args[0] || args[0].isNull()) return;
                try {
                    var p = args[0].readUtf8String() || "";
                    if (p.indexOf("/proc/net/tcp")     !== -1 ||
                        p.indexOf("frida")             !== -1 ||
                        p.indexOf("/proc/self/maps")   !== -1 ||
                        p.indexOf("/proc/self/status") !== -1 ||
                        p.indexOf("/proc/self/task")   !== -1)
                        sendDetection("frida_detection", { method: "open", cls: "native", extra: { path: p } });
                } catch(e) {}
            }});
            console.log("[AA] + open() Frida monitor installed");
        }
    } catch(e) {}

    // ---- 2g. readlink() — checks /proc/self/exe for Frida ----
    try {
        var rlPtr = Module.findExportByName("libc.so", "readlink");
        if (rlPtr && !rlPtr.isNull()) {
            Interceptor.attach(rlPtr, { onEnter: function(args) {
                try {
                    var p = args[0].readUtf8String() || "";
                    if (p.indexOf("/proc/self") !== -1)
                        sendDetection("frida_detection", { method: "readlink", cls: "native", extra: { path: p } });
                } catch(e) {}
            }});
        }
    } catch(e) {}

    // ---- 2h. strstr / strcmp — Frida string scanning ----
    try {
        var ssPtr = Module.findExportByName("libc.so", "strstr");
        if (ssPtr && !ssPtr.isNull()) {
            Interceptor.attach(ssPtr, { onEnter: function(args) {
                if (!args[1] || args[1].isNull()) return;
                try {
                    var needle = args[1].readUtf8String() || "";
                    if (/frida|gadget|gum-js-loop|linjector|frida-agent/i.test(needle))
                        sendDetection("frida_detection", { method: "strstr", cls: "native", extra: { needle: needle } });
                } catch(e) {}
            }});
        }
    } catch(e) {}

    // ---- 2i. ptrace — anti-debug ----
    try {
        var ptPtr = Module.findExportByName("libc.so", "ptrace");
        if (ptPtr && !ptPtr.isNull()) {
            Interceptor.attach(ptPtr, { onEnter: function(args) {
                var req = args[0] ? args[0].toInt32() : -1;
                if (req === 0 || req === 31) // PTRACE_TRACEME or PTRACE_ATTACH
                    sendDetection("debugger_detection", { method: "ptrace", cls: "native", extra: { request: req } });
            }});
            console.log("[AA] + ptrace monitor installed");
        }
    } catch(e) {}

    // ---- 2j. kill(0) — process existence check (common Frida detection) ----
    try {
        var killPtr = Module.findExportByName("libc.so", "kill");
        if (killPtr && !killPtr.isNull()) {
            Interceptor.attach(killPtr, { onEnter: function(args) {
                var sig = args[1] ? args[1].toInt32() : -1;
                if (sig === 0) // existence probe
                    sendDetection("frida_detection", { method: "kill(0)", cls: "native",
                        extra: { pid: args[0] ? args[0].toInt32() : -1 } });
            }});
        }
    } catch(e) {}

    // ---- 2k. socket() — port scan for Frida's 27042 ----
    try {
        var connPtr = Module.findExportByName("libc.so", "connect");
        if (connPtr && !connPtr.isNull()) {
            Interceptor.attach(connPtr, { onEnter: function(args) {
                try {
                    // sockaddr_in: family(2B) + port(2B BE) + addr(4B)
                    if (args[1] && !args[1].isNull()) {
                        var port = ((args[1].add(2).readU8() << 8) | args[1].add(3).readU8());
                        if (port === 27042 || port === 27043)
                            sendDetection("frida_detection", { method: "connect", cls: "native",
                                extra: { port: port } });
                    }
                } catch(e) {}
            }});
            console.log("[AA] + connect() port monitor installed");
        }
    } catch(e) {}

    // ---- 2l. fopen on /proc paths ----
    try {
        var fopenPtr = Module.findExportByName("libc.so", "fopen");
        if (fopenPtr && !fopenPtr.isNull()) {
            Interceptor.attach(fopenPtr, { onEnter: function(args) {
                try {
                    var p = args[0].readUtf8String() || "";
                    if (p.indexOf("/proc/") !== -1 && (
                        p.indexOf("/status") !== -1 ||
                        p.indexOf("/maps")   !== -1 ||
                        p.indexOf("/wchan")  !== -1 ||
                        p.indexOf("net/tcp") !== -1))
                        sendDetection("frida_detection", { method: "fopen", cls: "native", extra: { path: p } });
                } catch(e) {}
            }});
            console.log("[AA] + fopen /proc monitor installed");
        }
    } catch(e) {}

}, 400);

// ---------------------------------------------------------------------------
// PHASE 3 (1500ms): Java hooks
// ---------------------------------------------------------------------------
setTimeout(function phaseThree() {
    Java.perform(function() {
        console.log("[AA] Java hooks — Phase 3 starting...");

        // ================================================================
        // 3a. Class enumeration (name-based only — NO Java.use on all)
        // ================================================================
        var suspiciousClasses = [];
        try {
            var lc = Java.enumerateLoadedClassesSync();
            console.log("[AA] Java classes loaded: " + lc.length);

            var NAME_KW = [
                // SSL / pinning
                "certificatepinner","certpinner","sslpinner","pinning","pinset",
                "trustmanager","certverif","sslvalidat","hostnameverif","pinverif",
                "certificatetransparency","certverifier",
                // Root / integrity
                "rootdetect","rootcheck","rootbeer","rootguard","isrooted","rootutil",
                "devicecheck","integritycheck","safetynet","deviceintegrity",
                "playintegrity","attestation",
                // Tamper
                "tamperdetect","signatureverif","apkintegrity","apkcheck","hashverif",
                "checksumverif","integrityverif",
                // Debug / anti-analysis
                "debugdetect","antidebug","debuggercheck","debugcheck",
                "emulatordetect","emulatorcheck","isemulator","virtualdevice",
                // Frida / hook detection
                "fridadetect","hookdetect","xposeddetect","instrumentdetect",
                // Commercial protectors
                "dexguard","ixguard","arxan","guardsquare","appdome",
                "verimatrix","promon","liapp","bangcle","ijiami","secneo",
                "nagain","dexprotect","qihoo","qiguard",
                // Banking / custom names
                "securitycheck","antifraud","frauddetect","fraudprevention",
                "jailbreak","devicebind","devicetrust","appshield"
            ];

            var SYS_PFX = ["android.","java.","javax.","sun.","dalvik.","libcore.",
                "com.android.","com.google.android.","kotlin.","kotlinx.",
                "androidx.","okio.","retrofit2.","com.squareup."];

            lc.forEach(function(cn) {
                for (var s = 0; s < SYS_PFX.length; s++) {
                    if (cn.indexOf(SYS_PFX[s]) === 0) return;
                }
                var cl = cn.toLowerCase().replace(/[^a-z0-9]/g, "");
                for (var k = 0; k < NAME_KW.length; k++) {
                    if (cl.indexOf(NAME_KW[k]) !== -1) {
                        suspiciousClasses.push(cn);
                        break;
                    }
                }
            });

            if (suspiciousClasses.length > 120) {
                console.log("[AA] ! Capping suspicious classes at 120 (found " + suspiciousClasses.length + ")");
                suspiciousClasses = suspiciousClasses.slice(0, 120);
            }

            console.log("[AA] ! Suspicious classes: " + suspiciousClasses.length);
            suspiciousClasses.forEach(function(cn) {
                sendDetection("suspicious_class", { method: "classEnumeration", cls: cn });
                console.log("[AA]   -> " + cn);
                try {
                    var c = Java.use(cn);
                    var ms = c.class.getDeclaredMethods();
                    for (var i = 0; i < ms.length; i++) {
                        var mn = ms[i].getName().toLowerCase();
                        if (/check|detect|verify|isroot|isemul|isdebug|validate|pin|attest|cert|trust|sign|integr|tamper|frida|hook/.test(mn)) {
                            sendDetection("suspicious_method", { method: ms[i].getName(), cls: cn,
                                extra: { return: ms[i].getReturnType().getName() } });
                        }
                    }
                } catch(e) {}
            });
        } catch(e) { console.log("[AA] Class enum error: " + e.message); }

        // ================================================================
        // 3b. SSL / TLS — ALL known vectors
        // ================================================================

        // OkHttp3
        try {
            var CP = Java.use("okhttp3.CertificatePinner");
            CP.check.overloads.forEach(function(m) { m.implementation = function() {
                sendDetection("ssl_pinning", { method: "CertificatePinner.check", cls: "okhttp3.CertificatePinner",
                    extra: { hostname: arguments[0] ? arguments[0].toString() : "?" } });
                return m.apply(this, arguments);
            }; });
            console.log("[AA] + OkHttp3 hook installed");
        } catch(e) {}

        try {
            var OB = Java.use("okhttp3.OkHttpClient$Builder");
            var _obCertPin = OB.certificatePinner.overload("okhttp3.CertificatePinner");
            _obCertPin.implementation = function(p) {
                sendDetection("ssl_pinning", { method: "OkHttp3.Builder.certificatePinner", cls: "okhttp3.OkHttpClient$Builder" });
                return _obCertPin.call(this, p);
            };
        } catch(e) {}

        // OkHttp2
        try {
            var CP2 = Java.use("com.squareup.okhttp.CertificatePinner");
            CP2.check.overloads.forEach(function(m) { m.implementation = function() {
                sendDetection("ssl_pinning", { method: "OkHttp2.CertificatePinner.check", cls: "com.squareup.okhttp.CertificatePinner" });
                return m.apply(this, arguments);
            }; });
            console.log("[AA] + OkHttp2 hook installed");
        } catch(e) {}

        // TrustManagerImpl — use overloads (signature varies by Android version)
        try {
            var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
            TMI.verifyChain.overloads.forEach(function(ol) {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    sendDetection("ssl_pinning", { method: "verifyChain", cls: "com.android.org.conscrypt.TrustManagerImpl" });
                    return ol.apply(_self, _args);
                };
            });
            console.log("[AA] + TrustManagerImpl hook installed");
        } catch(e) {}

        // Conscrypt sockets — use overloads (signature varies by Android version)
        ["org.conscrypt.ConscryptFileDescriptorSocket", "org.conscrypt.ConscryptEngineSocket"].forEach(function(cn) {
            try {
                var c = Java.use(cn);
                c.verifyCertificateChain.overloads.forEach(function(ol) {
                    if (!ol || typeof ol.implementation === "undefined") return;
                    ol.implementation = function() {
                        var _self = this, _args = arguments;
                        sendDetection("ssl_pinning", { method: "verifyCertificateChain", cls: cn });
                        return ol.apply(_self, _args);
                    };
                });
                console.log("[AA] + Conscrypt hook: " + cn);
            } catch(e) {}
        });

        // HttpsURLConnection
        try {
            var HTTPS = Java.use("javax.net.ssl.HttpsURLConnection");
            var _httpsSSL = HTTPS.setSSLSocketFactory.overload("javax.net.ssl.SSLSocketFactory");
            _httpsSSL.implementation = function(f) {
                sendDetection("ssl_pinning", { method: "setSSLSocketFactory", cls: "javax.net.ssl.HttpsURLConnection" });
                return _httpsSSL.call(this, f);
            };
            var _httpsHV = HTTPS.setHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
            _httpsHV.implementation = function(v) {
                sendDetection("ssl_pinning", { method: "setHostnameVerifier", cls: "javax.net.ssl.HttpsURLConnection" });
                return _httpsHV.call(this, v);
            };
            console.log("[AA] + HttpsURLConnection hook installed");
        } catch(e) {}

        // SSLContext.init — hook all overloads (some apps use init(null, tm, null))
        try {
            var SC = Java.use("javax.net.ssl.SSLContext");
            SC.init.overloads.forEach(function(ol) {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    sendDetection("ssl_pinning", { method: "SSLContext.init", cls: "javax.net.ssl.SSLContext" });
                    return ol.apply(_self, _args);
                };
            });
            console.log("[AA] + SSLContext hook installed");
        } catch(e) {}

        // NetworkSecurityConfig
        try {
            var NSC = Java.use("android.security.net.config.NetworkSecurityConfig");
            NSC.isCleartextTrafficPermitted.implementation = function() {
                sendDetection("ssl_pinning", { method: "isCleartextTrafficPermitted", cls: "android.security.net.config.NetworkSecurityConfig" });
                return true;
            };
            console.log("[AA] + NetworkSecurityConfig hook installed");
        } catch(e) {}

        // PinSet
        try {
            var PS = Java.use("android.security.net.config.PinSet");
            var _psPins = PS.getPins.overload();
            _psPins.implementation = function() {
                sendDetection("ssl_pinning", { method: "PinSet.getPins", cls: "android.security.net.config.PinSet" });
                return _psPins.call(this);
            };
        } catch(e) {}

        // WebView
        try {
            var WV = Java.use("android.webkit.WebViewClient");
            WV.onReceivedSslError.implementation = function(v, h, e) {
                sendDetection("ssl_pinning", { method: "onReceivedSslError", cls: "android.webkit.WebViewClient" });
                h.proceed();
            };
            console.log("[AA] + WebViewClient hook installed");
        } catch(e) {}

        // Retrofit
        try {
            var RB2 = Java.use("retrofit2.OkHttpCall");
            var _rbExec = RB2.execute.overload();
            _rbExec.implementation = function() {
                sendDetection("ssl_pinning", { method: "Retrofit.execute", cls: "retrofit2.OkHttpCall" });
                return _rbExec.call(this);
            };
        } catch(e) {}

        // Cronet (Google's Chromium network stack, used by some fintech apps)
        try {
            var CR = Java.use("org.chromium.net.CronetEngine$Builder");
            var _crBuild = CR.build.overload();
            _crBuild.implementation = function() {
                sendDetection("ssl_pinning", { method: "CronetEngine.build", cls: "org.chromium.net.CronetEngine$Builder" });
                return _crBuild.call(this);
            };
        } catch(e) {}

        // Apache HttpClient (legacy but still in some apps)
        try {
            var AH = Java.use("org.apache.http.conn.ssl.SSLSocketFactory");
            var _ahIsSecure = AH.isSecure.overload("javax.net.ssl.SSLSocket");
            _ahIsSecure.implementation = function(s) {
                sendDetection("ssl_pinning", { method: "SSLSocketFactory.isSecure", cls: "org.apache.http.conn.ssl.SSLSocketFactory" });
                return _ahIsSecure.call(this, s);
            };
        } catch(e) {}

        // ================================================================
        // 3c. Root detection
        // ================================================================

        try {
            var F = Java.use("java.io.File");
            F.exists.implementation = function() {
                var p = this.getAbsolutePath().toString();
                if (/\/su$|\/su\/|magisk|busybox|supersu|rootcloak|xposed|substrate|kingroot|superuser/i.test(p))
                    sendDetection("root_detection", { method: "File.exists", cls: "java.io.File", extra: { path: p } });
                return this.exists.call(this);
            };
            console.log("[AA] + File.exists hook installed");
        } catch(e) {}

        // Runtime.exec
        try {
            var RT = Java.use("java.lang.Runtime");
            var _rtExecStr = RT.exec.overload("java.lang.String");
            var _rtExecArr = RT.exec.overload("[Ljava.lang.String;");
            _rtExecStr.implementation = function(cmd) {
                if (cmd && /which.*su|\bsu\b|id$|busybox|magisk|getprop/i.test(cmd))
                    sendDetection("root_detection", { method: "Runtime.exec", cls: "java.lang.Runtime", extra: { cmd: cmd } });
                return _rtExecStr.call(this, cmd);
            };
            _rtExecArr.implementation = function(cmds) {
                var j = cmds.join(" ");
                if (/which.*su|\bsu\b|id$|busybox|magisk/i.test(j))
                    sendDetection("root_detection", { method: "Runtime.exec[]", cls: "java.lang.Runtime", extra: { cmd: j } });
                return _rtExecArr.call(this, cmds);
            };
            console.log("[AA] + Runtime.exec hook installed");
        } catch(e) {}

        // ProcessBuilder
        try {
            var PB = Java.use("java.lang.ProcessBuilder");
            var _pbStart = PB.start.overload();
            _pbStart.implementation = function() {
                var cmd = this.command().toString();
                if (/su|which|busybox|magisk|getprop/i.test(cmd))
                    sendDetection("root_detection", { method: "ProcessBuilder.start", cls: "java.lang.ProcessBuilder", extra: { cmd: cmd } });
                return _pbStart.call(this);
            };
            console.log("[AA] + ProcessBuilder hook installed");
        } catch(e) {}

        // RootBeer
        try {
            var RBeer = Java.use("com.scottyab.rootbeer.RootBeer");
            var _rbIsRooted = RBeer.isRooted.overload();
            _rbIsRooted.implementation = function() {
                sendDetection("root_detection", { method: "RootBeer.isRooted", cls: "com.scottyab.rootbeer.RootBeer" });
                return _rbIsRooted.call(this);
            };
            console.log("[AA] + RootBeer hook installed");
        } catch(e) {}

        // PackageManager — root packages + signature flags (OBSERVE ONLY — no throws)
        try {
            var PM = Java.use("android.app.ApplicationPackageManager");
            var ROOT_PKGS = ["com.topjohnwu.magisk","eu.chainfire.supersu","com.koushikdutta.superuser",
                "de.robv.android.xposed.installer","com.saurik.substrate","com.devadvance.rootcloak",
                "com.amphoras.hidemyroot","com.formyhm.hideroot","com.thirdparty.superuser",
                "com.yellowes.su","com.kingroot.kinguser","com.kingo.root"];

            // API ≤ 32 — observe only, always pass through
            var _pmGetPkg = PM.getPackageInfo.overload("java.lang.String", "int");
            _pmGetPkg.implementation = function(pkg, flags) {
                if (ROOT_PKGS.indexOf(pkg) !== -1)
                    sendDetection("root_detection", { method: "getPackageInfo_rootPkg", cls: "PackageManager", extra: { pkg: pkg } });
                if ((flags & 0x40) !== 0 || (flags & 0x08000000) !== 0)
                    sendDetection("signature_check", { method: "getPackageInfo", cls: "PackageManager", extra: { pkg: pkg, flags: flags } });
                return _pmGetPkg.call(this, pkg, flags);  // always return real result
            };

            // API 33+ (Android 13) — capture overload ref BEFORE using it in closure
            try {
                var _pmGetPkg33 = PM.getPackageInfo.overload(
                    "java.lang.String",
                    "android.content.pm.PackageManager$PackageInfoFlags"
                );
                _pmGetPkg33.implementation = function(pkg, flags) {
                    sendDetection("signature_check", { method: "getPackageInfo_API33", cls: "PackageManager", extra: { pkg: pkg } });
                    return _pmGetPkg33.call(this, pkg, flags);  // always return real result
                };
            } catch(e) {}

            console.log("[AA] + PackageManager hook installed");
        } catch(e) {}

        // SafetyNet / Play Integrity
        try {
            var SN = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
            SN.attest.implementation = function() {
                sendDetection("safetynet", { method: "attest", cls: "com.google.android.gms.safetynet.SafetyNetClient" });
                return this.attest.apply(this, arguments);
            };
            console.log("[AA] + SafetyNet hook installed");
        } catch(e) {}

        try {
            var PI = Java.use("com.google.android.play.core.integrity.IntegrityManager");
            PI.requestIntegrityToken.implementation = function() {
                sendDetection("play_integrity", { method: "requestIntegrityToken", cls: "IntegrityManager" });
                return this.requestIntegrityToken.apply(this, arguments);
            };
            console.log("[AA] + Play Integrity hook installed");
        } catch(e) {}

        // ================================================================
        // 3d. Emulator detection — ALL TelephonyManager methods
        // ================================================================
        try {
            var TLM = Java.use("android.telephony.TelephonyManager");
            // Legacy getDeviceId (deprecated API 29)
            TLM.getDeviceId.overloads.forEach(function(ol) { ol.implementation = function() {
                var _self = this, _args = arguments;
                sendDetection("emulator_detection", { method: "getDeviceId", cls: "TelephonyManager" });
                return ol.apply(_self, _args);
            }; });
            // getImei — primary on API 26+
            try { TLM.getImei.overloads.forEach(function(ol) { ol.implementation = function() {
                var _self = this, _args = arguments;
                sendDetection("emulator_detection", { method: "getImei", cls: "TelephonyManager" });
                return ol.apply(_self, _args);
            }; }); } catch(e) {}
            // Carrier/network checks
            try { var _tlmSimOpName = TLM.getSimOperatorName.overload();
            _tlmSimOpName.implementation = function() {
                sendDetection("emulator_detection", { method: "getSimOperatorName", cls: "TelephonyManager" });
                return _tlmSimOpName.call(this); }; } catch(e) {}
            try { var _tlmNetOpName = TLM.getNetworkOperatorName.overload();
            _tlmNetOpName.implementation = function() {
                sendDetection("emulator_detection", { method: "getNetworkOperatorName", cls: "TelephonyManager" });
                return _tlmNetOpName.call(this); }; } catch(e) {}
            try { var _tlmSimOp = TLM.getSimOperator.overload();
            _tlmSimOp.implementation = function() {
                sendDetection("emulator_detection", { method: "getSimOperator", cls: "TelephonyManager" });
                return _tlmSimOp.call(this); }; } catch(e) {}
            // Subscriber
            try { TLM.getSubscriberId.overloads.forEach(function(ol) { ol.implementation = function() {
                var _self = this, _args = arguments;
                sendDetection("emulator_detection", { method: "getSubscriberId", cls: "TelephonyManager" });
                return ol.apply(_self, _args);
            }; }); } catch(e) {}
            console.log("[AA] + TelephonyManager hook installed");
        } catch(e) {}

        // android.os.Build field reads
        try {
            var Build = Java.use("android.os.Build");
            // Monitor static field access via reflection
            var BuildCls = Java.use("java.lang.Class")
                .forName("android.os.Build");
            var fields = ["FINGERPRINT","MANUFACTURER","MODEL","HARDWARE",
                "PRODUCT","DEVICE","BRAND","BOARD","TAGS","TYPE"];
            fields.forEach(function(fn) {
                try {
                    var f = BuildCls.getField(fn);
                    f.setAccessible(true);
                    // We can't easily intercept field reads, but we detect
                    // if the app reads via reflection (Class.getField pattern)
                } catch(e2) {}
            });
        } catch(e) {}

        // ================================================================
        // 3e. Anti-debug — ALL vectors
        // ================================================================
        try {
            var DB = Java.use("android.os.Debug");
            DB.isDebuggerConnected.implementation = function() {
                sendDetection("debugger_detection", { method: "isDebuggerConnected", cls: "android.os.Debug" });
                return false;
            };
            try { DB.waitingForDebugger.implementation = function() {
                sendDetection("debugger_detection", { method: "waitingForDebugger", cls: "android.os.Debug" });
                return false; }; } catch(e) {}
            try { var _dbCpuNanos = DB.threadCpuTimeNanos.overload();
            _dbCpuNanos.implementation = function() {
                sendDetection("debugger_detection", { method: "threadCpuTimeNanos", cls: "android.os.Debug" });
                return _dbCpuNanos.call(this); }; } catch(e) {}
            console.log("[AA] + android.os.Debug hook installed");
        } catch(e) {}

        // ActivityManager.isUserAMonkey (used to detect automation)
        try {
            var AM = Java.use("android.app.ActivityManager");
            AM.isUserAMonkey.implementation = function() {
                sendDetection("debugger_detection", { method: "isUserAMonkey", cls: "ActivityManager" });
                return false;
            };
        } catch(e) {}

        // ── USB Debugging / Developer Options detection ─────────────────────
        // Settings.Global.getInt — primary ADB/dev detection method
        try {
            var SG = Java.use("android.provider.Settings$Global");
            var ADB_KEYS = ["adb_enabled","development_settings_enabled",
                "stay_on_while_plugged_in","mock_location","allow_mock_location",
                "install_non_market_apps","usb_configuration"];

            var _sgInt2 = SG.getInt.overload("android.content.ContentResolver","java.lang.String");
            _sgInt2.implementation = function(cr, name) {
                for (var i = 0; i < ADB_KEYS.length; i++) {
                    if (name === ADB_KEYS[i]) {
                        sendDetection("adb_detection", { method: "Settings.Global.getInt",
                            cls: "android.provider.Settings$Global", extra: { key: name } });
                        break;
                    }
                }
                return _sgInt2.call(this, cr, name);
            };

            var _sgInt3 = SG.getInt.overload("android.content.ContentResolver","java.lang.String","int");
            _sgInt3.implementation = function(cr, name, def) {
                for (var i = 0; i < ADB_KEYS.length; i++) {
                    if (name === ADB_KEYS[i]) {
                        sendDetection("adb_detection", { method: "Settings.Global.getInt3",
                            cls: "android.provider.Settings$Global", extra: { key: name } });
                        break;
                    }
                }
                return _sgInt3.call(this, cr, name, def);
            };

            var _sgStr = SG.getString.overload("android.content.ContentResolver","java.lang.String");
            _sgStr.implementation = function(cr, name) {
                for (var i = 0; i < ADB_KEYS.length; i++) {
                    if (name === ADB_KEYS[i]) {
                        sendDetection("adb_detection", { method: "Settings.Global.getString",
                            cls: "android.provider.Settings$Global", extra: { key: name } });
                        break;
                    }
                }
                return _sgStr.call(this, cr, name);
            };

            console.log("[AA] + Settings.Global ADB detection hooks installed");
        } catch(e) {}

        // Settings.Secure.getInt — legacy ADB check
        try {
            var SS_D = Java.use("android.provider.Settings$Secure");
            var _ssInt3 = SS_D.getInt.overload("android.content.ContentResolver","java.lang.String","int");
            _ssInt3.implementation = function(cr, name, def) {
                if (name === "adb_enabled" || name === "development_settings_enabled") {
                    sendDetection("adb_detection", { method: "Settings.Secure.getInt",
                        cls: "android.provider.Settings$Secure", extra: { key: name } });
                }
                return _ssInt3.call(this, cr, name, def);
            };
        } catch(e) {}

        // ActivityManager.isRunningInTestHarness / isRunningInUserTestHarness
        try {
            var AM2 = Java.use("android.app.ActivityManager");
            try {
                AM2.isRunningInTestHarness.implementation = function() {
                    sendDetection("adb_detection", { method: "isRunningInTestHarness",
                        cls: "android.app.ActivityManager" });
                    return false;
                };
            } catch(e2) {}
            try {
                AM2.isRunningInUserTestHarness.implementation = function() {
                    sendDetection("adb_detection", { method: "isRunningInUserTestHarness",
                        cls: "android.app.ActivityManager" });
                    return false;
                };
            } catch(e2) {}
            console.log("[AA] + ActivityManager ADB detection hooks installed");
        } catch(e) {}

        // System.exit — some protections call this when detected

        try {
            var Sys = Java.use("java.lang.System");
            Sys.exit.implementation = function(code) {
                sendDetection("protection_triggered", { method: "System.exit", cls: "java.lang.System",
                    extra: { code: code } });
                console.log("[AA] !! System.exit(" + code + ") intercepted — NOT exiting");
                // Don't call through — stops the kill
            };
            console.log("[AA] + System.exit hook installed");
        } catch(e) {}

        // Runtime.halt
        try {
            var RTH = Java.use("java.lang.Runtime");
            RTH.halt.implementation = function(code) {
                sendDetection("protection_triggered", { method: "Runtime.halt", cls: "java.lang.Runtime",
                    extra: { code: code } });
                console.log("[AA] !! Runtime.halt(" + code + ") intercepted");
            };
        } catch(e) {}

        // ================================================================
        // 3f. Tamper / signature detection
        // ================================================================
        try {
            var MDG = Java.use("java.security.MessageDigest");
            var _mdDigest = MDG.digest.overload();
            _mdDigest.implementation = function() {
                sendDetection("hash_check", { method: "digest", cls: "java.security.MessageDigest",
                    extra: { algo: this.getAlgorithm() } });
                return _mdDigest.call(this);
            };
            console.log("[AA] + MessageDigest hook installed");
        } catch(e) {}

        // getInstallerPackageName / getInstallSourceInfo
        try {
            var PMI = Java.use("android.app.ApplicationPackageManager");
            var _getInstaller = PMI.getInstallerPackageName.overload('java.lang.String');
            _getInstaller.implementation = function(pkg) {
                sendDetection("signature_check", { method: "getInstallerPackageName", cls: "PackageManager",
                    extra: { pkg: pkg } });
                return _getInstaller.call(this, pkg);
            };
            console.log("[AA] + getInstallerPackageName hook installed");
        } catch(e) {}

        try {
            var PMISI = Java.use("android.app.ApplicationPackageManager");
            var _getInstallSrc = PMISI.getInstallSourceInfo.overload('java.lang.String');
            _getInstallSrc.implementation = function(pkg) {
                sendDetection("signature_check", { method: "getInstallSourceInfo", cls: "PackageManager",
                    extra: { pkg: pkg } });
                return _getInstallSrc.call(this, pkg);
            };
        } catch(e) {}

        // ================================================================
        // 3g. Dynamic code loading (DEX-in-DEX, DexClassLoader)
        // ================================================================
        try {
            var DCL = Java.use("dalvik.system.DexClassLoader");
            var _dclInit = DCL.$init.overload("java.lang.String","java.lang.String","java.lang.String","java.lang.ClassLoader");
            _dclInit.implementation = function(dexPath, optDir, libPath, parent) {
                sendDetection("dynamic_code_load", { method: "DexClassLoader.<init>", cls: "DexClassLoader",
                    extra: { dex: dexPath } });
                console.log("[AA] -> DexClassLoader: " + dexPath);
                return _dclInit.call(this, dexPath, optDir, libPath, parent);
            };
            console.log("[AA] + DexClassLoader hook installed");
        } catch(e) {}

        try {
            var IDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
            IDCL.$init.overloads.forEach(function(ol) {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    sendDetection("dynamic_code_load", { method: "InMemoryDexClassLoader.<init>", cls: "InMemoryDexClassLoader" });
                    console.log("[AA] -> InMemoryDexClassLoader used");
                    return ol.apply(_self, _args);
                };
            });
            console.log("[AA] + InMemoryDexClassLoader hook installed");
        } catch(e) {}

        // ================================================================
        // 3h. Reflection-based protection bypass detection
        // ================================================================
        try {
            var Method = Java.use("java.lang.reflect.Method");
            var _methodInvoke = Method.invoke.overload("java.lang.Object","[Ljava.lang.Object;");
            _methodInvoke.implementation = function(obj, args) {
                var mn = this.getName();
                if (/check|detect|verify|isroot|isemul|isdebug|pin|attest|cert|trust/i.test(mn)) {
                    sendDetection("reflection_hook", { method: "Method.invoke:" + mn,
                        cls: this.getDeclaringClass().getName() });
                }
                return _methodInvoke.call(this, obj, args);
            };
        } catch(e) {}

        // ================================================================
        // 3i. Biometric / device lock gate (fintech apps)
        // ================================================================
        try {
            var BM = Java.use("android.hardware.biometrics.BiometricManager");
            BM.canAuthenticate.overloads.forEach(function(ol) {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    sendDetection("biometric_gate", { method: "canAuthenticate", cls: "BiometricManager" });
                    return ol.apply(_self, _args);
                };
            });
        } catch(e) {}

        try {
            var KG = Java.use("android.app.KeyguardManager");
            var _kgIsDeviceSecure = KG.isDeviceSecure.overload();
            _kgIsDeviceSecure.implementation = function() {
                sendDetection("biometric_gate", { method: "isDeviceSecure", cls: "KeyguardManager" });
                return _kgIsDeviceSecure.call(this);
            };
        } catch(e) {}

        // ================================================================
        // 3j. Dynamic hooks on detected suspicious classes (capped)
        // ================================================================
        var methodsHooked = 0;
        var HOOK_RE = /check|detect|verify|isroot|isemul|isdebug|validate|pin|attest|cert|trust|sign|integr|tamper|frida|hook/i;
        var dynLimit = Math.min(suspiciousClasses.length, 60);

        for (var d = 0; d < dynLimit; d++) {
            var cn = suspiciousClasses[d];
            try {
                var c = Java.use(cn);
                var ms = c.class.getDeclaredMethods();
                var hCount = 0;
                for (var i = 0; i < ms.length && hCount < 10; i++) {
                    var mn = ms[i].getName();
                    if (!HOOK_RE.test(mn)) continue;
                    try {
                        (function(capturedMn, capturedCn) {
                            c[capturedMn].overloads.forEach(function(ov) {
                                try {
                                    ov.implementation = function() {
                                        var _self = this, _args = arguments;
                                        sendDetection("dynamic_hook", { method: capturedMn, cls: capturedCn,
                                            extra: { args: arguments.length } });
                                        return ov.apply(_self, _args);
                                    };
                                    hCount++; methodsHooked++;
                                } catch(e) {}
                            });
                        })(mn, cn);
                        console.log("[AA] + Dynamic: " + cn + "." + mn);
                    } catch(e) {}
                }
            } catch(e) {}
        }
        if (methodsHooked > 0) console.log("[AA] + Dynamic hooks total: " + methodsHooked);

        console.log("[AA] All hooks installed — interact with the app now!");
    });
}, 1500);

// ---------------------------------------------------------------------------
// PHASE 4 (10s): Lazy-loaded class rescan
// ---------------------------------------------------------------------------
setTimeout(function phaseFour() {
    Java.perform(function() {
        console.log("[AA] Phase 4 — lazy class rescan...");
        try {
            var lc2 = Java.enumerateLoadedClassesSync();
            var LAZY_KW = ["certificatepinner","trustmanager","sslpinner","rootdetect",
                "safetynet","playintegrity","pinning","tamperdetect","fridadetect",
                "integritycheck","devicecheck","attestation","hookdetect","dexguard","promon"];
            var SYS_PFX = ["android.","java.","javax.","sun.","dalvik.","libcore.",
                "com.android.","com.google.android.","kotlin.","kotlinx.","androidx."];
            lc2.forEach(function(cn) {
                for (var s = 0; s < SYS_PFX.length; s++) { if (cn.indexOf(SYS_PFX[s]) === 0) return; }
                var cl = cn.toLowerCase().replace(/[^a-z0-9]/g, "");
                for (var k = 0; k < LAZY_KW.length; k++) {
                    if (cl.indexOf(LAZY_KW[k]) !== -1) {
                        sendDetection("lazy_class_found", { method: "lazyRescan", cls: cn,
                            extra: { keyword: LAZY_KW[k] } });
                        break;
                    }
                }
            });
            console.log("[AA] Phase 4 complete.");
        } catch(e) {}
    });
}, 10000);
