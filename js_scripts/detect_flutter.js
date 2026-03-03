// ==================== FLUTTER DETECTION + ANALYSIS SCRIPT ====================
// Run this FIRST on any Flutter app to identify:
//   - Flutter engine version
//   - BoringSSL function locations (for bypass targeting)
//   - Certificate pinning implementation
//   - Dart SecurityContext setup
//   - Platform channel traffic
// =============================================================================

"use strict";

(function flutterDetect() {

    var TAG = "[FlutterDetect]";
    function log(msg) { console.log(TAG + " " + msg); }
    function report(category, detail) {
        console.log(JSON.stringify({
            flutter_detect: true,
            category: category,
            detail: detail,
            timestamp: Date.now()
        }));
    }

    // ── 1. Confirm Flutter presence ────────────────────────────────────────
    var flutterMod = Process.findModuleByName("libflutter.so");
    if (!flutterMod) {
        log("libflutter.so NOT found — this may not be a Flutter app");
        log("Checking for libapp.so (AOT compiled Dart)...");
        var appMod = Process.findModuleByName("libapp.so");
        if (appMod) {
            log("libapp.so found @ " + appMod.base + " — Flutter AOT (split engine)");
            report("framework", { type: "flutter_aot_split", libapp: appMod.base.toString() });
        }
        return;
    }

    var BASE     = flutterMod.base;
    var MOD_SIZE = flutterMod.size;
    var MOD_END  = BASE.add(MOD_SIZE);
    var ARCH     = Process.arch;

    log("✓ Flutter detected — libflutter.so @ " + BASE +
        " size=0x" + MOD_SIZE.toString(16) + " arch=" + ARCH);

    report("framework", {
        type: "flutter",
        base: BASE.toString(),
        size: MOD_SIZE,
        arch: ARCH
    });

    // ── 2. Flutter engine version ──────────────────────────────────────────
    // Try to extract version from exported symbol or embedded string

    var flutterVersion = "unknown";

    // Check for FlutterVersion export
    var versionFn = Module.findExportByName("libflutter.so", "FlutterEngineGetProcAddress");
    if (versionFn) log("FlutterEngineGetProcAddress found — likely Flutter 3.x+");

    // Scan for version string "Flutter/" or "engine/"
    var versionPat  = "46 6C 75 74 74 65 72 2F"; // "Flutter/"
    var enginePat   = "65 6E 67 69 6E 65 5F 72 65 76 69 73 69 6F 6E"; // "engine_revision"

    try {
        Process.enumerateRangesSync("r--").concat(Process.enumerateRangesSync("r-x"))
            .forEach(function(r) {
                if (r.base.compare(BASE) < 0 || r.base.compare(MOD_END) >= 0) return;
                try {
                    Memory.scanSync(r.base, r.size, enginePat).forEach(function(h) {
                        try {
                            var str = h.address.readUtf8String(80);
                            if (str) {
                                log("Engine string: " + str.substring(0, 60));
                                report("version", { string: str.substring(0, 60) });
                            }
                        } catch(e2) {}
                    });
                } catch(e) {}
            });
    } catch(e) {}

    // ── 3. BoringSSL function mapping ─────────────────────────────────────
    log("Scanning for BoringSSL string anchors...");

    var SSL_STRINGS = [
        { pattern: "73 73 6C 2F 73 73 6C 5F 78 35 30 39 2E 63 63 00",
          name: "ssl/ssl_x509.cc",         significance: "CRITICAL - X.509 verify chain" },
        { pattern: "73 73 6C 2F 68 61 6E 64 73 68 61 6B 65 2E 63 63 00",
          name: "ssl/handshake.cc",         significance: "CRITICAL - ssl_verify_peer_cert" },
        { pattern: "73 73 6C 2F 74 6C 73 5F 72 65 63 6F 72 64 2E 63 63 00",
          name: "ssl/tls_record.cc",        significance: "TLS record processing" },
        { pattern: "43 52 59 50 54 4F 5F 6D 65 6D 63 6D 70",
          name: "CRYPTO_memcmp",            significance: "Crypto comparison" },
        { pattern: "73 73 6C 5F 76 65 72 69 66 79 5F 70 65 65 72 5F 63 65 72 74",
          name: "ssl_verify_peer_cert",     significance: "CRITICAL - exact function name" },
        { pattern: "62 61 64 43 65 72 74 69 66 69 63 61 74 65 43 61 6C 6C 62 61 63 6B",
          name: "badCertificateCallback",   significance: "Dart-level cert callback" },
        { pattern: "43 45 52 54 49 46 49 43 41 54 45 00",
          name: "CERTIFICATE",             significance: "PEM header — cert loading" },
        { pattern: "73 65 63 75 72 69 74 79 43 6F 6E 74 65 78 74",
          name: "securityContext",          significance: "Dart SecurityContext" },
    ];

    var allReadable = [];
    Process.enumerateRangesSync("r--").concat(Process.enumerateRangesSync("r-x")).forEach(function(r) {
        if (r.base.compare(BASE) >= 0 && r.base.compare(MOD_END) < 0) allReadable.push(r);
    });

    SSL_STRINGS.forEach(function(entry) {
        var hits = [];
        allReadable.forEach(function(r) {
            try {
                Memory.scanSync(r.base, r.size, entry.pattern).forEach(function(h) {
                    hits.push(h.address);
                });
            } catch(e) {}
        });

        if (hits.length > 0) {
            log("✓ Found '" + entry.name + "' at " + hits.length + " location(s)");
            log("  → " + entry.significance);
            report("ssl_string_found", {
                name: entry.name,
                significance: entry.significance,
                addresses: hits.map(function(h) { return h.toString(); }),
                count: hits.length
            });
        } else {
            log("✗ '" + entry.name + "' not found (may be stripped/obfuscated)");
        }
    });

    // ── 4. Exported symbol inventory ──────────────────────────────────────
    log("Checking exported symbols...");

    var INTERESTING_EXPORTS = [
        "SSL_CTX_set_verify",
        "SSL_CTX_set_custom_verify",
        "SSL_CTX_set_cert_verify_callback",
        "SSL_get_verify_result",
        "X509_verify_cert",
        "ssl_verify_peer_cert",
        "ssl_crypto_x509_session_verify_cert_chain",
        "FlutterEngineInitialize",
        "FlutterEngineGetProcAddress",
        "Dart_Initialize",
        "Dart_Invoke",
        "Dart_InvokeClosure",
        "SecurityContext_SetTrustedCertificatesBytes",
        "_Dart_SecurityContext_SetTrustedCertificatesBytes",
    ];

    var foundExports = [];
    INTERESTING_EXPORTS.forEach(function(sym) {
        var p = Module.findExportByName("libflutter.so", sym);
        if (p && !p.isNull()) {
            foundExports.push({ sym: sym, addr: p.toString() });
            log("✓ Export: " + sym + " @ " + p);
        }
    });

    report("exports", {
        found: foundExports,
        total: foundExports.length,
        note: foundExports.length === 0
            ? "STRIPPED — must use pattern scan for bypass"
            : "EXPORTED — fast bypass available"
    });

    // ── 5. Java-level Flutter detection ──────────────────────────────────
    setTimeout(function() {
        Java.perform(function() {

            // Detect Flutter engine version from BuildConfig
            try {
                var FV = Java.use("io.flutter.BuildConfig");
                log("Flutter BuildConfig found");
                report("flutter_buildconfig", { found: true });
            } catch(e) {}

            // Detect if certificate pinning is configured via network_security_config
            try {
                var NSC = Java.use("android.security.net.config.NetworkSecurityConfig");
                NSC.isCleartextTrafficPermitted.implementation = function() {
                    var r = this.isCleartextTrafficPermitted.call(this);
                    log("NetworkSecurityConfig.isCleartextTrafficPermitted = " + r);
                    report("network_security", { cleartext_permitted: r });
                    return r;
                };
            } catch(e) {}

            // Monitor FlutterJNI for engine start events
            try {
                var FJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
                log("✓ FlutterJNI found — monitoring engine start");
                report("flutter_jni", { found: true });

                var _fjniRunDetect = FJNI.nativeRunBundleAndSnapshotFromLibrary.overload('long','java.lang.String','java.lang.String','java.lang.String','android.content.res.AssetManager','[Ljava.lang.String;');
                _fjniRunDetect.implementation = function(
                    nativeId, bundlePath, entrypoint, pathToEntrypoint, assetMgr, entrypointArgs
                ) {
                    log("Flutter engine running: entrypoint=" + entrypoint);
                    report("flutter_engine_start", {
                        entrypoint: entrypoint,
                        bundle: bundlePath,
                        pathToEntrypoint: pathToEntrypoint
                    });
                    return _fjniRunDetect.call(this,
                        nativeId, bundlePath, entrypoint, pathToEntrypoint, assetMgr, entrypointArgs
                    );
                };
            } catch(e) {}

            // Monitor platform channel messages (detect SSL/network-related calls)
            try {
                var BinaryMessenger = Java.use("io.flutter.plugin.common.MethodChannel$IncomingMethodCallHandler");
                log("+ MethodChannel IncomingHandler found");
            } catch(e) {}

            // Detect dio (Flutter HTTP library) — it wraps Dart's http client
            try {
                var dioCheck = Java.enumerateLoadedClassesSync()
                    .filter(function(cn) { return cn.indexOf("flutter") !== -1 && cn.toLowerCase().indexOf("dio") !== -1; });
                if (dioCheck.length > 0) {
                    log("Dio HTTP library detected: " + dioCheck.length + " classes");
                    report("dart_http_lib", { library: "dio", classes: dioCheck });
                }
            } catch(e) {}

            log("Java-level detection complete.");
        });
    }, 1500);

    // ── 6. Runtime network monitoring ─────────────────────────────────────
    // Hook SSL_do_handshake if found (exported in some builds)
    var handshakeFn = Module.findExportByName("libflutter.so", "SSL_do_handshake");
    if (handshakeFn && !handshakeFn.isNull()) {
        Interceptor.attach(handshakeFn, {
            onEnter: function(args) {
                this.ssl = args[0];
                log("SSL_do_handshake called — SSL ptr: " + this.ssl);
            },
            onLeave: function(ret) {
                log("SSL_do_handshake returned: " + ret.toInt32() +
                    (ret.toInt32() === 1 ? " (success)" : " (FAILED)"));
                report("ssl_handshake", { result: ret.toInt32() });
            }
        });
        log("+ SSL_do_handshake monitor installed");
    }

    log("Flutter detection setup complete. Interact with the app now.");

})();
