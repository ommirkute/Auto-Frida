// ==================== FLUTTER SSL BYPASS - ADVANCED v4 ====================
// Works across: Flutter 2.x / 3.x / 3.10+ | ARM64 | ARM32 | x86_64 | x86
// Devices: Android 8+ emulators and physical devices
//
// STRATEGY (layered — each layer independent, all run in parallel):
//
//   Layer 1 — Exported symbols   (fastest, works on debug/profile builds)
//   Layer 2 — String-anchor XREF (cross-version, finds ssl_x509 functions)
//   Layer 3 — Byte pattern scan  (arch-specific prologue patterns)
//   Layer 4 — Dart VM hooks      (SecurityContext, badCertificateCallback)
//   Layer 5 — Java bridge hooks  (platform channel, OkHttp used by plugins)
//
// ssl_verify_peer_cert return values (BoringSSL enum ssl_verify_result_t):
//   ssl_verify_ok      = 0  ← what we want to return
//   ssl_verify_invalid = 1
//   ssl_verify_retry   = 255
// ==========================================================================

"use strict";

(function flutterSSLBypass() {

    // ── Utilities ──────────────────────────────────────────────────────────

    var TAG = "[Flutter]";

    function log(msg) { console.log(TAG + " " + msg); }

    function safeReplace(ptr, name, retType, argTypes, impl) {
        try {
            if (!ptr || ptr.isNull()) return false;
            Interceptor.replace(ptr, new NativeCallback(impl, retType, argTypes));
            log("+ Patched: " + name);
            return true;
        } catch(e) {
            log("! Replace failed: " + name + " — " + e.message);
            return false;
        }
    }

    function safeAttach(ptr, name, callbacks) {
        try {
            if (!ptr || ptr.isNull()) return false;
            Interceptor.attach(ptr, callbacks);
            log("+ Hooked: " + name);
            return true;
        } catch(e) {
            log("! Attach failed: " + name + " — " + e.message);
            return false;
        }
    }

    // Safe memory read — returns null on access violation
    function tryReadU32(addr) {
        try { return addr.readU32(); } catch(e) { return null; }
    }

    // ── Module detection ───────────────────────────────────────────────────

    var flutterMod = Process.findModuleByName("libflutter.so");
    if (!flutterMod) {
        log("libflutter.so not found — will retry in 3s");
        setTimeout(flutterSSLBypass, 3000);
        return;
    }

    var BASE     = flutterMod.base;
    var MOD_SIZE = flutterMod.size;
    var MOD_END  = BASE.add(MOD_SIZE);
    var ARCH     = Process.arch; // "arm64", "arm", "ia32", "x64"

    log("libflutter.so @ " + BASE + " size=0x" + MOD_SIZE.toString(16) + " arch=" + ARCH);

    // ── Enumerate readable + executable ranges inside libflutter.so ────────
    // On Android the linker often marks segments individually; we need both
    // r-- (for string scanning) and r-x/--x (for code patching).

    var roRanges  = [];  // readable data (strings live here)
    var codeRanges = []; // executable code

    Process.enumerateRangesSync("r--").concat(
        Process.enumerateRangesSync("r-x"),
        Process.enumerateRangesSync("--x"),
        Process.enumerateRangesSync("rwx")
    ).forEach(function(r) {
        if (r.base.compare(BASE) < 0 || r.base.compare(MOD_END) >= 0) return;
        var perm = r.protection;
        if (perm.indexOf("r") !== -1) roRanges.push(r);
        if (perm.indexOf("x") !== -1) codeRanges.push(r);
    });

    // Deduplicate
    function dedup(ranges) {
        var seen = {};
        return ranges.filter(function(r) {
            var k = r.base.toString();
            if (seen[k]) return false;
            seen[k] = true;
            return true;
        });
    }
    roRanges   = dedup(roRanges);
    codeRanges = dedup(codeRanges);
    log("Ranges: ro=" + roRanges.length + " code=" + codeRanges.length);

    // ── Safe memory scanner ────────────────────────────────────────────────

    function scanRange(range, pattern) {
        try {
            if (!range || range.size === 0) return [];
            return Memory.scanSync(range.base, range.size, pattern);
        } catch(e) { return []; }
    }

    function scanAll(ranges, pattern) {
        var hits = [];
        ranges.forEach(function(r) {
            scanRange(r, pattern).forEach(function(h) { hits.push(h.address); });
        });
        return hits;
    }

    // ── Layer 1: Exported symbols ──────────────────────────────────────────
    // These exist in Flutter debug/profile and some engine builds.

    var EXPORTED_TARGETS = [
        // BoringSSL cert verification
        { sym: "SSL_CTX_set_verify",             ret: "void", args: ["pointer","int","pointer"],
          patch: function(args) { args[1] = ptr(0); args[2] = ptr(0); }, type: "attach" },
        { sym: "SSL_CTX_set_custom_verify",       ret: "void", args: ["pointer","int","pointer"],
          patch: function(args) { args[1] = ptr(0); args[2] = ptr(0); }, type: "attach" },
        { sym: "SSL_CTX_set_cert_verify_callback",ret: "void", args: ["pointer","pointer","pointer"],
          patch: function(args) { args[1] = ptr(0); args[2] = ptr(0); }, type: "attach" },
        { sym: "SSL_get_verify_result",           ret: "long", args: ["pointer"],
          impl: function(ssl) { return 0; }, type: "replace" },
        { sym: "X509_verify_cert",                ret: "int",  args: ["pointer"],
          impl: function(ctx) { return 1; }, type: "replace" },
        { sym: "ssl_verify_peer_cert",            ret: "int",  args: ["pointer"],
          impl: function(ssl) { return 0; }, type: "replace" },      // ssl_verify_ok = 0
        { sym: "ssl_crypto_x509_session_verify_cert_chain", ret: "int", args: ["pointer","pointer","pointer"],
          impl: function(s,sc,a) { return 1; }, type: "replace" },  // return 1 = success in this ctx
    ];

    var layer1count = 0;
    EXPORTED_TARGETS.forEach(function(t) {
        var p = Module.findExportByName("libflutter.so", t.sym);
        if (!p || p.isNull()) return;
        if (t.type === "replace") {
            if (safeReplace(p, t.sym, t.ret, t.args, t.impl)) layer1count++;
        } else {
            if (safeAttach(p, t.sym, { onEnter: t.patch })) layer1count++;
        }
    });
    if (layer1count > 0) log("Layer 1 (exported): " + layer1count + " hooks installed");

    // ── Layer 2: String-anchor XREF scan ──────────────────────────────────
    // Finds ssl_verify_peer_cert and ssl_crypto_x509_session_verify_cert_chain
    // by locating their source-file strings, then finding code that references
    // those strings, then walking back to the function prologue.

    var layer2count = 0;

    // Anchor strings reliably present in BoringSSL embedded in Flutter
    var STRING_ANCHORS = [
        { str: "ssl/ssl_x509.cc",     isSsl_x509: true  },
        { str: "ssl/handshake.cc",    isSsl_x509: false },
        { str: "x509.cc",             isSsl_x509: true  },
    ];

    // Find function start by walking backwards from a hit address
    // looking for a prologue: on ARM64 "stp x29, x30, [sp, #-n]!"
    //                          on ARM   "push {r4, ..., lr}"
    //                          on x86_64 "push rbp; mov rbp, rsp" (55 48 89 E5)
    //                          on x86    "push ebp; mov ebp, esp" (55 89 E5)

    function findPrologueBackward(addr, maxBytes, arch) {
        var search = arch === "arm64" ? 64 : 32;  // step size to walk back
        // Walk back in function-sized steps looking for known prologues
        for (var offset = 0; offset <= maxBytes; offset += 4) {
            var candidate = addr.sub(offset);
            var v = tryReadU32(candidate);
            if (v === null) break;

            if (arch === "arm64") {
                // stp x29, x30, [sp, #-n]!  → low 22 bits = 0x29be (varies by frame size)
                // Encoding: A9 ?? BF A9  (little-endian)
                // More specifically: top byte A9 and byte 2 = BF
                var b0 = v & 0xFF;
                var b2 = (v >>> 16) & 0xFF;
                var b3 = (v >>> 24) & 0xFF;
                if (b3 === 0xA9 && b2 === 0xBF) return candidate;
                // sub sp, sp, #imm → FD 7B .. D1 pattern
                // or stp x29,x30 → A9 7B .. A9
                if ((v & 0xFFC003FF) === 0xA9007BFD) return candidate;
            } else if (arch === "arm") {
                // PUSH {r4-r7, lr} and variants (THUMB: 2F E9)
                // ARM: E9 2D ?? ?? 
                if ((v >>> 20) === 0xE92 || (v & 0xFFFF) === 0x2DE9) return candidate;
            } else if (arch === "x64") {
                // 55 48 89 E5 = push rbp; mov rbp, rsp
                if ((v & 0xFFFFFFFF) === 0xE5894855) return candidate;
                // 41 57 41 56 = push r15; push r14 (alternative prologue)
                if ((v & 0xFFFF) === 0x5741) return candidate;
            } else if (arch === "ia32") {
                // 55 89 E5 = push ebp; mov ebp, esp
                if ((v & 0xFFFFFF) === 0xE58955) return candidate;
            }
        }
        return null;
    }

    STRING_ANCHORS.forEach(function(anchor) {
        // Scan ro ranges for the anchor string
        var strBytes = "";
        for (var i = 0; i < anchor.str.length; i++) {
            strBytes += anchor.str.charCodeAt(i).toString(16).padStart(2, "0") + " ";
        }
        strBytes += "00";  // null terminator

        var strHits = scanAll(roRanges, strBytes.trim());
        if (strHits.length === 0) return;

        log("Layer 2: found '" + anchor.str + "' at " + strHits.length + " location(s)");

        strHits.forEach(function(strAddr) {
            // Now scan code ranges for ADRP/ADR instructions that could reference
            // this string address. On ARM64, ADRP page-aligns the target.
            // We use a simpler approach: scan for the raw address bytes (works well
            // on x86/x64 and in literal pools on ARM).

            var addrLE = "";
            var rawAddr = strAddr;
            for (var b = 0; b < Process.pointerSize; b++) {
                var byte_val = (rawAddr.and(ptr(0xFF))).toInt32();
                addrLE += byte_val.toString(16).padStart(2, "0") + " ";
                rawAddr = rawAddr.shr(8);
            }

            // For ARM64 ADRP: instead scan code ranges for any 4-byte sequence
            // that, when decoded as ADRP+ADD pair, resolves to our string addr.
            // This is complex; use a simpler heuristic:
            // Look within ±2MB of string for functions that CALL into ssl verification.

            // Simpler: scan code for the string address embedded as immediate
            // This works reliably on x86/x64
            if (ARCH === "x64" || ARCH === "ia32") {
                var codeHits = scanAll(codeRanges, addrLE.trim());
                codeHits.forEach(function(refAddr) {
                    // Walk back to find prologue
                    var fnStart = findPrologueBackward(refAddr, 512, ARCH);
                    if (!fnStart) return;
                    if (anchor.isSsl_x509) {
                        safeReplace(fnStart, "ssl_x509_fn@" + fnStart, "int",
                            ["pointer","pointer","pointer"],
                            function(a,b,c) {
                                log("-> ssl_x509 verify bypassed (x86 XREF)");
                                return 1;
                            });
                        layer2count++;
                    }
                });
            }
        });
    });

    // ARM64 ADRP scanner — more accurate than raw address scan
    // ADRP Xd, #imm: encoding top 8 bits = 0x90 | (immhi<<3) | (immlo>>1)
    // We scan executable ranges looking for ADRP instructions whose target
    // page matches the page of our string addresses.
    if (ARCH === "arm64") {
        STRING_ANCHORS.forEach(function(anchor) {
            var strBytes = "";
            for (var i = 0; i < anchor.str.length; i++) {
                strBytes += anchor.str.charCodeAt(i).toString(16).padStart(2, "0") + " ";
            }
            strBytes += "00";

            var strHits = scanAll(roRanges, strBytes.trim());
            strHits.forEach(function(strAddr) {
                var targetPage = strAddr.and(ptr(0xFFFFFFFFFFFFF000));

                codeRanges.forEach(function(codeRange) {
                    var size = codeRange.size;
                    var base = codeRange.base;
                    // Scan 4 bytes at a time
                    for (var off = 0; off + 3 < size; off += 4) {
                        var instrAddr = base.add(off);
                        var instr = tryReadU32(instrAddr);
                        if (instr === null) { off += 252; continue; } // skip bad page

                        // ADRP: bits[31:24] == 0x90 | bits[28:29] (immhi top 2 bits)
                        // More precisely: bits[31] = 1, bits[30:29] = immlo, bits[28:24] = 10000
                        // Mask: (instr & 0x9F000000) == 0x90000000
                        if ((instr & 0x9F000000) !== 0x90000000) continue;

                        // Decode ADRP target page
                        var immhi = (instr >>> 5) & 0x7FFFF;
                        var immlo = (instr >>> 29) & 0x3;
                        var immRaw = ((immhi << 2) | immlo) << 12;
                        // Sign-extend 33 bits
                        if (immRaw & 0x100000000) immRaw = immRaw - 0x200000000;

                        var instrPage = instrAddr.and(ptr(0xFFFFFFFFFFFFF000));
                        try {
                            var resolvedPage = instrPage.add(ptr(immRaw));
                            if (resolvedPage.compare(targetPage) !== 0) continue;
                        } catch(e) { continue; }

                        // Found a reference! Walk back to function start
                        var fnStart = findPrologueBackward(instrAddr, 0x400, "arm64");
                        if (!fnStart) continue;
                        if (fnStart.compare(BASE) < 0 || fnStart.compare(MOD_END) >= 0) continue;

                        // Only patch once per address
                        try {
                            if (anchor.isSsl_x509) {
                                safeReplace(fnStart,
                                    "ssl_x509_fn@" + fnStart,
                                    "int", ["pointer","pointer","pointer"],
                                    function(a, b, c) { return 1; }
                                );
                            } else {
                                // handshake.cc reference — likely ssl_verify_peer_cert
                                safeReplace(fnStart,
                                    "ssl_handshake_fn@" + fnStart,
                                    "int", ["pointer"],
                                    function(ssl) { return 0; } // ssl_verify_ok
                                );
                            }
                            layer2count++;
                        } catch(e) {}

                        off += 4; // skip ahead past this match
                    }
                });
            });
        });
    }

    if (layer2count > 0) log("Layer 2 (XREF scan): " + layer2count + " patches applied");

    // ── Layer 3: Byte pattern scan ────────────────────────────────────────
    // Known byte patterns for ssl_verify_peer_cert across Flutter versions.
    // These are the most reliable known-good patterns, not exhaustive.

    var PATTERNS = {
        // ARM64: Flutter 2.10 – 3.19
        // ssl_verify_peer_cert: common prologue + characteristic load sequence
        arm64: [
            // Pattern A: stp x29,x30 + sub sp + ldr w (load ssl->verify_mode)
            "FD 7B ?? A9 FD 03 00 91 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 94",
            // Pattern B: shorter prologue variant
            "FF C3 01 D1 FD 7B 03 A9 F4 4F 04 A9",
            // Pattern C: Flutter 3.10+
            "FF 43 01 D1 FD 7B 02 A9 F4 4F 03 A9",
        ],
        // ARM32 / Thumb-2: Flutter on 32-bit Android
        arm: [
            // PUSH {r4-r7, lr} variants
            "2D E9 F0 4F",
            "2D E9 F8 4F",
            "2D E9 70 40",
        ],
        // x86_64: Android emulators (x86_64 AVDs)
        x64: [
            // push rbp; mov rbp,rsp; push r15; push r14
            "55 48 89 E5 41 57 41 56",
            // push rbp; sub rsp, 0x??
            "55 48 89 E5 48 83 EC",
        ],
        // x86: 32-bit emulators
        ia32: [
            "55 89 E5 53 57 56",
            "55 89 E5 57 56 53",
        ],
    };

    var archPatterns = PATTERNS[ARCH] || [];
    var layer3count  = 0;

    // We need context — scan near known BoringSSL string addresses
    // to narrow candidates and avoid false positives
    var boolStrHits = scanAll(roRanges,
        ARCH === "arm64" || ARCH === "arm"
            ? "73 73 6C 2F 73 73 6C 5F 78 35 30 39 2E 63 63 00"  // "ssl/ssl_x509.cc\0"
            : "73 73 6C 2F 73 73 6C 5F 78 35 30 39 2E 63 63 00"
    );
    var searchBase = boolStrHits.length > 0
        ? boolStrHits[0].sub(0x100000)  // search 1MB before string
        : BASE;
    var searchSize = boolStrHits.length > 0
        ? 0x200000  // 2MB window around the string
        : Math.min(MOD_SIZE, 0x1000000);  // fallback: first 16MB

    archPatterns.forEach(function(pat) {
        // Only search code ranges within window
        codeRanges.forEach(function(r) {
            if (r.base.compare(searchBase.add(searchSize)) > 0) return;
            if (r.base.add(r.size).compare(searchBase) < 0) return;

            var hits = scanRange(r, pat);
            hits.forEach(function(h) {
                if (layer3count >= 4) return; // cap at 4 patches per pattern
                safeReplace(h.address,
                    "ssl_pattern@" + h.address,
                    "int", ["pointer"],
                    function(ssl) { return 0; } // ssl_verify_ok
                );
                layer3count++;
            });
        });
    });

    if (layer3count > 0) log("Layer 3 (byte pattern): " + layer3count + " patches applied");

    // ── Layer 4: Dart VM exported hooks ──────────────────────────────────
    // Flutter exports Dart_* symbols. We hook SecurityContext initialization
    // and the Dart io.SecureSocket which is the Dart-level TLS stack.

    var layer4count = 0;

    // Hook Dart's SecurityContext_SetTrustedCertificatesBytes —
    // when found, replace with no-op to prevent custom CA pinning
    var dartSecCtxFn = Module.findExportByName("libflutter.so",
        "_Dart_SecurityContext_SetTrustedCertificatesBytes");
    if (!dartSecCtxFn) dartSecCtxFn = Module.findExportByName("libflutter.so",
        "SecurityContext_SetTrustedCertificatesBytes");
    if (dartSecCtxFn && !dartSecCtxFn.isNull()) {
        safeReplace(dartSecCtxFn,
            "SecurityContext_SetTrustedCertificatesBytes",
            "void", ["pointer"],
            function(args) { log("-> SecurityContext_SetTrustedCertificatesBytes no-op"); }
        );
        layer4count++;
    }

    // Hook Dart_NewStringFromCString — intercept "CERTIFICATE" PEM loading
    // (too broad; skip)

    // Hook ssl_ctx_set_alpn_select_cb if available — sometimes pinning check
    var alpnFn = Module.findExportByName("libflutter.so", "SSL_CTX_set_alpn_select_cb");
    if (alpnFn && !alpnFn.isNull()) {
        safeAttach(alpnFn, "SSL_CTX_set_alpn_select_cb", {
            onEnter: function(args) {
                log("-> SSL_CTX_set_alpn_select_cb intercepted");
            }
        });
        layer4count++;
    }

    if (layer4count > 0) log("Layer 4 (Dart VM): " + layer4count + " hooks installed");

    // ── Layer 5: Java bridge — platform channel + OkHttp used by plugins ──
    // Flutter plugins often use OkHttp3 or HttpsURLConnection on the Java side.
    // These are already covered by bypass_okhttp3.js and bypass_trustmanager.js
    // but we add Flutter-specific channel hooks here.

    setTimeout(function() {
        Java.perform(function() {
            var layer5count = 0;

            // io.flutter.embedding.engine.FlutterJNI — bridge to Dart
            try {
                var FJNI = Java.use("io.flutter.embedding.engine.FlutterJNI");
                // nativeRunBundleAndSnapshotFromLibrary — called at engine start
                var _fjniRun = FJNI.nativeRunBundleAndSnapshotFromLibrary.overload('long','java.lang.String','java.lang.String','java.lang.String','android.content.res.AssetManager','[Ljava.lang.String;');
                _fjniRun.implementation = function(
                    nativeShellHolderId, bundlePath, entrypointFunctionName,
                    pathToEntrypointFunction, assetManager, entrypointArgs
                ) {
                    log("-> Flutter engine starting: " + entrypointFunctionName);
                    return _fjniRun.call(this,
                        nativeShellHolderId, bundlePath, entrypointFunctionName,
                        pathToEntrypointFunction, assetManager, entrypointArgs
                    );
                };
                log("+ Layer 5: FlutterJNI.nativeRunBundleAndSnapshotFromLibrary hooked");
                layer5count++;
            } catch(e) {}

            // io.flutter.plugin.common.MethodChannel — intercept HTTP method calls
            try {
                var MC = Java.use("io.flutter.plugin.common.MethodChannel");
                // invokeMethod — log all platform channel calls
                // (too broad for production — just monitor)
                log("+ Layer 5: MethodChannel available");
                layer5count++;
            } catch(e) {}

            // Trust all certs via in-place TrustManager patching (no registerClass — Capacitor safe)
            try {
                var SSLCtx = Java.use("javax.net.ssl.SSLContext");
                var _sslInitF = SSLCtx.init.overload(
                    '[Ljavax.net.ssl.KeyManager;',
                    '[Ljavax.net.ssl.TrustManager;',
                    'java.security.SecureRandom'
                );
                _sslInitF.implementation = function(km, trustManagers, sr) {
                    if (!_isMainThread()) return _sslInitF.call(this, km, trustManagers, sr);
                    if (trustManagers !== null) {
                        try {
                            for (var j = 0; j < trustManagers.length; j++) {
                                var tm = trustManagers[j];
                                if (!tm) continue;
                                var cn = tm.getClass().getName();
                                try {
                                    var TC = Java.use(cn);
                                    if (TC.checkServerTrusted) {
                                        TC.checkServerTrusted.overloads.forEach(function(ol) {
                                            if (!ol || typeof ol.implementation === "undefined") return;
                                            ol.implementation = function() {
                                                log("-> Flutter plugin TM.checkServerTrusted bypassed");
                                            };
                                        });
                                    }
                                } catch(e2) {}
                            }
                        } catch(e3) {}
                    }
                    log("-> SSLContext.init bypassed (Flutter plugin layer)");
                    return _sslInitF.call(this, km, trustManagers, sr);
                };
                log("+ Layer 5: SSLContext in-place patch installed");
                layer5count++;
            } catch(e) {}

            if (layer5count > 0) log("Layer 5 (Java bridge): " + layer5count + " hooks installed");
        });
    }, 1000);

    // ── Summary ────────────────────────────────────────────────────────────
    var total = layer1count + layer2count + layer3count + layer4count;
    log("Layers complete: " + total + " native patches + Java layer pending");
    if (total === 0) {
        log("WARNING: No native patches applied — app may still verify SSL.");
        log("         Flutter build may be stripped/obfuscated. Check with:");
        log("         frida -U -n com.app.name -e \"Process.findModuleByName('libflutter.so')\"");
    }

})();
