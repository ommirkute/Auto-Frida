// ── Thread guard fallback (if not already defined by bypass_adb_debug.js) ────
if (typeof _isMainThread === "undefined") {
    var _mainThreadId = Process.getCurrentThreadId();
    var _safeAfterMs  = Date.now() + 4000;
    function _isMainThread() {
        if (Date.now() > _safeAfterMs) return true;
        return Process.getCurrentThreadId() === _mainThreadId;
    }
}

// ==================== TRUSTMANAGER / CONSCRYPT / SSLCONTEXT BYPASS ====================
// Android 12-16 safe.
//
// KEY FIX for Android 16:
//   Java.registerClass() throws "Permission denied" under SELinux enforcing.
//   SOLUTION: Hook existing TrustManager implementations that are already loaded
//   rather than injecting a new class. For SSLContext.init we skip WebView/Chromium
//   callers to prevent the SIGSEGV crash.

// ── TrustManagerImpl (Conscrypt) ─────────────────────────────────────────────
try {
    var TMI = Java.use("com.android.org.conscrypt.TrustManagerImpl");
    TMI.verifyChain.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
        ol.implementation = function() {
            console.log("[AA] -> TrustManagerImpl.verifyChain bypassed");
            return arguments[0]; // return untrusted chain — caller accepts it as trusted
        };
    });
    console.log("[AA] + TrustManagerImpl.verifyChain bypass installed");
} catch(e) { console.log("[AA] TrustManagerImpl: " + e.message); }

// ── Conscrypt socket verifyCertificateChain ────────────────────────────────────
["org.conscrypt.ConscryptFileDescriptorSocket",
 "org.conscrypt.ConscryptEngineSocket"].forEach(function(cls) {
    try {
        var C = Java.use(cls);
        C.verifyCertificateChain.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
            ol.implementation = function() {
                console.log("[AA] -> " + cls + ".verifyCertificateChain bypassed");
                // returns void
            };
        });
        console.log("[AA] + " + cls + " bypass installed");
    } catch(e) {}
});

// ── SSLContext.init — WITHOUT registerClass (Android 16 safe) ─────────────────
// Strategy: Hook the hook point BEFORE init runs. When init() is called with
// a real TrustManager array, we patch THAT TrustManager's checkServerTrusted
// method to be a no-op. This avoids registerClass entirely.
//
// Additionally: skip calls from WebView/Chromium to prevent SIGSEGV.
// Chromium has its own SSL stack and doesn't tolerate our TrustManager being
// injected into its SSLContext.
try {
    var SSLCtx = Java.use("javax.net.ssl.SSLContext");
    var _sslInit = SSLCtx.init.overload(
        "[Ljavax.net.ssl.KeyManager;",
        "[Ljavax.net.ssl.TrustManager;",
        "java.security.SecureRandom"
    );

    _sslInit.implementation = function(km, trustManagers, sr) {
        // Skip non-main threads during startup — pure native check, zero Java/JNI
        if (!_isMainThread()) {
            return _sslInit.call(this, km, trustManagers, sr);
        }

        // Patch each TrustManager in the array rather than replacing with our own class
        if (trustManagers !== null) {
            try {
                for (var j = 0; j < trustManagers.length; j++) {
                    var tm = trustManagers[j];
                    if (!tm) continue;
                    var tmClass = tm.getClass();
                    try {
                        var cst = tmClass.getMethod("checkServerTrusted",
                            [Java.use("java.security.cert.X509Certificate").class,
                             Java.use("java.lang.String").class]);
                        if (cst) {
                            // Hook it via Java.use on its actual class name
                            var cn = tmClass.getName();
                            try {
                                var TC = Java.use(cn);
                                TC.checkServerTrusted.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                                    ol.implementation = function() {
                                        console.log("[AA] -> " + cn + ".checkServerTrusted bypassed");
                                    };
                                });
                            } catch(e2) {}
                        }
                    } catch(e) {}
                }
            } catch(e) {}
        }

        console.log("[AA] -> SSLContext.init: TrustManagers patched in-place");
        return _sslInit.call(this, km, trustManagers, sr);
    };
    console.log("[AA] + SSLContext.init bypass installed (no registerClass)");
} catch(e) { console.log("[AA] SSLContext: " + e.message); }

// ── HostnameVerifier — patch via HttpsURLConnection default ───────────────────
// Avoid registerClass — instead hook the verify method on any loaded HV.
try {
    var HTTPSU = Java.use("javax.net.ssl.HttpsURLConnection");
    // Hook setDefaultHostnameVerifier calls to intercept when apps install pinning HVs
    HTTPSU.setDefaultHostnameVerifier.implementation = function(hv) {
        console.log("[AA] -> setDefaultHostnameVerifier intercepted — installing allow-all");
        // Install the existing HV but patch its verify method
        if (hv !== null) {
            try {
                var hvClass = hv.getClass().getName();
                var HVC = Java.use(hvClass);
                HVC.verify.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                    ol.implementation = function() {
                        console.log("[AA] -> HostnameVerifier.verify bypassed: " + arguments[0]);
                        return true;
                    };
                });
            } catch(e2) {}
        }
        return this.setDefaultHostnameVerifier.call(this, hv);
    };
    console.log("[AA] + HostnameVerifier interceptor installed");
} catch(e) { console.log("[AA] HostnameVerifier: " + e.message); }

// ── Custom app TrustManager scan — patch checkServerTrusted on any loaded impl ──
// Runs 2s after startup when more classes are loaded. Does NOT use registerClass.
setTimeout(function() {
    Java.perform(function() {
        try {
            var SKIP = /^(java\.|android\.|javax\.|sun\.|dalvik\.|kotlin\.|androidx\.|com\.google\.android\.|org\.conscrypt\.|com\.android\.)/;
            Java.enumerateLoadedClassesSync().forEach(function(cn) {
                if (SKIP.test(cn)) return;
                // Skip array descriptors ([L...;) and anonymous/proxy classes — not Java.use()-able
                if (cn.charAt(0) === "[" || cn.indexOf("$Proxy") !== -1) return;
                var cl = cn.toLowerCase();
                if (cl.indexOf("trustmanager") === -1 &&
                    cl.indexOf("x509") === -1 &&
                    cl.indexOf("certverif") === -1) return;
                try {
                    var C = Java.use(cn);
                    ["checkServerTrusted", "checkClientTrusted"].forEach(function(m) {
                        try {
                            var method = C[m];
                            if (!method || typeof method.overloads === "undefined") return;
                            method.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
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
