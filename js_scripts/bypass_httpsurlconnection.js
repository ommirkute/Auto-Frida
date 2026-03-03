// ==================== HTTPSURLCONNECTION / VOLLEY / RETROFIT SSL BYPASS ====================
// Android 12-16: explicit .call(this) on all overloaded method invocations.
// Capacitor/Cordova safe: NO Java.registerClass() — avoids NPE in MockCordovaWebViewImpl.
// Strategy: hook setSSLSocketFactory / setHostnameVerifier to intercept pinning installs,
//           then patch the provided object's methods in-place instead of replacing them.

// ── Thread safety guard — pure native, zero Java calls ───────────────────────
// _isMainThread() defined once globally in bypass_adb_debug.js which is always
// included before this script. If running standalone, define it here as fallback.
if (typeof _isMainThread === "undefined") {
    var _mainThreadId = Process.getCurrentThreadId();
    var _safeAfterMs  = Date.now() + 4000;
    function _isMainThread() {
        if (Date.now() > _safeAfterMs) return true;
        return Process.getCurrentThreadId() === _mainThreadId;
    }
}

function _isCapacitorCaller() {
    return !_isMainThread();
}

// ── HttpsURLConnection.setSSLSocketFactory / setHostnameVerifier ──────────────────────────
try {
    var HTTPS = Java.use("javax.net.ssl.HttpsURLConnection");
    var _setSSL = HTTPS.setSSLSocketFactory.overload('javax.net.ssl.SSLSocketFactory');
    _setSSL.implementation = function(f) {
        console.log("[AA] -> HttpsURLConnection.setSSLSocketFactory bypassed");
        return _setSSL.call(this, f);
    };
    var _setHV = HTTPS.setHostnameVerifier.overload('javax.net.ssl.HostnameVerifier');
    _setHV.implementation = function(v) {
        console.log("[AA] -> HttpsURLConnection.setHostnameVerifier bypassed");
        return _setHV.call(this, v);
    };
    console.log("[AA] + HttpsURLConnection bypass installed");
} catch(e) {}

// ── SSLContext.init — NO registerClass, Capacitor/Cordova safe ───────────────────────────
// Instead of injecting a new TrustManager class (which breaks Capacitor's WebView init),
// we intercept init() calls and patch the caller's TrustManager array in-place.
// Capacitor/Cordova callers are skipped entirely to prevent NPE crashes.
try {
    var SSLCtx = Java.use("javax.net.ssl.SSLContext");
    var _sslInit = SSLCtx.init.overload(
        '[Ljavax.net.ssl.KeyManager;',
        '[Ljavax.net.ssl.TrustManager;',
        'java.security.SecureRandom'
    );
    _sslInit.implementation = function(km, trustManagers, sr) {
        // ── Guard: skip Capacitor / Cordova / WebView callers ──
        if (_isCapacitorCaller()) {
            console.log("[AA] -> SSLContext.init: skipping Capacitor/Cordova caller");
            return _sslInit.call(this, km, trustManagers, sr);
        }

        // ── Patch each TrustManager in-place ──
        if (trustManagers !== null) {
            try {
                for (var j = 0; j < trustManagers.length; j++) {
                    var tm = trustManagers[j];
                    if (!tm) continue;
                    var cn = tm.getClass().getName();
                    try {
                        var TC = Java.use(cn);
                        TC.checkServerTrusted.overloads.forEach(function(ol) {
                            if (!ol || typeof ol.implementation === "undefined") return;
                            ol.implementation = function() {
                                console.log("[AA] -> " + cn + ".checkServerTrusted bypassed (universal)");
                            };
                        });
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

        console.log("[AA] -> SSLContext.init: TrustManagers patched in-place (universal)");
        return _sslInit.call(this, km, trustManagers, sr);
    };
    console.log("[AA] + SSLContext universal bypass installed");
} catch(e) {}

// ── Default HostnameVerifier — NO registerClass, Capacitor/Cordova safe ──────────────────
// Instead of setDefaultHostnameVerifier(TAH.$new()), hook the call site and patch
// the provided HV in-place. Capacitor/Cordova callers are skipped to prevent crashes.
try {
    var HTTPSU = Java.use("javax.net.ssl.HttpsURLConnection");
    HTTPSU.setDefaultHostnameVerifier.implementation = function(hv) {
        if (_isCapacitorCaller()) {
            console.log("[AA] -> setDefaultHostnameVerifier: skipping Capacitor/Cordova caller");
            return this.setDefaultHostnameVerifier.call(this, hv);
        }
        if (hv !== null) {
            try {
                var hvCn = hv.getClass().getName();
                var HVC = Java.use(hvCn);
                HVC.verify.overloads.forEach(function(ol) {
                    ol.implementation = function() {
                        console.log("[AA] -> HostnameVerifier.verify bypassed: " + arguments[0]);
                        return true;
                    };
                });
            } catch(e2) {}
        }
        return this.setDefaultHostnameVerifier.call(this, hv);
    };
    console.log("[AA] + Default HostnameVerifier bypassed");
} catch(e) {}

// ── SSLSocket.startHandshake ──────────────────────────────────────────────────────────────
try {
    var SSLSocket = Java.use("javax.net.ssl.SSLSocket");
    var _startHS = SSLSocket.startHandshake.overload();
    _startHS.implementation = function() {
        console.log("[AA] -> SSLSocket.startHandshake bypassed");
        return _startHS.call(this);
    };
    console.log("[AA] + SSLSocket.startHandshake bypass installed");
} catch(e) {}

// ── Volley HurlStack ──────────────────────────────────────────────────────────────────────
try {
    var HurlStack = Java.use("com.android.volley.toolbox.HurlStack");
    var _createConn = HurlStack.createConnection.overload('java.net.URL');
    _createConn.implementation = function(url) {
        console.log("[AA] -> Volley HurlStack.createConnection intercepted");
        return _createConn.call(this, url);
    };
    console.log("[AA] + Volley HurlStack hook installed");
} catch(e) {}
