// ==================== OKHTTP3 SSL PINNING BYPASS ====================
// Android 12-16 safe: explicit overload captures, correct return types.

// ── CertificatePinner.check — the main pinning call ────────────────────────
// Both overloads: check(hostname) and check(hostname, peerCertificates)
// Must return void (not return a value) — just swallow the call.
try {
    var CP = Java.use("okhttp3.CertificatePinner");
    CP.check.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> OkHttp3 CertificatePinner.check bypassed: " +
                (arguments[0] ? arguments[0].toString() : "?"));
            // Return void — do NOT throw, do NOT return a value
        };
    });
    console.log("[AA] + OkHttp3 CertificatePinner.check bypass installed");
} catch(e) {
    console.log("[AA] OkHttp3 CertificatePinner not found: " + e);
}

// ── CertificatePinner.Builder.add — prevent pins from being added ──────────
// Must return the Builder instance (this) — correct return type.
try {
    var CPB = Java.use("okhttp3.CertificatePinner$Builder");
    CPB.add.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> OkHttp3 CertificatePinner.Builder.add blocked: " +
                (arguments[0] ? arguments[0].toString() : "?"));
            return this;  // return Builder (correct — add() returns Builder)
        };
    });
    console.log("[AA] + OkHttp3 CertificatePinner.Builder.add bypass installed");
} catch(e) {}

// ── OkHttpClient.Builder.certificatePinner — prevent pinner attachment ─────
// Must return the OkHttpClient$Builder instance.
try {
    var OkB = Java.use("okhttp3.OkHttpClient$Builder");
    var _certPinner = OkB.certificatePinner.overload("okhttp3.CertificatePinner");
    _certPinner.implementation = function(pinner) {
        console.log("[AA] -> OkHttp3 OkHttpClient.Builder.certificatePinner bypassed");
        return this;  // return Builder (correct — certificatePinner() returns Builder)
    };
    console.log("[AA] + OkHttp3 Builder.certificatePinner bypass installed");
} catch(e) {}

// ── OkHttp2 (com.squareup.okhttp) ─────────────────────────────────────────
try {
    var CP2 = Java.use("com.squareup.okhttp.CertificatePinner");
    CP2.check.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> OkHttp2 CertificatePinner.check bypassed");
        };
    });
    console.log("[AA] + OkHttp2 CertificatePinner bypass installed");
} catch(e) {}
