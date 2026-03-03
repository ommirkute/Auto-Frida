// ==================== XAMARIN / MONO SSL BYPASS ====================
// Covers Xamarin.Android and Mono-based apps.

// Mono.Android.SSL — Xamarin wraps Android SSL through Mono runtime
try {
    var MonoSSL = Java.use("mono.android.ssl.NotifyingX509TrustManager");
    MonoSSL.checkServerTrusted.overloads.forEach(function(m) {
        m.implementation = function() {
            console.log("[AA] -> Xamarin NotifyingX509TrustManager bypassed");
        };
    });
    console.log("[AA] + Xamarin NotifyingX509TrustManager bypass installed");
} catch(e) {}

// Xamarin.Android.Net.AndroidClientHandler (used with HttpClient)
try {
    var ACH = Java.use("xamarin.android.net.AndroidClientHandler");
    ACH.verifyServerCertificate.overloads.forEach(function(m) {
        m.implementation = function() {
            console.log("[AA] -> Xamarin AndroidClientHandler.verifyServerCertificate bypassed");
            return true;
        };
    });
    console.log("[AA] + Xamarin AndroidClientHandler bypass installed");
} catch(e) {}

// Xamarin ServicePointManager equivalent — custom validator
try {
    var SPM = Java.use("xamarin.android.net.ServicePointManager");
    if (SPM.ServerCertificateValidationCallback && SPM.ServerCertificateValidationCallback.value !== null) {
        console.log("[AA] -> Xamarin ServerCertificateValidationCallback found");
    }
} catch(e) {}

// Native Mono: mono_unity_liveness_stop_gc_world / mono_runtime_invoke — these
// are the paths Xamarin uses to call managed code. We hook at the Java bridge layer
// since direct Mono IL hooking requires Mono-specific Frida extensions.
// Instead, catch all SSLContext and TrustManager usage as in bypass_trustmanager.js.

// Also hook OkHttp if Xamarin uses it via NuGet bindings
try {
    var XOkHttp = Java.use("com.squareup.okhttp3.CertificatePinner");
    XOkHttp.check.overloads.forEach(function(m) {
        m.implementation = function() {
            console.log("[AA] -> Xamarin OkHttp3 CertificatePinner bypassed");
        };
    });
} catch(e) {}

console.log("[AA] Xamarin/Mono bypass script loaded");
