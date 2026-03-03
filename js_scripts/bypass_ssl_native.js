// ==================== NATIVE SSL BYPASS (libssl / libboringssl) ====================
// Patches native OpenSSL/BoringSSL certificate verification functions.
// Essential for Flutter, React Native (with native fetch), and C++ networking.

(function nativeSslBypass() {
    var sslLibs = [
        "libssl.so", "libssl.so.1.1", "libssl.so.3",
        "libboringssl.so", "libssl_boring.so"
    ];

    sslLibs.forEach(function(libName) {
        var mod = Process.findModuleByName(libName);
        if (!mod) return;
        console.log("[AA] Patching " + libName + " @ " + mod.base);

        // SSL_CTX_set_verify — sets the verification callback
        // Mode 0 = SSL_VERIFY_NONE (no verification)
        var setVerify = Module.findExportByName(libName, "SSL_CTX_set_verify");
        if (setVerify) {
            Interceptor.attach(setVerify, {
                onEnter: function(args) {
                    // Force mode=0 (SSL_VERIFY_NONE) and callback=NULL
                    args[1] = ptr(0);
                    args[2] = ptr(0);
                    console.log("[AA] -> SSL_CTX_set_verify forced to VERIFY_NONE");
                }
            });
            console.log("[AA] + SSL_CTX_set_verify patched (" + libName + ")");
        }

        // SSL_CTX_set_cert_verify_callback — removes custom cert verifier
        var setCertVerify = Module.findExportByName(libName, "SSL_CTX_set_cert_verify_callback");
        if (setCertVerify) {
            Interceptor.attach(setCertVerify, {
                onEnter: function(args) {
                    args[1] = ptr(0);
                    args[2] = ptr(0);
                    console.log("[AA] -> SSL_CTX_set_cert_verify_callback cleared");
                }
            });
            console.log("[AA] + SSL_CTX_set_cert_verify_callback patched (" + libName + ")");
        }

        // SSL_get_verify_result — return X509_V_OK (0)
        var getVerifyResult = Module.findExportByName(libName, "SSL_get_verify_result");
        if (getVerifyResult) {
            Interceptor.replace(getVerifyResult, new NativeCallback(function(ssl) {
                return 0;  // X509_V_OK
            }, 'long', ['pointer']));
            console.log("[AA] + SSL_get_verify_result replaced with OK (" + libName + ")");
        }

        // X509_verify_cert — return 1 (success)
        var x509Verify = Module.findExportByName(libName, "X509_verify_cert");
        if (x509Verify) {
            Interceptor.replace(x509Verify, new NativeCallback(function(ctx) {
                return 1;  // success
            }, 'int', ['pointer']));
            console.log("[AA] + X509_verify_cert replaced with success (" + libName + ")");
        }

        // SSL_CTX_set_alpn_protos — not verification but sometimes checked
        // We leave this as-is; only patch verification functions.
    });

    // Flutter-specific: libflutter.so embeds BoringSSL but exports differ
    var flutterLib = Process.findModuleByName("libflutter.so");
    if (flutterLib) {
        console.log("[AA] Flutter detected — scanning for BoringSSL exports in libflutter.so");
        // Flutter statically links BoringSSL so we cannot use findExportByName.
        // Instead we rely on the Java layer (bypass_flutter_ssl.js) for Flutter apps.
        // Advanced: memory pattern scan for ssl_verify_peer_cert() can be done here.
        console.log("[AA] Flutter SSL: use bypass_flutter_ssl.js for full coverage");
    }
})();
