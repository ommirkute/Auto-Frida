// Flutter SSL Pinning Bypass
// Works with Flutter apps using BoringSSL

var defined_functions = {};

function hook_ssl_verify_result(address) {
    Interceptor.attach(address, {
        onEnter: function(args) {
            console.log("[+] ssl_verify_result called");
        },
        onLeave: function(retval) {
            console.log("[+] Original return: " + retval);
            retval.replace(0x1);
            console.log("[+] Returning 1 (success)");
        }
    });
}

function hook_boring_ssl_checks() {
    // Hook ssl_verify_peer_cert (BoringSSL)
    var ssl_verify_peer_cert = Module.findExportByName("libflutter.so", "ssl_verify_peer_cert");
    if (ssl_verify_peer_cert) {
        Interceptor.replace(ssl_verify_peer_cert, new NativeCallback(function(a, b, c) {
            console.log("[+] ssl_verify_peer_cert bypassed");
            return 0; // Return success
        }, 'int', ['pointer', 'pointer', 'pointer']));
    }
}

function find_ssl_verify_in_flutter() {
    console.log("[*] Searching for SSL verification in libflutter.so");
    
    var m = Process.findModuleByName("libflutter.so");
    if (!m) {
        console.log("[-] libflutter.so not found, waiting...");
        return false;
    }

    console.log("[+] libflutter.so found at: " + m.base);
    console.log("[+] Size: " + m.size);

    // Pattern for ssl_crypto_x509_session_verify_cert_chain
    // This is the function that performs certificate verification in BoringSSL
    var patterns = [
        "FF 03 01 D1 FD 7B 02 A9 FD 83 00 91 F4 4F 03 A9",
        "F5 0F 1D F8 F4 4F 02 A9 FD 7B 03 A9 FD C3 00 91",
        "FF 43 01 D1 FE 67 01 A9 F8 5F 02 A9 F6 57 03 A9"
    ];

    for (var i = 0; i < patterns.length; i++) {
        try {
            var results = Memory.scan(m.base, m.size, patterns[i], {
                onMatch: function(address, size) {
                    console.log("[+] Pattern found at: " + address);
                    if (!defined_functions[address]) {
                        defined_functions[address] = true;
                        hook_ssl_verify_result(address);
                    }
                },
                onComplete: function() {
                    console.log("[*] Pattern scan complete");
                }
            });
        } catch (e) {
            console.log("[-] Pattern " + i + " failed: " + e);
        }
    }

    // Alternative: Hook session_verify_cert_chain
    var session_verify = Module.findExportByName("libflutter.so", "session_verify_cert_chain");
    if (session_verify) {
        console.log("[+] Found session_verify_cert_chain at: " + session_verify);
        Interceptor.replace(session_verify, new NativeCallback(function(ssl, out_alert) {
            console.log("[+] session_verify_cert_chain bypassed");
            return 1; // Return success
        }, 'int', ['pointer', 'pointer']));
    }

    return true;
}

// Main execution
console.log("[*] Flutter SSL Pinning Bypass Started");

// Try immediately
if (!find_ssl_verify_in_flutter()) {
    // Wait for library to load
    var interval = setInterval(function() {
        if (find_ssl_verify_in_flutter()) {
            clearInterval(interval);
        }
    }, 500);
    
    // Also hook dlopen to catch library loading
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"), {
        onEnter: function(args) {
            this.library = args[0].readCString();
        },
        onLeave: function(retval) {
            if (this.library && this.library.indexOf("libflutter.so") !== -1) {
                console.log("[+] libflutter.so loaded via dlopen");
                setTimeout(function() {
                    find_ssl_verify_in_flutter();
                    hook_boring_ssl_checks();
                }, 100);
            }
        }
    });
}

console.log("[*] Flutter SSL Bypass Initialized");
