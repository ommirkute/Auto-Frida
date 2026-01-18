// Anti-Debug & Emulator Detection Bypass
// Bypasses common anti-tampering checks

Java.perform(function() {
    console.log("[*] Anti-Debug Bypass Loaded");

    // Debug.isDebuggerConnected() Bypass
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[+] Debug.isDebuggerConnected() bypassed");
        return false;
    };

    // Debug.waitingForDebugger() Bypass
    Debug.waitingForDebugger.implementation = function() {
        console.log("[+] Debug.waitingForDebugger() bypassed");
        return false;
    };

    // Emulator Detection Bypass
    var Build = Java.use('android.os.Build');
    
    // Override Build properties that indicate emulator
    var fields = {
        'FINGERPRINT': 'google/coral/coral:11/RQ3A.210805.001.A1/7474174:user/release-keys',
        'MODEL': 'Pixel 4 XL',
        'MANUFACTURER': 'Google',
        'BRAND': 'google',
        'DEVICE': 'coral',
        'PRODUCT': 'coral',
        'HARDWARE': 'coral',
        'BOARD': 'coral'
    };

    for (var field in fields) {
        try {
            Build[field].value = fields[field];
            console.log("[+] Build." + field + " set to: " + fields[field]);
        } catch (e) {
            console.log("[-] Could not set Build." + field);
        }
    }

    // Telephony Manager Bypass
    try {
        var TelephonyManager = Java.use('android.telephony.TelephonyManager');
        
        TelephonyManager.getDeviceId.overload().implementation = function() {
            console.log("[+] TelephonyManager.getDeviceId() spoofed");
            return "352099001761481";
        };

        TelephonyManager.getSimSerialNumber.implementation = function() {
            console.log("[+] TelephonyManager.getSimSerialNumber() spoofed");
            return "89014103211118510720";
        };

        TelephonyManager.getSubscriberId.implementation = function() {
            console.log("[+] TelephonyManager.getSubscriberId() spoofed");
            return "310260000000000";
        };

        TelephonyManager.getNetworkOperatorName.implementation = function() {
            console.log("[+] TelephonyManager.getNetworkOperatorName() spoofed");
            return "T-Mobile";
        };
    } catch (e) {
        console.log("[-] TelephonyManager hooks failed");
    }

    // Settings.Secure Bypass
    try {
        var Settings = Java.use('android.provider.Settings$Secure');
        Settings.getString.implementation = function(resolver, name) {
            if (name === "android_id") {
                console.log("[+] Settings.Secure.android_id spoofed");
                return "9774d56d682e549c";
            }
            return this.getString(resolver, name);
        };
    } catch (e) {
        console.log("[-] Settings.Secure hook failed");
    }

    // Timing Attack Prevention
    try {
        var SystemClock = Java.use('android.os.SystemClock');
        var originalUptimeMillis = SystemClock.uptimeMillis;
        var offset = 0;
        
        SystemClock.uptimeMillis.implementation = function() {
            var result = originalUptimeMillis.call(this);
            // Add small random offset to prevent timing attacks
            offset += Math.floor(Math.random() * 10);
            return result + offset;
        };
        console.log("[+] SystemClock timing bypass enabled");
    } catch (e) {
        console.log("[-] SystemClock hook failed");
    }

    // ptrace Anti-Debug (Native)
    try {
        var ptracePtr = Module.findExportByName(null, "ptrace");
        if (ptracePtr) {
            Interceptor.attach(ptracePtr, {
                onEnter: function(args) {
                    this.request = args[0].toInt32();
                },
                onLeave: function(retval) {
                    if (this.request === 0) { // PTRACE_TRACEME
                        console.log("[+] ptrace(PTRACE_TRACEME) bypassed");
                        retval.replace(0);
                    }
                }
            });
        }
    } catch (e) {
        console.log("[-] ptrace hook failed");
    }

    // /proc/self/status TracerPid check
    try {
        var fopen = Module.findExportByName("libc.so", "fopen");
        Interceptor.attach(fopen, {
            onEnter: function(args) {
                this.path = args[0].readCString();
            },
            onLeave: function(retval) {
                if (this.path && this.path.indexOf("/proc/") !== -1 && 
                    this.path.indexOf("status") !== -1) {
                    console.log("[+] Detected /proc/status access: " + this.path);
                }
            }
        });
    } catch (e) {
        console.log("[-] fopen hook failed");
    }

    // Frida Detection Bypass - Hide frida-server
    try {
        var openat = Module.findExportByName("libc.so", "openat");
        Interceptor.attach(openat, {
            onEnter: function(args) {
                var path = args[1].readCString();
                if (path && (path.indexOf("frida") !== -1 || 
                            path.indexOf("linjector") !== -1 ||
                            path.indexOf("agent") !== -1)) {
                    console.log("[+] Blocking access to: " + path);
                    args[1] = Memory.allocUtf8String("/dev/null");
                }
            }
        });
    } catch (e) {
        console.log("[-] openat hook failed");
    }

    console.log("[*] Anti-Debug Bypass Complete!");
});
