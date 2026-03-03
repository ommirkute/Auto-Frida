// ==================== ANTI-DEBUG BYPASS ====================
// Android 12+ note: uses findExportByName (null-safe) not getExportByName.

try {
    var D = Java.use("android.os.Debug");
    D.isDebuggerConnected.implementation = function() {
        console.log("[AA] -> isDebuggerConnected = false");
        return false;
    };
    console.log("[AA] + Debug.isDebuggerConnected bypass installed");
} catch(e) {}

try {
    Java.use("android.os.Debug").waitingForDebugger.implementation = function() {
        return false;
    };
    console.log("[AA] + Debug.waitingForDebugger bypass installed");
} catch(e) {}

// Monitor /proc/<pid>/status reads for TracerPid checks
try {
    var fopenPtr = Module.findExportByName("libc.so", "fopen");
    if (fopenPtr && !fopenPtr.isNull()) {
        Interceptor.attach(fopenPtr, {
            onEnter: function(args) {
                var p = "";
                try { p = args[0].readUtf8String(); } catch(e) {}
                if (p && p.indexOf("/proc/") !== -1 && p.indexOf("/status") !== -1) {
                    this.isStatusFile = true;
                    console.log("[AA] -> TracerPid status file access detected: " + p);
                }
            }
        });
        console.log("[AA] + TracerPid monitor installed");
    }
} catch(e) {}
