// ==================== ANTI-FRIDA SELF-PROTECTION ====================
// Depends on _native_resolver.js. Gracefully skips any symbol not found
// or not executable (common on Android 16 where many libc fns are inlined).
console.log("[AA-Shield] Installing anti-Frida protection...");

// Helper: try to replace a native symbol, skip gracefully if unavailable
function tryNativeReplace(name, retType, argTypes, impl) {
    try {
        var ptr = _findNativeSym(name);
        if (!ptr) { console.log("[AA-Shield] " + name + " not hookable (not found/exported)"); return false; }
        var orig = new NativeFunction(ptr, retType, argTypes);
        Interceptor.replace(ptr, new NativeCallback(function() {
            return impl.apply(this, [orig].concat(Array.prototype.slice.call(arguments)));
        }, retType, argTypes));
        console.log("[AA-Shield] + " + name + "() hook installed");
        return true;
    } catch(e) {
        console.log("[AA-Shield] " + name + " hook skipped: " + e.message);
        return false;
    }
}

// ── open() — block /proc/net/tcp and frida-related paths ────────────────────
tryNativeReplace("open", "int", ["pointer", "int"],
    function(orig, pathPtr, flags) {
        var path = "";
        try { path = pathPtr.readCString() || ""; } catch(e) {}
        if (path.indexOf("/proc/net/tcp") !== -1 || path.indexOf("frida") !== -1)
            return -1;
        return orig(pathPtr, flags);
    });

// ── fgets() — scrub Frida-identifying lines ─────────────────────────────────
tryNativeReplace("fgets", "pointer", ["pointer", "int", "pointer"],
    function(orig, buf, size, fp) {
        var result = orig(buf, size, fp);
        if (!result.isNull()) {
            try {
                var line = buf.readCString() || "";
                if (line.indexOf("frida") !== -1 || line.indexOf("27042") !== -1 ||
                    line.indexOf("linjector") !== -1) {
                    return orig(buf, size, fp); // skip this line
                }
            } catch(e) {}
        }
        return result;
    });

// ── strstr() — lie about Frida presence ─────────────────────────────────────
tryNativeReplace("strstr", "pointer", ["pointer", "pointer"],
    function(orig, haystack, needle) {
        try {
            var n = needle.isNull() ? "" : (needle.readCString() || "");
            if (n === "frida" || n === "gadget" || n === "gum-js-loop") return ptr(0);
        } catch(e) {}
        return orig(haystack, needle);
    });

// ── strcmp() — lie about Frida process names ─────────────────────────────────
tryNativeReplace("strcmp", "int", ["pointer", "pointer"],
    function(orig, s1, s2) {
        try {
            var a = s1.isNull() ? "" : (s1.readCString() || "");
            var b = s2.isNull() ? "" : (s2.readCString() || "");
            if ((a + b).indexOf("frida") !== -1) return -1;
        } catch(e) {}
        return orig(s1, s2);
    });

// ── Java: StackTrace and Socket ───────────────────────────────────────────────
setTimeout(function() {
    Java.perform(function() {
        try {
            var Thread = Java.use("java.lang.Thread");
            Thread.getStackTrace.implementation = function() {
                var traces = this.getStackTrace.call(this);
                var out = [];
                for (var i = 0; i < traces.length; i++) {
                    var f = traces[i].toString();
                    if (f.indexOf("frida") === -1 && f.indexOf("gadget") === -1) out.push(traces[i]);
                }
                return out;
            };
            console.log("[AA-Shield] + StackTrace filter installed");
        } catch(e) {}

        try {
            var Socket = Java.use("java.net.Socket");
            var _sockInit = Socket.$init.overload("java.lang.String", "int");
            _sockInit.implementation = function(host, port) {
                if (port === 27042 || port === 27043)
                    throw Java.use("java.io.IOException").$new("Connection refused");
                return _sockInit.call(this, host, port);
            };
            console.log("[AA-Shield] + Socket filter installed");
        } catch(e) {}
    });
}, 500);

console.log("[AA-Shield] Anti-Frida shield active");
