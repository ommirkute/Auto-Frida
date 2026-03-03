// ==================== SHARED NATIVE LIBRARY RESOLVER ====================
// Resolves libc/bionic exports on ALL Android versions including API 36.
//
// Android 16 (API 36) changes:
//   - libc lives at /apex/com.android.runtime/lib64/bionic/libc.so
//   - Many C library functions (open, fopen, fgets, strcmp, strstr) are
//     no longer exported from libc in the traditional sense on x86_64 --
//     they may be PLT stubs or inlined. We verify the pointer is executable.
//   - __system_property_get IS still exported but must be found via
//     Module.findExportByName(null, ...) (process-wide search).
//
// _findNativeSym(name) → NativePointer (verified executable) or null
// _isExecPtr(ptr)      → bool
// ========================================================================
"use strict";
(function() {
    if (typeof globalThis._findNativeSym !== "undefined") return;

    function _isExecPtr(ptr) {
        if (!ptr || ptr.isNull()) return false;
        try {
            var range = Process.findRangeByAddress(ptr);
            return range !== null && range.protection.indexOf("x") !== -1;
        } catch(e) { return false; }
    }

    function _findNativeSym(name) {
        // 1. Process-wide search first (catches apex bionic on Android 12-16)
        try {
            var p = Module.findExportByName(null, name);
            if (p && !p.isNull() && _isExecPtr(p)) return p;
        } catch(e) {}

        // 2. Named module fallback list
        var candidates = ["libc.so", "libc.bionic", "libSystem.B.dylib"];
        for (var i = 0; i < candidates.length; i++) {
            try {
                var p2 = Module.findExportByName(candidates[i], name);
                if (p2 && !p2.isNull() && _isExecPtr(p2)) return p2;
            } catch(e) {}
        }

        // 3. Enumerate all modules — catches any unusual module naming
        try {
            var mods = Process.enumerateModulesSync();
            for (var j = 0; j < mods.length; j++) {
                var mn = mods[j].name.toLowerCase();
                if (mn.indexOf("libc") === -1 && mn.indexOf("bionic") === -1) continue;
                try {
                    var p3 = Module.findExportByName(mods[j].name, name);
                    if (p3 && !p3.isNull() && _isExecPtr(p3)) return p3;
                } catch(e) {}
            }
        } catch(e) {}

        return null; // Not found or not executable — caller must skip gracefully
    }

    globalThis._findNativeSym = _findNativeSym;
    globalThis._isExecPtr     = _isExecPtr;
})();
