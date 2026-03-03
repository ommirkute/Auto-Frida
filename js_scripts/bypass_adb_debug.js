// ==================== USB DEBUGGING & DEVELOPER OPTIONS BYPASS ====================
// Covers every technique apps use to detect ADB / developer mode.
// Android 8 – 16 | All architectures.
//
// SPOOF STRATEGY:
//   Settings.Global/Secure/System → return 0 / "0" for all debug keys
//   Native __system_property_get  → already in bypass_build_props.js (extended here)
//   ActivityManager               → isRunningInTestHarness / isUserAMonkey → false
//   File system                   → block /sys/kernel/debug reads
//   ContentResolver.query         → spoof cursor result for settings provider
// ================================================================================

"use strict";

// ── Thread safety guard — pure native, zero Java calls ───────────────────────
// Captures the main thread ID at script load time using Frida's native API.
// All hook guards compare against this ID — no Java, no JNI, no re-entry risk.
var _mainThreadId = Process.getCurrentThreadId();
var _safeAfterMs  = Date.now() + 4000; // 4s startup window

function _isMainThread() {
    // After 4s startup window, allow all threads (app is stable)
    if (Date.now() > _safeAfterMs) return true;
    // During startup, only the main thread is guaranteed safe
    return Process.getCurrentThreadId() === _mainThreadId;
}

(function adbDebugBypass() {

    var TAG = "[ADB]";
    function log(msg) { console.log(TAG + " " + msg); }

    // ── Spoof tables ──────────────────────────────────────────────────────────
    // Keys that return 0 (int) when spoofed
    var INT_ZERO_KEYS = [
        "adb_enabled",
        "development_settings_enabled",
        "stay_on_while_plugged_in",
        "usb_configuration",
        "mock_location",
        "allow_mock_location",
        "install_non_market_apps",
        "package_verifier_enable",
        "wifi_on",           // some detectors check wifi-related dev settings
        "tether_dun_required",
        "user_setup_complete" // returning 1 for this would be correct, but some
                              // detectors treat 0 as "not a developer device"
    ];

    // Keys that return "0" (string) when spoofed
    var STR_ZERO_KEYS = [
        "adb_enabled",
        "development_settings_enabled",
        "stay_on_while_plugged_in",
        "mock_location",
        "allow_mock_location",
        "install_non_market_apps",
        "tether_dun_required"
    ];

    function isDebugIntKey(name) {
        for (var i = 0; i < INT_ZERO_KEYS.length; i++) {
            if (name === INT_ZERO_KEYS[i]) return true;
        }
        return false;
    }
    function isDebugStrKey(name) {
        for (var i = 0; i < STR_ZERO_KEYS.length; i++) {
            if (name === STR_ZERO_KEYS[i]) return true;
        }
        return false;
    }

    // ── Thread safety guard — pure native, zero Java calls ──────────────────────
    // Uses Frida's native Process.getCurrentThreadId() — no JNI, no re-entry risk.
    function _isUnsafeCaller() {
        return !_isMainThread();
    }

    // ── Settings.Global ───────────────────────────────────────────────────────
    // This is the PRIMARY source for ADB/dev options checks on Android 4.2+
    try {
        var SG = Java.use("android.provider.Settings$Global");

        // getInt(ContentResolver, String) → int
        var _sgGetInt2 = SG.getInt.overload(
            "android.content.ContentResolver", "java.lang.String");
        _sgGetInt2.implementation = function(cr, name) {
            if (_isUnsafeCaller()) return _sgGetInt2.call(this, cr, name);
            if (isDebugIntKey(name)) {
                log("Settings.Global.getInt(" + name + ") → 0");
                return 0;
            }
            return _sgGetInt2.call(this, cr, name);
        };

        // getInt(ContentResolver, String, int) → int  (with default)
        var _sgGetInt3 = SG.getInt.overload(
            "android.content.ContentResolver", "java.lang.String", "int");
        _sgGetInt3.implementation = function(cr, name, def) {
            if (_isUnsafeCaller()) return _sgGetInt3.call(this, cr, name, def);
            if (isDebugIntKey(name)) {
                log("Settings.Global.getInt(" + name + ",def) → 0");
                return 0;
            }
            return _sgGetInt3.call(this, cr, name, def);
        };

        // getString(ContentResolver, String) → String
        var _sgGetStr = SG.getString.overload(
            "android.content.ContentResolver", "java.lang.String");
        _sgGetStr.implementation = function(cr, name) {
            if (_isUnsafeCaller()) return _sgGetStr.call(this, cr, name);
            if (isDebugStrKey(name)) {
                log("Settings.Global.getString(" + name + ") → '0'");
                return "0";
            }
            return _sgGetStr.call(this, cr, name);
        };

        log("+ Settings.Global bypass installed (getInt/getString)");
    } catch(e) { log("Settings.Global error: " + e); }

    // ── Settings.Secure ───────────────────────────────────────────────────────
    // Legacy ADB check path (Android < 4.2) + android_id (already in build_props)
    try {
        var SS = Java.use("android.provider.Settings$Secure");

        var _ssGetInt2 = SS.getInt.overload(
            "android.content.ContentResolver", "java.lang.String");
        _ssGetInt2.implementation = function(cr, name) {
            if (_isUnsafeCaller()) return _ssGetInt2.call(this, cr, name);
            if (isDebugIntKey(name)) {
                log("Settings.Secure.getInt(" + name + ") → 0");
                return 0;
            }
            return _ssGetInt2.call(this, cr, name);
        };

        var _ssGetInt3 = SS.getInt.overload(
            "android.content.ContentResolver", "java.lang.String", "int");
        _ssGetInt3.implementation = function(cr, name, def) {
            if (_isUnsafeCaller()) return _ssGetInt3.call(this, cr, name, def);
            if (isDebugIntKey(name)) {
                log("Settings.Secure.getInt(" + name + ",def) → 0");
                return 0;
            }
            return _ssGetInt3.call(this, cr, name, def);
        };

        var _ssGetStr = SS.getString.overload(
            "android.content.ContentResolver", "java.lang.String");
        _ssGetStr.implementation = function(cr, name) {
            if (_isUnsafeCaller()) return _ssGetStr.call(this, cr, name);
            if (name === "android_id") return "a1b2c3d4e5f60718"; // keep existing spoof
            if (isDebugStrKey(name)) {
                log("Settings.Secure.getString(" + name + ") → '0'");
                return "0";
            }
            return _ssGetStr.call(this, cr, name);
        };

        log("+ Settings.Secure bypass installed (getInt/getString)");
    } catch(e) { log("Settings.Secure error: " + e); }

    // ── Settings.System ───────────────────────────────────────────────────────
    // Some OEM ROMs store adb_enabled in Settings.System
    try {
        var SY = Java.use("android.provider.Settings$System");

        var _syGetInt3 = SY.getInt.overload(
            "android.content.ContentResolver", "java.lang.String", "int");
        _syGetInt3.implementation = function(cr, name, def) {
            if (_isUnsafeCaller()) return _syGetInt3.call(this, cr, name, def);
            if (isDebugIntKey(name)) {
                log("Settings.System.getInt(" + name + ",def) → 0");
                return 0;
            }
            return _syGetInt3.call(this, cr, name, def);
        };

        var _syGetStr = SY.getString.overload(
            "android.content.ContentResolver", "java.lang.String");
        _syGetStr.implementation = function(cr, name) {
            if (_isUnsafeCaller()) return _syGetStr.call(this, cr, name);
            if (isDebugStrKey(name)) {
                log("Settings.System.getString(" + name + ") → '0'");
                return "0";
            }
            return _syGetStr.call(this, cr, name);
        };

        log("+ Settings.System bypass installed");
    } catch(e) { log("Settings.System error: " + e); }



    // ── ActivityManager flags ─────────────────────────────────────────────────
    try {
        var AM = Java.use("android.app.ActivityManager");

        // isRunningInTestHarness — true when launched via ADB instrumentation
        try {
            AM.isRunningInTestHarness.implementation = function() {
                log("isRunningInTestHarness → false");
                return false;
            };
        } catch(e) {}

        // isUserAMonkey — true during adb shell monkey
        try {
            AM.isUserAMonkey.implementation = function() {
                log("isUserAMonkey → false");
                return false;
            };
        } catch(e) {}

        // isRunningInUserTestHarness (API 29+)
        try {
            AM.isRunningInUserTestHarness.implementation = function() {
                log("isRunningInUserTestHarness → false");
                return false;
            };
        } catch(e) {}

        log("+ ActivityManager test/monkey hooks installed");
    } catch(e) { log("ActivityManager error: " + e); }

    // ── ApplicationInfo.FLAG_DEBUGGABLE ───────────────────────────────────────
    // Apps check their own ApplicationInfo.flags & FLAG_DEBUGGABLE (0x2)
    // We can't directly intercept field reads, but we hook getApplicationInfo
    // so our app appears non-debuggable to itself.
    try {
        var PM = Java.use("android.app.ApplicationPackageManager");
        // Hook getApplicationInfo for the app's own package
        var _gai = PM.getApplicationInfo.overload("java.lang.String", "int");
        var _orig_gai = _gai.implementation;  // may already be set by root bypass
        _gai.implementation = function(pkg, flags) {
            var info = _gai.call(this, pkg, flags);
            if (info !== null) {
                try {
                    // Clear FLAG_DEBUGGABLE (bit 1) from flags
                    var currentFlags = info.flags.value;
                    if ((currentFlags & 0x2) !== 0) {
                        info.flags.value = currentFlags & ~0x2;
                        log("ApplicationInfo.FLAG_DEBUGGABLE cleared for: " + pkg);
                    }
                } catch(e2) {}
            }
            return info;
        };
        log("+ ApplicationInfo.FLAG_DEBUGGABLE bypass installed");
    } catch(e) { log("ApplicationInfo error: " + e); }

    // ── Debug.isDebuggerConnected ─────────────────────────────────────────────
    try {
        var Dbg = Java.use("android.os.Debug");
        Dbg.isDebuggerConnected.implementation = function() {
            log("Debug.isDebuggerConnected → false");
            return false;
        };
        try {
            Dbg.waitingForDebugger.implementation = function() { return false; };
        } catch(e) {}
        log("+ Debug.isDebuggerConnected bypass installed");
    } catch(e) {}

    // Native __system_property_get ADB overrides are handled in bypass_build_props.js
    // (init.svc.adbd, service.adb.root, ro.adb.secure, persist.sys.usb.config etc.)
    // No duplicate hook here — Interceptor.replace cannot be applied twice to same address.
    log("+ Native ADB props covered by bypass_build_props.js");

    // /sys/kernel/debug fopen blocks are handled in bypass_generic_root.js
    log("+ /sys/kernel/debug path blocks covered by bypass_generic_root.js");

    // ── Java File blocks for debug-specific paths ─────────────────────────────
    try {
        var File = Java.use("java.io.File");
        var _origExists = File.exists.implementation;
        // Extend (not replace) the existing exists hook with debug paths
        // Since bypass_generic_root.js already sets File.exists.implementation,
        // we chain by wrapping the File class directly using a different approach:
        // Hook the specific paths that root bypass doesn't cover.
        var DEBUG_PATHS = [
            "/sys/kernel/debug",
            "/sys/kernel/debug/usb",
            "/proc/net/unix",
            "/sys/class/android_usb/android0/enable"
        ];
        // Extend existing hook if present, otherwise set new one
        var prevExists = File.exists.implementation;
        File.exists.implementation = function() {
            var path = this.getAbsolutePath().toString();
            for (var i = 0; i < DEBUG_PATHS.length; i++) {
                if (path.indexOf(DEBUG_PATHS[i]) === 0) {
                    log("File.exists blocked (debug): " + path);
                    return false;
                }
            }
            // Call previous implementation (from root bypass) or original
            return prevExists ? prevExists.call(this) : File.exists.call(this);
        };
        log("+ File.exists debug path block installed");
    } catch(e) { log("File debug block error: " + e); }

    // ContentResolver.query hook removed — Settings.Global/Secure/System hooks above
    // provide complete coverage. The query hook caused SIGSEGV crashes in spawn mode
    // due to Frida JNI re-entry during Parcel/IPC operations on background threads.
    log("+ ContentResolver: covered via Settings.* hooks");

    log("ADB/Developer bypass fully installed.");

})(); // end IIFE
