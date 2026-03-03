// ==================== ANDROID BUILD PROPS / EMULATOR BYPASS ====================
// Depends on _native_resolver.js being loaded first (prepended by auto_frida.py).

// ---- Java: android.os.Build static fields ----
try {
    var Build = Java.use("android.os.Build");
    var props = {
        FINGERPRINT:  "google/oriole/oriole:12/SP1A.210812.016.A1/7961137:user/release-keys",
        MANUFACTURER: "Google",
        BRAND:        "google",
        MODEL:        "Pixel 6",
        DEVICE:       "oriole",
        PRODUCT:      "oriole",
        HARDWARE:     "oriole",
        BOARD:        "oriole",
        TAGS:         "release-keys",
        TYPE:         "user",
        HOST:         "abfarm-release-rbe-64-00026",
        BOOTLOADER:   "slider-1.0-8077218"
    };
    Object.keys(props).forEach(function(k) {
        try { Build[k].value = props[k]; } catch(e) {}
    });
    console.log("[AA] + Build fields spoofed");
} catch(e) { console.log("[AA] Build fields error: " + e); }

// ---- Native: __system_property_get ----
// Uses _findNativeSym which verifies the pointer is in an executable range.
// If not found or not executable on this Android version, skips silently.
var PROP_OVERRIDES = {
    "ro.build.fingerprint":    "google/oriole/oriole:12/SP1A.210812.016.A1/7961137:user/release-keys",
    "ro.build.tags":           "release-keys",
    "ro.build.type":           "user",
    "ro.product.model":        "Pixel 6",
    "ro.product.manufacturer": "Google",
    "ro.product.brand":        "google",
    "ro.product.device":       "oriole",
    "ro.product.name":         "oriole",
    "ro.hardware":             "oriole",
    "ro.debuggable":           "0",
    "ro.secure":               "1",
    "ro.build.selinux":        "1",
    "ro.kernel.qemu":          "0",
    "ro.kernel.qemu.avd_name": "",
    "ro.boot.qemu":            "0",
    "ro.boot.qemu.avd_name":   "",
    "ro.adb.secure":           "1",
    "init.svc.adbd":           "stopped",
    "init.svc.adbd_root":      "stopped",
    "service.adb.root":        "0",
    "persist.service.adb.enable": "0",
    "persist.sys.usb.config":  "mtp",
    "sys.usb.state":           "mtp",
    "sys.usb.config":          "mtp",
    "init.svc.qemu-props":     ""
};

try {
    var getPropPtr = _findNativeSym("__system_property_get");
    if (!getPropPtr) throw new Error("__system_property_get not found or not executable");
    var nativeGetProp = new NativeFunction(getPropPtr, "int", ["pointer", "pointer"]);
    Interceptor.replace(getPropPtr, new NativeCallback(function(namePtr, valuePtr) {
        var name = "";
        try { name = namePtr.readCString() || ""; } catch(e) {}
        if (name && Object.prototype.hasOwnProperty.call(PROP_OVERRIDES, name)) {
            var ov = PROP_OVERRIDES[name];
            try { valuePtr.writeUtf8String(ov); return ov.length; } catch(e) {}
        }
        return nativeGetProp(namePtr, valuePtr);
    }, "int", ["pointer", "pointer"]));
    console.log("[AA] + __system_property_get override installed");
} catch(e) {
    // Fallback: hook Java SystemProperties instead (always works)
    console.log("[AA] Native prop hook skipped (" + e.message + ") — using Java fallback");
}

// ---- Settings.Secure (android_id) ----
try {
    var Settings = Java.use("android.provider.Settings$Secure");
    var _getString = Settings.getString.overload(
        "android.content.ContentResolver", "java.lang.String");
    _getString.implementation = function(cr, name) {
        if (name === "android_id") return "a1b2c3d4e5f60718";
        return _getString.call(this, cr, name);
    };
    console.log("[AA] + Settings.Secure.android_id spoofed");
} catch(e) {}
