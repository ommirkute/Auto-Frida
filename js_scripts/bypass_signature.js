// ==================== SIGNATURE / TAMPER DETECTION BYPASS ====================
// Android 12-16: explicit .call(this) on all overloaded method invocations.

// Monitor signature-flag reads
try {
    var PM = Java.use("android.app.ApplicationPackageManager");

    var _getPkgInt = PM.getPackageInfo.overload('java.lang.String', 'int');
    _getPkgInt.implementation = function(pkg, flags) {
        if ((flags & 0x40) !== 0 || (flags & 0x8000000) !== 0)
            console.log("[AA] -> Signature check intercepted for: " + pkg);
        return _getPkgInt.call(this, pkg, flags);
    };

    // API 33+ (Android 13) — use overloads[] to safely find the right variant
    try {
        PM.getPackageInfo.overloads.forEach(function(ol) {
            var types = ol.argumentTypes.map(function(t) { return t.className; });
            // Only hook the PackageInfoFlags variant (not the int variant — already hooked above)
            if (types.length === 2 && types[1] !== "int" && types[0] === "java.lang.String") {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    console.log("[AA] -> Signature check (API33) intercepted for: " + arguments[0]);
                    return ol.apply(_self, _args);
                };
            }
        });
    } catch(e) {}

    console.log("[AA] + PackageManager.getPackageInfo signature monitor installed");
} catch(e) {}

// Spoof installer to Google Play Store
try {
    var PM2 = Java.use("android.app.ApplicationPackageManager");
    var _getInstaller = PM2.getInstallerPackageName.overload('java.lang.String');
    _getInstaller.implementation = function(pkg) {
        console.log("[AA] -> Installer spoof for: " + pkg);
        return "com.android.vending";
    };
    console.log("[AA] + getInstallerPackageName spoof installed");
} catch(e) {}

// API 30+ getInstallSourceInfo
try {
    var PM3 = Java.use("android.app.ApplicationPackageManager");
    var _getInstallSrc = PM3.getInstallSourceInfo.overload('java.lang.String');
    _getInstallSrc.implementation = function(pkg) {
        console.log("[AA] -> getInstallSourceInfo intercepted for: " + pkg);
        return _getInstallSrc.call(this, pkg);
    };
} catch(e) {}

// Monitor MessageDigest (hash verification / certificate pinning checks)
try {
    var MD = Java.use("java.security.MessageDigest");
    var _digest0 = MD.digest.overload();
    _digest0.implementation = function() {
        console.log("[AA] -> MessageDigest.digest() called (" + this.getAlgorithm() + ")");
        return _digest0.call(this);
    };
    try {
        var _digestB = MD.digest.overload('[B');
        _digestB.implementation = function(input) {
            console.log("[AA] -> MessageDigest.digest(bytes) called (" + this.getAlgorithm() + ", " + input.length + "B)");
            return _digestB.call(this, input);
        };
    } catch(e) {}
    console.log("[AA] + MessageDigest monitor installed");
} catch(e) {}
