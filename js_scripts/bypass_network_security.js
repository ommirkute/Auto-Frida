// ==================== NETWORK SECURITY CONFIG BYPASS ====================
try {
    var NSC = Java.use("android.security.net.config.NetworkSecurityConfig");
    NSC.isCleartextTrafficPermitted.overload().implementation = function() {
        console.log("[AA] -> Cleartext permitted (no-arg)");
        return true;
    };
    try {
        NSC.isCleartextTrafficPermitted.overload('java.lang.String').implementation = function(h) {
            console.log("[AA] -> Cleartext permitted for: " + h);
            return true;
        };
    } catch(e) {}
    console.log("[AA] + NetworkSecurityConfig bypass installed");
} catch(e) {}

try {
    var PS = Java.use("android.security.net.config.PinSet");
    PS.getPins.implementation = function() {
        console.log("[AA] -> PinSet.getPins bypassed");
        return Java.use("java.util.LinkedHashSet").$new();
    };
    console.log("[AA] + PinSet bypass installed");
} catch(e) {}
