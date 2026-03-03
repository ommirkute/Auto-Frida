// ==================== ROOTBEER + ROOT LIBRARY BYPASS ====================
// Handles RootBeer and other common root detection library wrappers.
// bypass_generic_root.js handles the underlying system calls — this file
// handles the library-level abstraction on top.

// ── RootBeer (com.scottyab.rootbeer) ─────────────────────────────────────
(function() {
    var BOOL_FALSE_METHODS = [
        "isRooted", "isRootedWithoutBusyBoxCheck", "isRootedWithBusyBoxCheck",
        "detectRootManagementApps", "detectPotentiallyDangerousApps",
        "detectTestKeys", "checkForBusyBoxBinary", "checkForSuBinary",
        "checkSuExists", "checkForRWPaths", "checkForDangerousProps",
        "checkForRootNative", "detectRootCloakingApps", "checkForMagiskBinary",
        "isSelinuxFlagInEnabled", "checkSELinuxEnforcing",
        "checkForSuInPath", "checkForDangerousProperties",
        "checkForRWSystem"
    ];

    ["com.scottyab.rootbeer.RootBeer",
     "com.scottyab.rootbeer.RootBeerNative"].forEach(function(cls) {
        try {
            var RB = Java.use(cls);
            BOOL_FALSE_METHODS.forEach(function(m) {
                try {
                    if (!RB[m] || typeof RB[m].overloads === 'undefined' || !RB[m].overloads.length) return;
                    RB[m].overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                        ol.implementation = function() {
                            console.log("[RootBeer] " + m + " => false");
                            return false;
                        };
                    });
                } catch(e) {}
            });
            console.log("[AA] + RootBeer bypass installed: " + cls);
        } catch(e) {}
    });
})();

// ── SafetyNet / Play Integrity (often paired with root check) ─────────────
// (handled in bypass_safetynet.js — see that file)

// ── Common root detection wrapper classes (various SDKs) ─────────────────
(function() {
    // Pattern: any class whose simple name contains "Root", "Jailbreak",
    // "Integrity", "Tamper" and has a boolean isRooted/check method.
    // We do a targeted sweep of loaded classes 3s after startup.
    setTimeout(function() {
        Java.perform(function() {
            try {
                var TARGET_PATTERNS = [
                    /rootdetect/i, /rootcheck/i, /jailbreak/i,
                    /deviceintegrity/i, /tamperdetect/i, /antiroot/i,
                    /roothelper/i, /rootutil/i, /rootmanager/i
                ];
                var TARGET_METHODS = [
                    "isRooted","isDeviceRooted","checkRoot","hasRoot",
                    "isJailBroken","isCompromised","isDeviceCompromised",
                    "deviceIsRooted","rootDetected","isRootPresent",
                    "isDeviceSecure","isDeviceIntact"
                ];
                var SKIP = /^(java|android|javax|dalvik|kotlin|androidx|com\.google\.android|sun\.)/;

                Java.enumerateLoadedClassesSync().forEach(function(cn) {
                    if (SKIP.test(cn)) return;
                    if (cn.charAt(0) === "[" || cn.indexOf("$Proxy") !== -1) return;
                    var matches = TARGET_PATTERNS.some(function(re) { return re.test(cn); });
                    if (!matches) return;

                    if (cn.charAt(0) === "[" || cn.indexOf("$Proxy") !== -1) return;
                    try {
                        var C = Java.use(cn);
                        TARGET_METHODS.forEach(function(m) {
                            try {
                                if (!C[m]) return;
                                if (typeof C[m].overloads === 'undefined' || !C[m].overloads.length) return;
                                C[m].overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                                    var rt = ol.returnType ? ol.returnType.className : "";
                                    ol.implementation = function() {
                                        console.log("[AA] -> " + cn + "." + m + " bypassed");
                                        if (rt === "boolean" || rt === "Boolean") return false;
                                        if (rt === "int"     || rt === "Integer") return 0;
                                        return null;
                                    };
                                });
                            } catch(e2) {}
                        });
                    } catch(e) {}
                });
                console.log("[AA] + Root library class scan complete");
            } catch(e) {}
        });
    }, 3000);
})();
