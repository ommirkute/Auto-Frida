// ==================== BIOMETRIC / KEYGUARD GATE BYPASS ====================
// Some fintech/banking apps gate access behind biometric or device lock checks.
// This script spoofs those checks to return "available" and "authenticated".

// BiometricManager.canAuthenticate — return BIOMETRIC_SUCCESS (0)
try {
    var BM = Java.use("android.hardware.biometrics.BiometricManager");
    BM.canAuthenticate.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> BiometricManager.canAuthenticate bypassed (BIOMETRIC_SUCCESS)");
            return 0; // BIOMETRIC_SUCCESS
        };
    });
    console.log("[AA] + BiometricManager.canAuthenticate bypass installed");
} catch(e) {}

// androidx.biometric.BiometricManager (Jetpack wrapper)
try {
    var ABM = Java.use("androidx.biometric.BiometricManager");
    ABM.canAuthenticate.overloads.forEach(function(ol) {
        ol.implementation = function() {
            console.log("[AA] -> androidx BiometricManager.canAuthenticate bypassed");
            return 0;
        };
    });
    console.log("[AA] + androidx BiometricManager bypass installed");
} catch(e) {}

// KeyguardManager.isDeviceSecure — return true (device has lock screen)
try {
    var KG = Java.use("android.app.KeyguardManager");
    KG.isDeviceSecure.implementation = function() {
        console.log("[AA] -> KeyguardManager.isDeviceSecure bypassed (true)");
        return true;
    };
    try {
        KG.isKeyguardSecure.implementation = function() {
            console.log("[AA] -> KeyguardManager.isKeyguardSecure bypassed (true)");
            return true;
        };
    } catch(e) {}
    try {
        KG.isKeyguardLocked.implementation = function() {
            return false; // not locked — skip lock check
        };
    } catch(e) {}
    console.log("[AA] + KeyguardManager bypass installed");
} catch(e) {}

// FingerprintManager (deprecated API 28 but still used)
try {
    var FM = Java.use("android.hardware.fingerprint.FingerprintManager");
    FM.isHardwareDetected.implementation = function() { return true; };
    FM.hasEnrolledFingerprints.implementation = function() { return true; };
    console.log("[AA] + FingerprintManager bypass installed");
} catch(e) {}
