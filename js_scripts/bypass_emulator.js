// ==================== EMULATOR DETECTION BYPASS ====================
try {
    var TM = Java.use("android.telephony.TelephonyManager");

    try { TM.getSimOperatorName.implementation   = function() { return "T-Mobile"; }; } catch(e) {}
    try { TM.getNetworkOperatorName.implementation = function() { return "T-Mobile"; }; } catch(e) {}
    try { TM.getSimOperator.implementation        = function() { return "310260"; }; }   catch(e) {}
    try { TM.getNetworkOperator.implementation    = function() { return "310260"; }; }   catch(e) {}
    try { TM.getLine1Number.implementation        = function() { return "+15555215554"; }; } catch(e) {}
    try {
        // getDeviceId removed in API 29 — guard against missing/broken overloads
        var _devIdMethod = TM.getDeviceId;
        if (_devIdMethod && _devIdMethod.overloads && _devIdMethod.overloads.length > 0) {
            _devIdMethod.overloads.forEach(function(ol) {
                ol.implementation = function() { return "358240051111110"; };
            });
        }
    } catch(e) {}

    console.log("[AA] + TelephonyManager emulator bypass installed");
} catch(e) {}
