// ==================== SAFETYNET / PLAY INTEGRITY BYPASS ====================
// Android 12-16: explicit .call(this) / .apply(this) on all overloaded calls.
try {
    var SNC = Java.use("com.google.android.gms.safetynet.SafetyNetClient");
    var _attest = SNC.attest.overload('[B', 'java.lang.String');
    _attest.implementation = function(nonce, apiKey) {
        console.log("[AA] -> SafetyNet.attest intercepted");
        return _attest.call(this, nonce, apiKey);
    };
    console.log("[AA] + SafetyNet hook installed");
} catch(e) {}

try {
    var IM = Java.use("com.google.android.play.core.integrity.IntegrityManager");
    IM.requestIntegrityToken.overloads.forEach(function(ol) {
        ol.implementation = function() {
            var _self = this, _args = arguments;
            console.log("[AA] -> Play Integrity.requestIntegrityToken intercepted");
            return ol.apply(_self, _args);
        };
    });
    console.log("[AA] + Play Integrity hook installed");
} catch(e) {}
