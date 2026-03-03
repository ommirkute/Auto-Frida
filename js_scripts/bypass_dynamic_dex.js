// ==================== DYNAMIC DEX / CLASSLOADER BYPASS ====================
// Hooks DexClassLoader and InMemoryDexClassLoader.
// Some protectors load their real protection logic from encrypted DEX at runtime.
// Hooking the loader lets us see what is being loaded and suppress block calls.

try {
    var DCL = Java.use("dalvik.system.DexClassLoader");
    DCL.$init.implementation = function(dexPath, optDir, libPath, parent) {
        console.log("[AA] -> DexClassLoader loading: " + dexPath);
        return this.$init(dexPath, optDir, libPath, parent);
    };
    console.log("[AA] + DexClassLoader hook installed");
} catch(e) {}

try {
    var IDCL = Java.use("dalvik.system.InMemoryDexClassLoader");
    IDCL.$init.overloads.forEach(function(ol) {
        ol.implementation = function() {
            var _self = this, _args = arguments;
            console.log("[AA] -> InMemoryDexClassLoader used (in-memory DEX detected)");
            return ol.apply(_self, _args);
        };
    });
    console.log("[AA] + InMemoryDexClassLoader hook installed");
} catch(e) {}

// PathClassLoader — standard app DEX loader, watch for unusual loads
try {
    var PCL = Java.use("dalvik.system.PathClassLoader");
    PCL.$init.overloads.forEach(function(ol) {
        ol.implementation = function() {
            var _self = this, _args = arguments;
            var args = Array.prototype.slice.call(arguments);
            if (args[0] && typeof args[0] === "string" &&
                args[0].indexOf("/data/") !== -1 && args[0].indexOf(".jar") !== -1) {
                console.log("[AA] -> PathClassLoader unusual jar: " + args[0]);
            }
            return ol.apply(_self, _args);
        };
    });
} catch(e) {}

// Reflection-based class loading — Class.forName with suspicious names
try {
    var CLS = Java.use("java.lang.Class");
    var _cfn = CLS.forName.overload("java.lang.String");
    _cfn.implementation = function(name) {
        if (/protect|guard|check|detect|verify|integr|tamper|root|frida|hook/i.test(name)) {
            console.log("[AA] -> Class.forName suspicious: " + name);
        }
        return _cfn.call(this, name);
    };
    console.log("[AA] + Class.forName monitor installed");
} catch(e) {}
