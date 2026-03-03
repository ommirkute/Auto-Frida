// ==================== SYSTEM.EXIT / RUNTIME.HALT INTERCEPTOR ====================
// Some protections call System.exit() or Runtime.halt() when they detect tampering.
// This script intercepts those calls so the app stays alive during analysis.

// System.exit — most common protection kill
try {
    var Sys = Java.use("java.lang.System");
    Sys.exit.implementation = function(code) {
        console.log("[AA] !! System.exit(" + code + ") intercepted — app kept alive");
        // Do NOT call through
    };
    console.log("[AA] + System.exit interceptor installed");
} catch(e) {}

// Runtime.exit
try {
    var RTX = Java.use("java.lang.Runtime");
    RTX.exit.implementation = function(code) {
        console.log("[AA] !! Runtime.exit(" + code + ") intercepted — app kept alive");
    };
    console.log("[AA] + Runtime.exit interceptor installed");
} catch(e) {}

// Runtime.halt (forceful JVM stop, bypasses shutdown hooks)
try {
    var RTH = Java.use("java.lang.Runtime");
    RTH.halt.implementation = function(code) {
        console.log("[AA] !! Runtime.halt(" + code + ") intercepted — app kept alive");
    };
    console.log("[AA] + Runtime.halt interceptor installed");
} catch(e) {}

// Process.killProcess (Android-specific)
try {
    var Proc = Java.use("android.os.Process");
    Proc.killProcess.implementation = function(pid) {
        console.log("[AA] !! Process.killProcess(" + pid + ") intercepted");
    };
    Proc.myPid.implementation = function() {
        var pid = this.myPid();
        return pid;
    };
    console.log("[AA] + Process.killProcess interceptor installed");
} catch(e) {}

// ActivityManager.killBackgroundProcesses — some apps nuke themselves
try {
    var AM = Java.use("android.app.ActivityManager");
    AM.killBackgroundProcesses.implementation = function(pkg) {
        console.log("[AA] !! killBackgroundProcesses(" + pkg + ") intercepted");
    };
} catch(e) {}
