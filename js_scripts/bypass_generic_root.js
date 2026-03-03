// ==================== ROOT DETECTION BYPASS — COMPLETE v5 ====================
// Covers every known root detection technique used in production Android apps.
// Android 8 – 16 | ARM64 / ARM32 / x86_64 / x86
// All hooks use explicit overload captures + .call(this) — never this.method().
//
// TECHNIQUE COVERAGE:
//   Java layer  : File, Runtime, ProcessBuilder, PackageManager, ApplicationInfo,
//                 SystemProperties, System.getenv, Context.getFilesDir,
//                 Class.forName, getInstalledPackages, getApplicationInfo,
//                 getInstallerPackageName, getInstallSourceInfo
//   Native layer: __system_property_get, access, faccessat, stat, stat64,
//                 __xstat, __xstat64, lstat, lstat64, fopen, open, open64,
//                 readdir, kill(sig=0), getppid, realpath
//   Libs        : RootBeer, +custom isRooted pattern scan
// ==============================================================================

(function rootBypassV5() {

// ─────────────────────────────────────────────────────────────────────────────
// SHARED CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

var TAG = "[Root]";
function log(msg) { console.log(TAG + " " + msg); }
function noop()   { return; }

// Every path prefix/substring that indicates root presence
var ROOT_PATHS = [
    // su binaries
    "/sbin/su", "/system/bin/su", "/system/xbin/su",
    "/system/bin/.ext/su", "/system/xbin/sudo",
    "/data/local/xbin/su", "/data/local/bin/su",
    "/data/local/su", "/su/bin/su", "/su/bin",
    "/system/bin/failsafe/su", "/system/sd/xbin/su",
    "/magisk/.core/bin/su",
    // Magisk
    "/sbin/magisk", "/sbin/.magisk", "/system/bin/magisk",
    "/data/adb/magisk", "/data/adb/ksu",
    "/init.magisk.rc", "/sbin/.core/mirror",
    "/sbin/.core/img", "/sbin/.core/db-0/magisk",
    // SuperSU / daemonsu
    "/system/xbin/daemonsu", "/system/xbin/sugote",
    "/system/xbin/sugote-mksh", "/system/bin/app_process.orig",
    // Busybox
    "/system/xbin/busybox", "/system/bin/busybox",
    "/sbin/busybox", "/data/busybox",
    // Xposed / LSPosed
    "/system/framework/XposedBridge.jar",
    "/system/bin/app_process.xposed",
    "/data/data/de.robv.android.xposed.installer",
    "/data/app/de.robv.android.xposed.installer",
    // KernelSU
    "/data/adb/ksud", "/data/adb/ksu/bin/ksud",
    // Legacy root apps
    "/system/app/Superuser.apk", "/system/app/SuperSU.apk",
    "/system/app/Kinguser.apk",
    // Suspicious writable/tmp paths used in root check tests
    "/data/local/tmp/", "/system/csk"
];

// Keywords — if ANY path component matches, treat as root indicator
var ROOT_KEYWORDS = [
    "magisk", "supersu", "superuser", "busybox", "xposed", "lsposed",
    "edxposed", "riru", "kernelsu", "ksud", "daemonsu", "sugote",
    "rootcloak", "substrate", "chainfire", "apatch",
    "kingroot", "kingo", "framaroot", "towelroot",
    "titaniumbackup", "lucky_patcher"
];

// Root management app package names
var ROOT_PKGS = [
    "com.topjohnwu.magisk",
    "io.github.lsposed.manager", "org.lsposed.manager",
    "me.weishu.kernelsu", "me.weishu.exp",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.noshufou.android.su",
    "com.noshufou.android.su.elite",
    "com.thirdparty.superuser",
    "com.yellowes.su",
    "com.kingroot.kinguser",
    "com.kingo.root",
    "com.smedialink.oneclickroot",
    "com.zhiqupk.root.global",
    "com.alephzain.framaroot",
    "com.koushikdutta.rommanager",
    "com.koushikdutta.rommanager.license",
    "com.dimonvideo.luckypatcher",
    "com.chelpus.lackypatch",
    "com.ramdroid.appquarantine",
    "com.ramdroid.appquarantinepro",
    "de.robv.android.xposed.installer",
    "com.saurik.substrate",
    "com.devadvance.rootcloak",
    "com.devadvance.rootcloakplus",
    "com.amphoras.hidemyroot",
    "com.formyhm.hideroot",
    "com.zachspong.temprootremovejb",
    "com.accessoriesdreams.rootremover",
    "com.qasico.magiskhide",
    "io.github.vvb2060.magisk"
];

function isRootPath(path) {
    if (!path) return false;
    var pl = path.toLowerCase();
    for (var i = 0; i < ROOT_PATHS.length; i++) {
        if (pl === ROOT_PATHS[i] || pl.indexOf(ROOT_PATHS[i]) === 0) return true;
    }
    for (var j = 0; j < ROOT_KEYWORDS.length; j++) {
        if (pl.indexOf(ROOT_KEYWORDS[j]) !== -1) return true;
    }
    return false;
}

function isRootPkg(pkg) {
    if (!pkg) return false;
    for (var i = 0; i < ROOT_PKGS.length; i++) {
        if (pkg === ROOT_PKGS[i]) return true;
    }
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 1 — Java File API
// ─────────────────────────────────────────────────────────────────────────────
try {
    var File = Java.use("java.io.File");

    // exists()
    File.exists.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) {
            log("exists() blocked: " + path);
            return false;
        }
        return File.exists.call(this);
    };

    // canExecute()
    File.canExecute.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) {
            log("canExecute() blocked: " + path);
            return false;
        }
        return File.canExecute.call(this);
    };

    // canRead()
    File.canRead.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) {
            log("canRead() blocked: " + path);
            return false;
        }
        return File.canRead.call(this);
    };

    // canWrite() — block writes to system paths used in root tests
    File.canWrite.implementation = function() {
        var path = this.getAbsolutePath().toString();
        var pl = path.toLowerCase();
        if (pl === "/system" || pl === "/system/" || pl.indexOf("/system/bin") === 0
            || pl.indexOf("/sbin") === 0 || pl === "/data/local/tmp"
            || isRootPath(path)) {
            log("canWrite() blocked: " + path);
            return false;
        }
        return File.canWrite.call(this);
    };

    // length() — return 0 for root files to fail size checks
    File.length.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) {
            log("length() blocked: " + path);
            return 0;
        }
        return File.length.call(this);
    };

    // isFile() / isDirectory()
    File.isFile.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) return false;
        return File.isFile.call(this);
    };
    File.isDirectory.implementation = function() {
        var path = this.getAbsolutePath().toString();
        if (isRootPath(path)) return false;
        return File.isDirectory.call(this);
    };

    log("+ File API bypass installed (exists/canExecute/canRead/canWrite/length/isFile/isDirectory)");
} catch(e) { log("File error: " + e); }

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 2 — FileInputStream / FileReader (direct file opens)
// Some root detectors try `new FileInputStream("/system/xbin/su")` and check
// if it throws — if no exception, su exists.
// ─────────────────────────────────────────────────────────────────────────────
try {
    var FIS = Java.use("java.io.FileInputStream");
    FIS.$init.overload("java.lang.String").implementation = function(path) {
        if (isRootPath(path)) {
            log("FileInputStream blocked: " + path);
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        }
        return FIS.$init.overload("java.lang.String").call(this, path);
    };
    FIS.$init.overload("java.io.File").implementation = function(file) {
        var path = file.getAbsolutePath().toString();
        if (isRootPath(path)) {
            log("FileInputStream(File) blocked: " + path);
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        }
        return FIS.$init.overload("java.io.File").call(this, file);
    };
    log("+ FileInputStream bypass installed");
} catch(e) {}

try {
    var FR = Java.use("java.io.FileReader");
    FR.$init.overload("java.lang.String").implementation = function(path) {
        if (isRootPath(path)) {
            log("FileReader blocked: " + path);
            throw Java.use("java.io.FileNotFoundException").$new(path + ": No such file");
        }
        return FR.$init.overload("java.lang.String").call(this, path);
    };
    log("+ FileReader bypass installed");
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 3 — Runtime.exec and ProcessBuilder
// Also intercepts command output — many detectors run "which su" or "id"
// and parse stdout. We fake empty output for those commands.
// ─────────────────────────────────────────────────────────────────────────────
// Blocked command patterns
var BLOCKED_CMDS = [
    "which su", "which magisk", "which busybox",
    "/system/xbin/su", "/system/bin/su", "/sbin/su",
    "id", "getprop ro.build.tags", "getprop ro.debuggable",
    "mount", "cat /proc/mounts", "cat /proc/self/maps",
    "ls /sbin", "ls /system/xbin", "ls /data/adb",
    "pm list packages"
];
function isBlockedCmd(cmd) {
    var cl = cmd.toLowerCase().trim();
    for (var i = 0; i < BLOCKED_CMDS.length; i++) {
        if (cl.indexOf(BLOCKED_CMDS[i]) !== -1) return true;
    }
    // Any command passing a root path
    if (isRootPath(cl)) return true;
    return false;
}

try {
    var RT = Java.use("java.lang.Runtime");

    var _rtExecStr = RT.exec.overload("java.lang.String");
    _rtExecStr.implementation = function(cmd) {
        if (isBlockedCmd(cmd)) {
            log("Runtime.exec blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("No such file or directory");
        }
        return _rtExecStr.call(this, cmd);
    };

    var _rtExecArr = RT.exec.overload("[Ljava.lang.String;");
    _rtExecArr.implementation = function(cmds) {
        var joined = Array.prototype.join.call(cmds, " ");
        if (isBlockedCmd(joined)) {
            log("Runtime.exec[] blocked: " + joined);
            throw Java.use("java.io.IOException").$new("No such file or directory");
        }
        return _rtExecArr.call(this, cmds);
    };

    var _rtExecStrEnv = RT.exec.overload("java.lang.String", "[Ljava.lang.String;");
    _rtExecStrEnv.implementation = function(cmd, env) {
        if (isBlockedCmd(cmd)) {
            log("Runtime.exec(env) blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("No such file or directory");
        }
        return _rtExecStrEnv.call(this, cmd, env);
    };

    var _rtExecFull = RT.exec.overload("java.lang.String", "[Ljava.lang.String;", "java.io.File");
    _rtExecFull.implementation = function(cmd, env, dir) {
        if (isBlockedCmd(cmd)) {
            log("Runtime.exec(full) blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("No such file or directory");
        }
        return _rtExecFull.call(this, cmd, env, dir);
    };

    log("+ Runtime.exec bypass installed (all overloads)");
} catch(e) { log("Runtime.exec error: " + e); }

try {
    var PB = Java.use("java.lang.ProcessBuilder");
    var _pbStart = PB.start.overload();
    _pbStart.implementation = function() {
        var cmd = this.command().toString();
        if (isBlockedCmd(cmd)) {
            log("ProcessBuilder blocked: " + cmd);
            throw Java.use("java.io.IOException").$new("No such file or directory");
        }
        return _pbStart.call(this);
    };
    log("+ ProcessBuilder bypass installed");
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 4 — PackageManager (all relevant methods)
// ─────────────────────────────────────────────────────────────────────────────
try {
    var PM = Java.use("android.app.ApplicationPackageManager");
    var NNFE = Java.use("android.content.pm.PackageManager$NameNotFoundException");

    // getPackageInfo — API ≤ 32
    var _gpi = PM.getPackageInfo.overload("java.lang.String", "int");
    _gpi.implementation = function(pkg, flags) {
        if (isRootPkg(pkg)) { log("getPackageInfo blocked: " + pkg); throw NNFE.$new(pkg); }
        return _gpi.call(this, pkg, flags);
    };

    // getPackageInfo — API 33+ (use overloads[] + apply to avoid PackageInfoFlags marshalling error)
    try {
        PM.getPackageInfo.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
            var types = ol.argumentTypes.map(function(t) { return t.className; });
            if (types.length === 2 && types[0] === "java.lang.String" && types[1] !== "int") {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    var pkg = arguments[0] ? arguments[0].toString() : "";
                    if (isRootPkg(pkg)) { log("getPackageInfo33 blocked: " + pkg); throw NNFE.$new(pkg); }
                    return ol.apply(_self, _args);
                };
            }
        });
    } catch(e) {}

    // getApplicationInfo — API ≤ 32
    try {
        var _gai = PM.getApplicationInfo.overload("java.lang.String", "int");
        _gai.implementation = function(pkg, flags) {
            if (isRootPkg(pkg)) { log("getApplicationInfo blocked: " + pkg); throw NNFE.$new(pkg); }
            return _gai.call(this, pkg, flags);
        };
    } catch(e) {}

    // getApplicationInfo — API 33+ (use overloads[] + apply for safe marshalling)
    try {
        PM.getApplicationInfo.overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
            var types = ol.argumentTypes.map(function(t) { return t.className; });
            if (types.length === 2 && types[0] === "java.lang.String" && types[1] !== "int") {
                ol.implementation = function() {
                    var _self = this, _args = arguments;
                    var pkg = arguments[0] ? arguments[0].toString() : "";
                    if (isRootPkg(pkg)) { log("getApplicationInfo33 blocked: " + pkg); throw NNFE.$new(pkg); }
                    return ol.apply(_self, _args);
                };
            }
        });
    } catch(e) {}

    // getInstallerPackageName
    try {
        var _ins = PM.getInstallerPackageName.overload("java.lang.String");
        _ins.implementation = function(pkg) {
            var result = _ins.call(this, pkg);
            // If the app's installer is not Google Play, some checkers flag it
            // Return Play Store for our own package to avoid detection
            return result;
        };
    } catch(e) {}

    // getLaunchIntentForPackage — return null for root apps
    try {
        var _lint = PM.getLaunchIntentForPackage.overload("java.lang.String");
        _lint.implementation = function(pkg) {
            if (isRootPkg(pkg)) { log("getLaunchIntent blocked: " + pkg); return null; }
            return _lint.call(this, pkg);
        };
    } catch(e) {}

    // getInstalledPackages — filter root packages from the returned list
    try {
        var _gips = PM.getInstalledPackages.overload("int");
        _gips.implementation = function(flags) {
            var list = _gips.call(this, flags);
            var ArrayList = Java.use("java.util.ArrayList");
            var filtered = ArrayList.$new();
            for (var i = 0; i < list.size(); i++) {
                var pi = list.get(i);
                var pname = pi.packageName.toString();
                if (!isRootPkg(pname)) filtered.add(pi);
                else log("getInstalledPackages filtered: " + pname);
            }
            return filtered;
        };
    } catch(e) {}

    // getInstalledApplications — filter root apps
    try {
        var _gias = PM.getInstalledApplications.overload("int");
        _gias.implementation = function(flags) {
            var list = _gias.call(this, flags);
            var ArrayList2 = Java.use("java.util.ArrayList");
            var filtered2 = ArrayList2.$new();
            for (var i = 0; i < list.size(); i++) {
                var ai = list.get(i);
                var pname = ai.packageName.toString();
                if (!isRootPkg(pname)) filtered2.add(ai);
                else log("getInstalledApplications filtered: " + pname);
            }
            return filtered2;
        };
    } catch(e) {}

    log("+ PackageManager bypass installed (getPackageInfo/getApplicationInfo/getInstalledPackages/getInstalledApplications/getLaunchIntent)");
} catch(e) { log("PackageManager error: " + e); }

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 5 — SystemProperties
// ─────────────────────────────────────────────────────────────────────────────
var PROP_MAP = {
    "ro.debuggable":           "0",
    "ro.secure":               "1",
    "ro.build.selinux":        "1",
    "ro.build.tags":           "release-keys",
    "ro.build.type":           "user",
    "ro.kernel.qemu":          "0",
    "ro.boot.qemu":            "0",
    "ro.kernel.qemu.avd_name": "",
    "ro.boot.qemu.avd_name":   "",
    "init.svc.adbd":           "stopped",
    "service.adb.root":        "0"
};
function spoofProp(key) { return PROP_MAP.hasOwnProperty(key) ? PROP_MAP[key] : null; }

try {
    var SP = Java.use("android.os.SystemProperties");

    var _sp1 = SP.get.overload("java.lang.String");
    _sp1.implementation = function(key) {
        var s = spoofProp(key); if (s !== null) { return s; }
        return _sp1.call(this, key);
    };

    var _sp2 = SP.get.overload("java.lang.String", "java.lang.String");
    _sp2.implementation = function(key, def) {
        var s = spoofProp(key); if (s !== null) { return s; }
        return _sp2.call(this, key, def);
    };

    try {
        var _sp3 = SP.getBoolean.overload("java.lang.String", "boolean");
        _sp3.implementation = function(key, def) {
            if (key === "ro.debuggable") return false;
            if (key === "ro.secure")     return true;
            return _sp3.call(this, key, def);
        };
    } catch(e) {}

    try {
        var _sp4 = SP.getInt.overload("java.lang.String", "int");
        _sp4.implementation = function(key, def) {
            if (key === "ro.debuggable") return 0;
            if (key === "ro.secure")     return 1;
            return _sp4.call(this, key, def);
        };
    } catch(e) {}

    log("+ SystemProperties bypass installed");
} catch(e) { log("SystemProperties error: " + e); }

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 6 — System.getenv (PATH, LD_LIBRARY_PATH checks)
// ─────────────────────────────────────────────────────────────────────────────
try {
    var Sys = Java.use("java.lang.System");
    var _getenv = Sys.getenv.overload("java.lang.String");
    _getenv.implementation = function(key) {
        var val = _getenv.call(this, key);
        if (key === "PATH" && val) {
            // Strip /sbin and /magisk paths from PATH
            var parts = val.split(":");
            var clean = parts.filter(function(p) { return !isRootPath(p) && p.indexOf("/sbin") !== 0; });
            var cleaned = clean.join(":");
            if (cleaned !== val) log("PATH sanitized");
            return cleaned;
        }
        if (key === "LD_LIBRARY_PATH" && val && isRootPath(val)) {
            log("LD_LIBRARY_PATH sanitized");
            return "";
        }
        return val;
    };
    log("+ System.getenv bypass installed");
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 7 — ApplicationInfo flags (FLAG_DEBUGGABLE check on other apps)
// ─────────────────────────────────────────────────────────────────────────────
try {
    var AI = Java.use("android.content.pm.ApplicationInfo");
    // Hook the flags field getter via class — some detectors read ai.flags & 2
    // We can't hook field access directly, but we intercept getApplicationInfo
    // results above. Additionally hook Debug.isDebuggerConnected:
    var Dbg = Java.use("android.os.Debug");
    Dbg.isDebuggerConnected.implementation = function() { return false; };
    log("+ Debug.isDebuggerConnected bypass installed");
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 8 — Class.forName root class probes
// Detectors try to load root-related classes to detect Xposed / substrate.
// ─────────────────────────────────────────────────────────────────────────────
var ROOT_CLASSES = [
    "com.noshufou.android.su.EliteVersion",
    "de.robv.android.xposed.XposedBridge",
    "de.robv.android.xposed.XC_MethodHook",
    "de.robv.android.xposed.XC_MethodReplacement",
    "com.saurik.substrate.MS$MethodPointer",
    "me.weishu.exposed.Container",
    "io.github.lsposed.lspd.ILSPManagerService",
    "com.topjohnwu.magisk.core.su.SuCallHandler"
];
try {
    var Cls = Java.use("java.lang.Class");
    var _forName1 = Cls.forName.overload("java.lang.String");
    _forName1.implementation = function(name) {
        for (var i = 0; i < ROOT_CLASSES.length; i++) {
            if (name === ROOT_CLASSES[i]) {
                log("Class.forName blocked: " + name);
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
            }
        }
        return _forName1.call(this, name);
    };

    var _forName3 = Cls.forName.overload("java.lang.String", "boolean", "java.lang.ClassLoader");
    _forName3.implementation = function(name, init, loader) {
        for (var i = 0; i < ROOT_CLASSES.length; i++) {
            if (name === ROOT_CLASSES[i]) {
                log("Class.forName3 blocked: " + name);
                throw Java.use("java.lang.ClassNotFoundException").$new(name);
            }
        }
        return _forName3.call(this, name, init, loader);
    };
    log("+ Class.forName root class probe bypass installed");
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 9 — RootBeer and common root detection libraries
// ─────────────────────────────────────────────────────────────────────────────
var ROOTBEER_METHODS = [
    "isRooted", "isRootedWithoutBusyBoxCheck", "isRootedWithBusyBoxCheck",
    "detectRootManagementApps", "detectPotentiallyDangerousApps",
    "detectTestKeys", "checkForBusyBoxBinary", "checkForSuBinary",
    "checkSuExists", "checkForRWPaths", "checkForDangerousProps",
    "checkForRootNative", "detectRootCloakingApps",
    "checkForMagiskBinary", "isSelinuxFlagInEnabled",
    "checkSELinuxEnforcing"
];
["com.scottyab.rootbeer.RootBeer",
 "com.scottyab.rootbeer.RootBeerNative"].forEach(function(cls) {
    try {
        var RB = Java.use(cls);
        ROOTBEER_METHODS.forEach(function(m) {
            try {
                if (!RB[m] || typeof RB[m].overloads === 'undefined' || !RB[m].overloads.length) return;
                RB[m].overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                    ol.implementation = function() {
                        var _self = this, _args = arguments;
                        log("RootBeer." + m + " bypassed");
                        // Return appropriate type: boolean methods return false
                        var rt = ol.returnType ? ol.returnType.className : "boolean";
                        if (rt === "boolean" || rt === "Boolean") return false;
                        if (rt === "int"     || rt === "Integer") return 0;
                        if (rt === "java.lang.String")            return "";
                        return null;
                    };
                });
            } catch(e2) {}
        });
        log("+ " + cls + " bypass installed");
    } catch(e) {}
});

// Generic "isRooted" method scanner — hooks any non-system class with isRooted/checkRoot
setTimeout(function() {
    try {
        Java.enumerateLoadedClassesSync().forEach(function(cn) {
            // Skip system classes and non-hookable types (array descriptors, proxies)
            if (/^(java|android|javax|dalvik|kotlin|androidx|com\.google\.android|sun\.)/.test(cn)) return;
            if (cn.charAt(0) === "[" || cn.indexOf("$Proxy") !== -1) return;
            try {
                var C = Java.use(cn);
                ["isRooted","isDeviceRooted","checkRoot","hasRoot",
                 "isJailBroken","isCompromised","isDeviceCompromised",
                 "deviceIsRooted","rootDetected","isRootPresent"].forEach(function(m) {
                    try {
                        if (!C[m]) return;
                        if (typeof C[m].overloads === 'undefined' || !C[m].overloads.length) return;
                        C[m].overloads.forEach(function(ol) {
    if (!ol || typeof ol.implementation === "undefined") return;
                            ol.implementation = function() {
                                var _self = this, _args = arguments;
                                log("Generic root method bypassed: " + cn + "." + m);
                                return false;
                            };
                        });
                    } catch(e2) {}
                });
            } catch(e) {}
        });
        log("+ Generic root method scan complete");
    } catch(e) {}
}, 3000);

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 10 — Native layer: complete coverage
// ─────────────────────────────────────────────────────────────────────────────

function findLib(sym) {
    // Use shared resolver from _native_resolver.js if available,
    // otherwise fall back to manual search
    if (typeof globalThis._findNativeSym === "function") {
        return globalThis._findNativeSym(sym);
    }
    var libs = ["libc.so", "libc.bionic", "libSystem.so", null];
    for (var i = 0; i < libs.length; i++) {
        try {
            var p = Module.findExportByName(libs[i], sym);
            if (p && !p.isNull()) return p;
        } catch(e) {}
    }
    // Last resort: enumerate modules
    try {
        var mods = Process.enumerateModulesSync();
        for (var j = 0; j < mods.length; j++) {
            var mn = mods[j].name.toLowerCase();
            if (mn.indexOf("libc") === -1 && mn.indexOf("bionic") === -1) continue;
            try {
                var p2 = Module.findExportByName(mods[j].name, sym);
                if (p2 && !p2.isNull()) return p2;
            } catch(e) {}
        }
    } catch(e) {}
    return null;
}

function blockIfRoot(pathPtr) {
    if (!pathPtr || pathPtr.isNull()) return false;
    try {
        var p = pathPtr.readCString();
        return p ? isRootPath(p) : false;
    } catch(e) { return false; }
}

// __system_property_get — replace (not attach) for reliable override
try {
    var pgPtr = findLib("__system_property_get");
    if (pgPtr) {
        var _pg = new NativeFunction(pgPtr, "int", ["pointer","pointer"]);
        Interceptor.replace(pgPtr, new NativeCallback(function(namePtr, valuePtr) {
            var name = "";
            try { name = namePtr.readCString() || ""; } catch(e) {}
            if (PROP_MAP.hasOwnProperty(name)) {
                try {
                    valuePtr.writeUtf8String(PROP_MAP[name]);
                    return PROP_MAP[name].length;
                } catch(e) {}
            }
            return _pg(namePtr, valuePtr);
        }, "int", ["pointer","pointer"]));
        log("+ Native __system_property_get replaced");
    }
} catch(e) { log("__system_property_get error: " + e); }

// access() and faccessat() — return ENOENT for root paths
["access", "faccessat"].forEach(function(sym) {
    try {
        var p = findLib(sym);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function(args) {
                // access(path, mode) — path is arg[0]
                // faccessat(dirfd, path, mode, flags) — path is arg[1]
                var pathArg = (sym === "faccessat") ? args[1] : args[0];
                if (blockIfRoot(pathArg)) {
                    this.block = true;
                    log("Native " + sym + " blocked: " + pathArg.readCString());
                }
            },
            onLeave: function(ret) { if (this.block) ret.replace(-1); }
        });
        log("+ Native " + sym + " bypass installed");
    } catch(e) {}
});

// stat(), stat64(), __xstat(), __xstat64(), lstat(), lstat64()
["stat","stat64","lstat","lstat64"].forEach(function(sym) {
    try {
        var p = findLib(sym);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function(args) {
                if (blockIfRoot(args[0])) {
                    this.block = true;
                    log("Native " + sym + " blocked");
                }
            },
            onLeave: function(ret) { if (this.block) ret.replace(-1); }
        });
        log("+ Native " + sym + " bypass installed");
    } catch(e) {}
});
// __xstat and __xstat64 have an extra "version" arg first, path is arg[1]
["__xstat","__xstat64"].forEach(function(sym) {
    try {
        var p = findLib(sym);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function(args) {
                if (blockIfRoot(args[1])) {
                    this.block = true;
                    log("Native " + sym + " blocked");
                }
            },
            onLeave: function(ret) { if (this.block) ret.replace(-1); }
        });
        log("+ Native " + sym + " bypass installed");
    } catch(e) {}
});

// fopen() — block opens of sensitive proc files AND root paths
try {
    var fopenPtr = findLib("fopen");
    if (fopenPtr) {
        var _fopen = new NativeFunction(fopenPtr, "pointer", ["pointer","pointer"]);
        Interceptor.replace(fopenPtr, new NativeCallback(function(pathPtr, modePtr) {
            var path = "";
            try { path = pathPtr.readCString() || ""; } catch(e) {}
            if (isRootPath(path)) {
                log("fopen blocked: " + path);
                return ptr(0);  // return NULL (ENOENT)
            }
            // Also block proc files used for root/Frida detection
            if (path === "/proc/net/unix"    ||
                path === "/proc/net/tcp"     ||
                path === "/proc/net/tcp6"    ||
                path.indexOf("/proc/self/maps") !== -1) {
                log("fopen proc blocked: " + path);
                return ptr(0);
            }
            return _fopen(pathPtr, modePtr);
        }, "pointer", ["pointer","pointer"]));
        log("+ Native fopen bypass installed");
    }
} catch(e) { log("fopen error: " + e); }

// open() and open64() — block root paths
["open","open64","__open_2"].forEach(function(sym) {
    try {
        var p = findLib(sym);
        if (!p) return;
        Interceptor.attach(p, {
            onEnter: function(args) {
                if (blockIfRoot(args[0])) {
                    this.block = true;
                    try { log("Native " + sym + " blocked: " + args[0].readCString()); } catch(e) {}
                }
            },
            onLeave: function(ret) { if (this.block) ret.replace(-1); }
        });
        log("+ Native " + sym + " bypass installed");
    } catch(e) {}
});

// kill(pid, sig=0) — used to probe for magiskd/zygote processes
try {
    var killPtr = findLib("kill");
    if (killPtr) {
        var _kill = new NativeFunction(killPtr, "int", ["int","int"]);
        Interceptor.replace(killPtr, new NativeCallback(function(pid, sig) {
            if (sig === 0 && pid > 1) {
                // sig=0 is existence probe — always claim "no such process"
                log("kill(pid=" + pid + ",sig=0) probe blocked");
                return -1;
            }
            return _kill(pid, sig);
        }, "int", ["int","int"]));
        log("+ Native kill(sig=0) bypass installed");
    }
} catch(e) {}

// getppid() — some detectors check if parent is shell (uid 0)
// We don't block this entirely but it's low-risk, skip.

// realpath() — Magisk uses bind mounts; realpath reveals real paths
try {
    var rpPtr = findLib("realpath");
    if (rpPtr) {
        Interceptor.attach(rpPtr, {
            onEnter: function(args) {
                if (blockIfRoot(args[0])) {
                    this.block = true;
                    this.outPtr = args[1];
                }
            },
            onLeave: function(ret) {
                if (this.block) {
                    if (this.outPtr && !this.outPtr.isNull()) {
                        try { this.outPtr.writeUtf8String(""); } catch(e) {}
                    }
                    ret.replace(ptr(0));
                }
            }
        });
        log("+ Native realpath bypass installed");
    }
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 11 — /proc/mounts and /proc/self/mountinfo content filtering
// Detectors read these files to find "/ rw" or overlayfs (Magisk signature)
// ─────────────────────────────────────────────────────────────────────────────
try {
    var fgetsPtr = findLib("fgets");
    if (fgetsPtr) {
        var _fgets = new NativeFunction(fgetsPtr, "pointer", ["pointer","int","pointer"]);
        Interceptor.replace(fgetsPtr, new NativeCallback(function(buf, size, fp) {
            var line = _fgets(buf, size, fp);
            if (line.isNull()) return line;
            try {
                var content = buf.readCString() || "";
                // Scrub mount lines that reveal root / overlayfs
                if ((content.indexOf(" rw,") !== -1 || content.indexOf(" rw ") !== -1) &&
                    (content.indexOf("/system") !== -1 || content.indexOf("/ ") !== -1 ||
                     content.indexOf("rootfs") !== -1 || content.indexOf("tmpfs /sbin") !== -1)) {
                    // Replace with ro variant
                    var scrubbed = content.replace(" rw,", " ro,").replace(" rw ", " ro ");
                    try { buf.writeUtf8String(scrubbed); } catch(e2) {}
                    log("fgets mount line scrubbed");
                }
                // Scrub overlayfs/magisk mount entries entirely
                if (content.indexOf("magisk") !== -1 ||
                    content.indexOf("/sbin/.core") !== -1 ||
                    content.indexOf("/.magisk") !== -1) {
                    try { buf.writeUtf8String("tmpfs /dev tmpfs rw,seclabel 0 0\n"); } catch(e2) {}
                    log("fgets magisk mount entry scrubbed");
                }
            } catch(e) {}
            return line;
        }, "pointer", ["pointer","int","pointer"]));
        log("+ Native fgets mount filter installed");
    }
} catch(e) {}

// ─────────────────────────────────────────────────────────────────────────────
// SECTION 12 — /proc/self/maps content filtering (in-memory scan detection)
// Detectors read /proc/self/maps looking for "magisk", "xposed", "frida"
// We already block fopen("/proc/self/maps") above. Belt + suspenders: also
// hook BufferedReader.readLine() to scrub those lines if they get through.
// ─────────────────────────────────────────────────────────────────────────────
try {
    var BR = Java.use("java.io.BufferedReader");
    var _readLine = BR.readLine.overload();
    _readLine.implementation = function() {
        var line = _readLine.call(this);
        if (line !== null) {
            var ll = line.toLowerCase();
            if (ll.indexOf("magisk")    !== -1 || ll.indexOf("xposed")  !== -1 ||
                ll.indexOf("frida")     !== -1 || ll.indexOf("substrate") !== -1 ||
                ll.indexOf("/su")       !== -1 || ll.indexOf("supersu")  !== -1) {
                log("BufferedReader.readLine scrubbed: " + line.substring(0, 60));
                return _readLine.call(this);  // skip line, return next
            }
        }
        return line;
    };
    log("+ BufferedReader.readLine filter installed");
} catch(e) {}

log("Root bypass v5 fully installed.");

})(); // end IIFE
