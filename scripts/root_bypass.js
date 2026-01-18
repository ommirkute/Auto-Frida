// Root Detection Bypass for Android
// Bypasses common root detection methods

Java.perform(function() {
    console.log("[*] Root Detection Bypass Loaded");

    // Common root paths to hide
    var rootPaths = [
        "/system/app/Superuser.apk",
        "/system/xbin/su",
        "/system/bin/su",
        "/sbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/data/local/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/su/bin/su",
        "/magisk/.core/bin/su"
    ];

    var rootPackages = [
        "com.topjohnwu.magisk",
        "com.koushikdutta.superuser",
        "com.noshufou.android.su",
        "com.thirdparty.superuser",
        "eu.chainfire.supersu",
        "com.yellowes.su"
    ];

    // File.exists() Bypass
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        for (var i = 0; i < rootPaths.length; i++) {
            if (path.indexOf(rootPaths[i]) !== -1) {
                console.log("[+] Hiding root path: " + path);
                return false;
            }
        }
        return this.exists();
    };

    // Runtime.exec() Bypass
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1) {
            console.log("[+] Blocking exec: " + cmd);
            throw new Error("Command not found");
        }
        return this.exec(cmd);
    };

    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
        for (var i = 0; i < cmds.length; i++) {
            if (cmds[i].indexOf("su") !== -1) {
                console.log("[+] Blocking exec array with su");
                throw new Error("Command not found");
            }
        }
        return this.exec(cmds);
    };

    // PackageManager.getPackageInfo() Bypass
    var PackageManager = Java.use('android.app.ApplicationPackageManager');
    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(packageName, flags) {
        for (var i = 0; i < rootPackages.length; i++) {
            if (packageName === rootPackages[i]) {
                console.log("[+] Hiding package: " + packageName);
                throw Java.use('android.content.pm.PackageManager$NameNotFoundException').$new();
            }
        }
        return this.getPackageInfo(packageName, flags);
    };

    // System.getProperty() Bypass
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function(prop) {
        if (prop === "ro.debuggable" || prop === "ro.secure") {
            console.log("[+] Hiding system property: " + prop);
            return "1";
        }
        return this.getProperty(prop);
    };

    // Build Properties Bypass
    try {
        var Build = Java.use('android.os.Build');
        Build.TAGS.value = "release-keys";
        Build.FINGERPRINT.value = Build.FINGERPRINT.value.replace("test-keys", "release-keys");
        console.log("[+] Build properties patched");
    } catch (e) {
        console.log("[-] Could not patch Build properties");
    }

    // RootBeer Bypass (popular root detection library)
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log("[+] RootBeer.isRooted() bypassed");
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() {
            console.log("[+] RootBeer check bypassed");
            return false;
        };
    } catch (e) {
        console.log("[-] RootBeer not found");
    }

    console.log("[*] Root Detection Bypass Complete!");
});
