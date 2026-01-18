// Universal SSL Pinning Bypass for Android
// Supports: OkHttp, TrustManager, WebView, Apache HTTP

Java.perform(function() {
    console.log("[*] SSL Pinning Bypass Loaded");

    // TrustManager Bypass
    var TrustManager = Java.registerClass({
        name: 'com.frida.TrustManager',
        implements: [Java.use('javax.net.ssl.X509TrustManager')],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // SSLContext Bypass
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(km, tm, sr) {
        console.log("[+] SSLContext.init() bypassed");
        this.init(km, [TrustManager.$new()], sr);
    };

    // OkHttp3 CertificatePinner Bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {
            console.log("[+] OkHttp3 CertificatePinner bypassed for: " + hostname);
            return;
        };
        CertificatePinner.check.overload('java.lang.String', 'java.security.cert.Certificate').implementation = function(hostname, cert) {
            console.log("[+] OkHttp3 CertificatePinner bypassed for: " + hostname);
            return;
        };
    } catch (e) {
        console.log("[-] OkHttp3 not found");
    }

    // TrustManagerImpl Bypass (Android 7+)
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log("[+] TrustManagerImpl bypassed for: " + host);
            return untrustedChain;
        };
    } catch (e) {
        console.log("[-] TrustManagerImpl not found");
    }

    // WebViewClient Bypass
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        WebViewClient.onReceivedSslError.implementation = function(view, handler, error) {
            console.log("[+] WebView SSL error bypassed");
            handler.proceed();
        };
    } catch (e) {
        console.log("[-] WebViewClient not found");
    }

    // HttpsURLConnection Bypass
    try {
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
            console.log("[+] HttpsURLConnection HostnameVerifier bypassed");
            return;
        };
        HttpsURLConnection.setSSLSocketFactory.implementation = function(sslSocketFactory) {
            console.log("[+] HttpsURLConnection SSLSocketFactory bypassed");
            return;
        };
    } catch (e) {
        console.log("[-] HttpsURLConnection not found");
    }

    console.log("[*] SSL Pinning Bypass Complete!");
});
