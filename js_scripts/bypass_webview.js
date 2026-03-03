// ==================== WEBVIEW SSL BYPASS ====================
try {
    var WVC = Java.use("android.webkit.WebViewClient");
    WVC.onReceivedSslError.implementation = function(view, handler, error) {
        console.log("[AA] -> WebView SSL error bypassed");
        handler.proceed();
    };
    console.log("[AA] + WebView bypass installed");
} catch(e) {}
