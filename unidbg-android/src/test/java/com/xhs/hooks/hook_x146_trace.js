// x146 v13 — 打印intercept前后所有headers + 多次请求
Java.perform(function () {
    var count = 0;

    var interceptor = Java.use("com.xingin.shield.http.XhsHttpInterceptor");

    interceptor.intercept.implementation = function (chain) {
        count++;
        if (count > 3) return this.intercept(chain);

        // 原始请求
        var origReq = chain.request();
        var origUrl = origReq.url().toString();
        console.log("\n[intercept #" + count + "] url=" + origUrl.substring(0, 100));

        // 调用原始intercept
        var response = this.intercept(chain);

        // 打印response的request的所有headers
        var request = response.request();
        var headers = request.headers();
        var size = headers.size();
        console.log("[after] headers (" + size + "):");
        for (var i = 0; i < size; i++) {
            var name = headers.name(i);
            var value = headers.value(i);
            console.log("  " + name + " = " + value.substring(0, 120));
        }

        return response;
    };
    console.log("[+] intercept hooked (print all headers)");
});
