// Hook Intent.getBooleanExtra 追踪 x32 的 key 参数
Java.perform(function () {
    var Intent = Java.use("android.content.Intent");

    Intent.getBooleanExtra.implementation = function (key, defaultValue) {
        var result = this.getBooleanExtra(key, defaultValue);
        console.log("[getBooleanExtra] key=" + key + " default=" + defaultValue + " result=" + result);
        console.log("    action=" + this.getAction());
        return result;
    };

    Intent.getIntExtra.implementation = function (key, defaultValue) {
        var result = this.getIntExtra(key, defaultValue);
        console.log("[getIntExtra] key=" + key + " default=" + defaultValue + " result=" + result);
        return result;
    };
});
