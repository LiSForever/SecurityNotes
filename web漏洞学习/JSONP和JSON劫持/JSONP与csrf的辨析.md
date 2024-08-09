#### 前言

  首先指出，JSONP已经是一种过时的技术，CORS是更为安全的代替，而且众多浏览器也不再支持JSONP技术，使得相关漏洞的触发更为困难

#### JSONP简介

  JSONP用于从当前网页从别的域名（网站）那获取资料，即突破同源策略跨域读取数据，而且JSONP算是一种非标准的技术手段。

  JSONP的组成：

* 资源请求方：资源请求方，使用script标签跨域请求不同源的资源，\<script src=http://targeturl?callback=func\>\</script>，http://targeturl是我们想请求的资源的url，func则是我们预先定义好的一个函数，这里为什么要将函数名作为参数传递，请看后面的资源提供方
* 资源提供方：提供了一个接口http://targeturl?callback=xxx，这个接口的功能是返回xxx({"xxx":"xxx","aaa":"aaa"})，{"xxx":"xxx","aaa":"aaa"}是提供给请求者想要的json格式的资源，若请求方以\<script src=http://targeturl?callback=func\>\</script>请求，实际得到的结果是\<script\>func({"xxx":"xxx","aaa":"aaa"})\</script>，这就调用了函数func对返回的json资源进行处理

#### JSONP劫持

  黑客伪造了一个A网站带有\<script src=http://targeturl?callback=func\>\</script>，当http://targeturl的合法用户访问A网站时，就会以类似csrf的形式窃取http://targeturl的敏感信息，而且由于回调函数func的存在，黑客可以控制获取这些敏感信息

#### JSONP劫持与CSRF的辨析

  CSRF可以进行一些敏感操作，但是这些操作均是增、删、改等操作，如果存在CSRF的url仅仅是取得信息，那CRSF是没有危害的，因为由于同源策略的限制，该CSRF获取到的信息是无法被javascript读取和修改的，也就无法达成黑客的愿望，即使用JavaScript读取这些信息然后返回到黑客读取的服务器。而JSONP劫持则使这成为可能，因为请求方通过JSONP返回的是调用JavaScript函数的代码，而且调用的函数里已经写好了参数。

