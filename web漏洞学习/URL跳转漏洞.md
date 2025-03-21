### 简介

* 产生原因：URL跳转漏洞又称为开放重定向漏洞，在实现URL跳转时，若没有对可控参数进行过滤和先知，是的跳转的目标域名可控，就会造成url跳转漏洞
* 危害：容易被利用进行钓鱼攻击

### 测试方式

* 黑盒测试时寻找敏感参数名：redirect url redirectUrl callback return_url toUrl ReturnUrl fromUrl redUrl request redirect_to redirect_url jump jump_to target to goto link linkto domain oauth_callback等
* 寻找常见跳转功能点：
  * 用户登录、统一身份认证处，认证完后会跳转
  * 用户分享、收藏内容过后，会跳转
  * 跨站点认证、授权后，会跳转
  * 站内点击其它网址链接时，会跳转

### 防御

* 站内的任意跳转风险在于CSRF，防御方法应该归入CSRF
* 对于固定跳转需设置白名单并禁止参数可控
* 跳转到其他站点需要提示跳转风险
* 禁止%0d%0a等特殊字符，防止CRLF攻击
* 设置跳转的URL匹配规则

### 绕过

* 绕过的核心在于不同的写法在重定向时可以被识别为合法的url，这里不同的后端语言可能表现不同
  
  * ?url=http://xxx.com
  
  * ?url=//xxx（//不能省略，省略后就变为本站站内的重定向了）
  
  ![image-20231116195644022](.\images\image-20231116195644022.png)
  
  * 加？来匹配一些需要的匹配的字符?url=http://xxx?a
  
  * 同上?url=http://xxx#a
  
  * 同上?url=http://xxx/a
  
  * 加@常见的绕过?url=http:aaa@xxx
  
  * 多次跳转，先跳转到信任页面，然后再在信任页面跳转
  
  * xss跳转：\<meta content="1;url=http://www.baidu.com" http-equiv="refresh"\>
  
  * .xip.io绕过：.xip.io是一个域名解析服务
    
    ```txt
       10.0.0.1.xip.io   resolves to   10.0.0.1
      www.10.0.0.1.xip.io   resolves to   10.0.0.1
      mysite.10.0.0.1.xip.io   resolves to   10.0.0.1
     foo.bar.10.0.0.1.xip.io   resolves to   10.0.0.1
    ```
    
     url=http://白名单域名.恶意ip.xip.io来绕过
  
  * 短链接绕过
  
  * 补充
  
    * ?@组合拳    http://www.hack.com?@qq.com 实际访问域名为hack
    * 其他存在后端处理、规划化url的场景，还可以尝试宽字节、`../`目录穿越等。`http://www.qq.com/../hack.com` `http://hack.com%df/.qq.com`
  