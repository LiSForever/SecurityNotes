### CORS漏洞的挖掘

* 直接的检测是寻找关键api接口，伪造xhr请求，设置Origin，查看返回的数据包是否允许跨域
* 可以通关burp完成

![image-20240113184926159](.\images\image-20240113184926159.png)

### CORS的利用

* 在Access-Control-Allow-Credentials为true时，进行类似CSRF的攻击
* 在Access-Control-Allow-Credentials为true时，且samesite设置为none，目标api设置Secure且为https，可以使用ajax进行加强版CSRF
* 在Access-Control-Allow-Credentials为false时，利用场景比较少，当某些不需要鉴权但限制为特定ip访问的接口，可用于对管理员的钓鱼攻击

### 绕过

#### 绕过null

| “Access-Control-Allow-Origin” 值               | “Access-Control-Allow-Credentials” 值 | 是否可利用 |
| --------------------------------------------- | ------------------------------------ | ----- |
| [https://attacker.com](https://attacker.com/) | true                                 | 是     |
| null                                          | true                                 | 是     |
| *                                             | true                                 | 否     |

null是可以利用的，可以通过\<iframe\>利用

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src='data:text/html,<script>var req=new XMLHttpRequest();req.onload=reqListener;req.open("get","http://127.0.0.1/test.html",true);req.withCredentials=true;req.send();function reqListener(){alert(this.responseText)};</script>'></iframe>
```

#### 绕过不严格的域名校验

* 可以参考url跳转漏洞

#### 子域名托管

* 暂略

### Safari浏览器的特殊性质

* 暂略