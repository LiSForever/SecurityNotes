https://www.usenix.org/conference/usenixsecurity23/presentation/squarcina

https://www.usenix.org/system/files/sec23_slides_squarcina-marco.pdf

### weak Integrity

* foo.example.com可以设置example.com的cookie，影响到bar.example.com
* 利用不安全的http冒充foo.example.com为该domain设置cookie
* 攻击者设置大量无效cookie，使得客户端对于某一域名的cookie数量达到上限，使得合法站点的cookie无法正常set

### 突破CSRF令牌

* Double-Submit Pattern
  * 介绍
  * 缺陷设计：csrf令牌不是集成在有认证作用的cookie中，而是单独有一个cookie，攻击者就可以通过weak Integrity的特性set自己的csrf令牌（针对后端做csrf token校验的方法是，校验cookie中的token与某个其他字段的cookie是否相同）
* Synchronizer Token Pattern
  * 介绍
  * 缺陷设计：新的csrf令牌会从老的csrf中产生，即使老的session是无效的，攻击者可以通过weak Integrity的特性，故意生成一个无效的session，但是其中包含自己的csrf令牌
* 会话固定

### 浏览器对畸形cookie设置的反映