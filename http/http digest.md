### 基本介绍

* http digest弥补了BASIC的弱点，不再发送明文密码。
* 和BASIC一样采用质询/响应



### http digest认证的基本过程

![img](.\images\1615446-20200331162837843-77969056.png)

关键：

* 认证前请求资源，服务器返回401Authorization Required状态码，带首部Authorization Required

* Authorization Required必须包括realm和nonce。

* 客户端进行身份认证，带首部Authorization，包括收到的realm、nonce，username（明文），uri（目标uri，存在http代理转发时发挥作用），response（也叫Request-Digest）存放经过MD5运算的密码字符串

* 服务器端进行身份鉴别，成功后返回的首部中有Authorization-Info表示认证成功，或者在cookie中缓存认证成功；失败则继续401

* 参数一览：realm表明需要哪个域的用户名和密码

  ​                     nonce 是一种每次随返回的 401 响应生成的任意随机字符串，这个数会经常发生变化。客户端计算密码摘要时将其附加上去，使得多次生成同一用户的密码摘要各不相同，用来防止重放攻击，该字符串通常推荐由Base64 编码的十六进制数的组成形式，但实际内容依赖服务器的具体实现

  ​                    qop：有auth（默认的）和auth-int（增加了报文完整性检测）两种策略

  ​					nc：nonce计数器，是一个16进制的数值，表示同一nonce下客户端发送出请求的数量。

​                             nextnonce：下一个服务端随机数，使客户端可以预先发送正确的摘要

​                             rspauth：响应摘要，用于客户端对服务端进行认证

​                             stale：当密码摘要使用的随机数过期时，服务器可以返回一个附带有新随机数的401响应，并指定stale=true，表示服务器在告知客户端用新的随机数来重试，而不再要求用户重新输入用户名和密码了

* response = MD5(MD5(username:realm:password):nonce:nc:cnonce:qop:MD5(<request-method>:url))

#### php实现http digest复现

