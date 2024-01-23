### 前置知识

#### keep-alive与pipeline

为了缓解源站的压力，一般会在用户和后端服务器（源站）之间加设前置服务器，用以缓存、简单校验、负载均衡等，而前置服务器与后端服务器往往是在可靠的网络域中，ip 也是相对固定的，所以可以重用 TCP 连接来减少频繁 TCP 握手带来的开销。这里就用到了 HTTP1.1 中的 `Keep-Alive` 和 `Pipeline` 特性：

> 所谓 Keep-Alive，就是在 HTTP 请求中增加一个特殊的请求头 Connection: Keep-Alive，告诉服务器，接收完这次 HTTP 请求后，不要关闭 TCP 链接，后面对相同目标服务器的 HTTP 请求，重用这一个 TCP 链接，这样只需要进行一次 TCP 握手的过程，可以减少服务器的开销，节约资源，还能加快访问速度。这个特性在 HTTP1.1 中是默认开启的。
> 
> 有了 Keep-Alive 之后，后续就有了 Pipeline，在这里呢，客户端可以像流水线一样发送自己的 HTTP 请求，而不需要等待服务器的响应，服务器那边接收到请求后，需要遵循**先入先出**机制，将请求和响应严格对应起来，再将响应发送给客户端。现如今，浏览器默认是不启用 Pipeline 的，但是一般的服务器都提供了对 Pipleline 的支持。

#### http请求走私攻击的概念

> 当我们向代理服务器发送一个比较**模糊**的 HTTP 请求时，由于两者服务器的实现方式不同，可能代理服务器认为这是一个 HTTP 请求，然后将其转发给了后端的源站服务器，但源站服务器经过解析处理后，只认为其中的一部分为正常请求，剩下的那一部分，就算是走私的请求，当该部分对正常用户的请求造成了影响之后，就实现了 HTTP 走私攻击。

#### 使用CL和TE使得请求变得模糊

* CL即Content-Length，TE即Transfer-Encoding

* Transfer-Encoding在HTTP2中不再支持

* 对于TE我们只关心值为chunked的情况
  
  * 设置了 `Transfer-Encoding: chunked` 后，请求主体按一系列块的形式发送，并将省略 `Content-Length`
  
  * 在每个块的开头需要用十六进制数指明当前块的长度，数值后接 `\r\n`（占 2 字节），然后是块的内容，再接 `\r\n` 表示此块结束。最后用长度为 0 的块表示终止块。终止块后是一个 trailer，由 0 或多个实体头组成，可以用来存放对数据的数字签名等。

```http
POST / HTTP/1.1
Host: 1.com
Content-Type: application/x-www-form-urlencoded
Transfer-Encoding: chunked

b
q=smuggling
6
hahaha
0
[空白行]
[空白行]
```

* CL和块长度的显著区别：CL需要将**请求主体中的 \r\n** 所占的 2 字节计算在内，而块长度要忽略块内容末尾表示终止的 `\r\n`，请求头与请求主体之间有一个空行，是规范要求的结构，并不计入 `Content-Length`

* 至此，可以看到有两种方式用来表示 HTTP 请求的内容长度： `Content-Length` 和 `Transfer-Encoding` 。为了避免歧义，[rfc2616#section-4.4](https://tools.ietf.org/html/rfc2616#section-4.4) 中规定当这两个同时出现时，`Content-Length` 将被忽略。

* 规范避免了歧义的产生，但并非所有中间件都严格遵守规范，这导致了不同服务器在请求的边界划分上产生了歧义，从而导致请求走私
  
  * CL-TE 前置服务器认为CL优先级更高，后置服务器认为TE优先级更好
  
  * TE-CL 与上述相反
  
  * TE-TE 前端后端服务器都支持TE，但是可以通过混淆让它产生分歧

### 请求走私

#### CL-TE
