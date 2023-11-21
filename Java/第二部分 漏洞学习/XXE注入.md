### XML解析

#### DOM解析

* 基于树的解析
* 原生自带

```java
package com.example.springbootdemo2.xeedemo;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.InputStream;
import java.io.StringReader;

@RestController
public class DOMTest {
    @RequestMapping("/domdemo/vul")
    public String domDemo(HttpServletRequest request){
        try {
            //获取输入流
            InputStream in = request.getInputStream();
            String body = convertStreamToString(in);
            StringReader sr = new StringReader(body);
            InputSource is = new InputSource(sr);
            // 创建DocumentBuilderFactory对象
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            // 创建DocumentBuilder对象
            DocumentBuilder db = dbf.newDocumentBuilder();
            // 解析xml
            Document document = db.parse(is);
            // 遍历xml节点name和value
            StringBuilder buf = new StringBuilder();
            NodeList rootNodeList = document.getChildNodes();
            for (int i = 0; i < rootNodeList.getLength(); i++) {
                Node rootNode = rootNodeList.item(i);
                NodeList child = rootNode.getChildNodes();
                for (int j = 0; j < child.getLength(); j++) {
                    Node node = child.item(j);
                    buf.append(String.format("%s: %s\n", node.getNodeName(),
                            node.getTextContent()));
                }
            }
            sr.close();
            return buf.toString();
        } catch (Exception e) {
            return "EXCEPT ERROR!!!";
        }
    }
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}

```

#### SAX解析

* 基于事件
* 原生自带

```java
package com.example.springbootdemo2.xeedemo;
import com.sun.org.apache.xml.internal.resolver.readers.SAXParserHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;

@RestController
public class SAXTest {
    @RequestMapping("/saxdemo/vul")
    public String saxDemo(HttpServletRequest request) throws IOException {
        //获取输入流
        InputStream in = request.getInputStream();
        String body = convertStreamToString(in);
        try {
            SAXParserFactory spf = SAXParserFactory.newInstance();
            SAXParser parser = spf.newSAXParser();
            SAXParserHandler handler = new SAXParserHandler();
            //解析xml
            parser.parse(new InputSource(new StringReader(body)), handler);
            return "Sax xxe vuln code";
        } catch (Exception e) {
            return "Error......";
        }
    }
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}

```

#### JDOM解析

* java开源库
* 简单易用

```java
package com.example.springbootdemo2.xeedemo;

import org.jdom.input.SAXBuilder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;

@RestController
public class JDOMTest {
    @RequestMapping("/jdomdemo/vul")
    public String jdomDemo(HttpServletRequest request) throws IOException {
        //获取输入流
        InputStream in = request.getInputStream();
        String body = convertStreamToString(in);
        try {
            SAXBuilder builder = new SAXBuilder();
            builder.build(new InputSource(new StringReader(body)));
            return "jdom xxe vuln code";
        } catch (Exception e) {
            return "Error......";
        }
    }
    public static String convertStreamToString(java.io.InputStream is) {
        java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
    }
}
```

```xml
<dependency>
<groupId>org.jdom</groupId>
<artifactId>jdom</artifactId>
<version>1.1.3</version>
</dependency>
```



#### DOM4J

* JDOM升级版

```java
package com.example.xxedemo;
import org.dom4j.io.SAXReader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
炼石计划@赛博代审之旅内部文章，请勿外传，违者必究！
5、Digester 解析
Digester 是 Apache 下一款开源项目。 目前最新版本为 Digester 3.x 。
Digester 是对 SAX 的包装，底层是采用的是 SAX 解析方式。
import java.io.InputStream;
import java.io.StringReader;
/**
* 编号7089
*/
@RestController
public class DOM4JTest {
@RequestMapping("/dom4jdemo/vul")
public String dom4jDemo(HttpServletRequest request) {
try {
//获取输入流
InputStream in = request.getInputStream();
String body = convertStreamToString(in);
SAXReader reader = new SAXReader();
reader.read(new InputSource(new StringReader(body)));
return "DOM4J XXE......";
} catch (Exception e) {
return "EXCEPT ERROR!!!";
}
}
public static String convertStreamToString(java.io.InputStream is) {
java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
return s.hasNext() ? s.next() : "";
}
}
```

```xml
<dependency>
<groupId>dom4j</groupId>
<artifactId>dom4j</artifactId>
<version>1.6.1</version>
</dependency>
```



#### Digester

* Apache下开源项目
* 对SAX的包装

```java
package com.example.xxedemo;
import org.apache.commons.digester.Digester;
import org.dom4j.io.SAXReader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.xml.sax.InputSource;
import javax.servlet.http.HttpServletRequest;
import java.io.InputStream;
import java.io.StringReader;
@RestController
public class DigesterTest {
@RequestMapping("/digesterdemo/vul")
public String digesterDemo(HttpServletRequest request) {
try {
//获取输入流
InputStream in = request.getInputStream();
String body = convertStreamToString(in);
Digester digester = new Digester();
digester.parse(new StringReader(body));
return "Digester XXE......";
} catch (Exception e) {
return "EXCEPT ERROR!!!";
}
}
public static String convertStreamToString(java.io.InputStream is) {
java.util.Scanner s = new java.util.Scanner(is).useDelimiter("\\A");
return s.hasNext() ? s.next() : "";
}
}
```

```xml
<dependency>
<groupId>commons-digester</groupId>
<artifactId>commons-digester</artifactId>
<version>2.1</version>
</dependency>
```

### Java XEE对于协议的支持

* 支持sun.net.www.protocol里的所有协议：http，https，file，ftp，mailto，jar，netdoc
* JDK1.7 JDK1.6还支持gopher协议

### XEE漏洞审计函数

```txt
XMLReaderFactory
createXMLReader
SAXBuilder
SAXReader
SAXParserFactory
newSAXParser
Digester
DocumentBuilderFactory
DocumentBuilder
XMLReader
DocumentHelper
XMLStreamReader
SAXParser
SAXSource
TransformerFactory
SAXTransformerFactory
SchemaFactory
Unmarshaller
XPathExpression
javax.xml.parsers.DocumentBuilder
javax.xml.parsers.DocumentBuilderFactory
javax.xml.stream.XMLStreamReader
javax.xml.stream.XMLInputFactory
org.jdom.input.SAXBuilder
org.jdom2.input.SAXBuilder
org.jdom.output.XMLOutputter
oracle.xml.parser.v2.XMLParser
javax.xml.parsers.SAXParser
org.dom4j.io.SAXReader
org.dom4j.DocumentHelper
org.xml.sax.XMLReader
javax.xml.transform.sax.SAXSource
javax.xml.transform.TransformerFactory
javax.xml.transform.sax.SAXTransformerFactory
javax.xml.validation.SchemaFactory
javax.xml.validation.Validator
javax.xml.bind.Unmarshaller
javax.xml.xpath.XPathExpression
java.beans.XMLDecoder
```



 