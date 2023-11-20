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
<!DOCTYPE book SYSTEM "DTD-location">
<book>
<title>XML Basics</title>
<author>John Doe</author>
</book>
```

* DTD-localtion支持多种协议：sun.net.www.protocol规定http，https，file，ftp，mailto，jar，netdoc等协议
* DTD-location：
  * 本地文件读取：windows file:///c:/	linux file:///
  * 远程：http://、https://、ftp://

### XEE注入

#### 原理

#### 利用方式

##### 任意文件读取

##### SSRF

##### DOS攻击

### 防御

### 突破

#### 无直接回显

dnslog