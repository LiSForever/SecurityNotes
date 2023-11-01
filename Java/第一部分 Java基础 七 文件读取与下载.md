### java.nio.file.Files读取文本

#### 特性

* JDK>7
* 原理：File类读取文件内容字节数组
* 适用：将文件内容读取到内存，适用于小文件

#### 代码分析

### java.io.FileReader类读取文本

#### 特性

* 原理：FileReader获取BufferedReader，然后逐行读取文件
* 适用：不支持编码，使用系统默认编码

#### 代码分析

### java.io.BufferedReader读取文本

#### 特性

* 适用：可逐行读取文件并对它们进行处理；适用于处理大文件，支持编码；是同步的，线程安全，默认缓冲区大小为8KB。

#### 代码分析

### 使用Scanner读取文本

#### 特性

* 原理：Scanner类使用分隔符模式将输入分解为标记，分隔符默认为空格。
* 适用：逐行读取文件；给予java正则读取文件；不同步，线程不安全。

#### 代码分析

### RandomAccessFile断点续传读取文 本

#### 特性

* 原理：不属于IO流；通过文件指针实现任意位置读取或者写入
* 断点续传：断点续传是在下载或上传时，将下载或上传任务（一个文件或一个压缩包）人为的划分 为几个部分，每一个部分采用一个线程进行上传或下载，如果碰到网络故障，可以从已 经上传或下载的部分开始继续上传或者下载未完成的部分，而没有必要从头开始上传或 者下载。
* 适用：断点续传

#### 代码分析

### 外部库 org.apache.commons.io.FileUtils.readFileToString ()读取文本

#### 特性

* 原理：依赖于外部库Commons-io。

```xml
<dependency>
<groupId>commons-io</groupId>
<artifactId>commons-io</artifactId>
<version>2.11.0</version>
</dependency>
```

* 适用：较短代码实现读取

### 外部库 org.apache.commons.io.FileUtils.readFileToString ()读取文本

* 原理：
* JDK>11
* 适用：较短代码实现读取

### 文件读取与文件下载

读取

```txt
HTTP/1.1 200
Content-Type: text/html;charset=UTF-8
Content-Length: 17
Date: Tue, 31 Oct 2023 12:54:20 GMT
Keep-Alive: timeout=60
Connection: keep-alive

crsf 清除缓存
```

下载

```txt
HTTP/1.1 200 
Content-Disposition: attachment;filename=C%3A%2FUsers%2FAdministrator%2FDesktop%2Fyzn.txt
Content-Type: text/html;charset=UTF-8
Content-Length: 17
Date: Tue, 31 Oct 2023 13:00:32 GMT
Keep-Alive: timeout=60
Connection: keep-alive

crsf 清除缓存
```