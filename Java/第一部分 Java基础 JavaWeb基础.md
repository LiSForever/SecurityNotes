### Java Web技术简介

> Java Web，是用Java技术来解决相关web互联网领域的技术栈。 web包括：web服务端和web客户端两部分。Java在客户端的应用有Java Applet，不过 使用得很少。 Java在服务器端的应用非常的丰富，比如Servlet，JSP、SpringBoot等等。
>
> JavaWeb架构演变过程大致分为以下几个阶段：
>
> ![image-20231012194348347](.\images\image-20231012194348347.png)

### Java Web的核心Servlet

#### Servlet是什么

* 从Java语言的标准角度来说，Servlet是Java EE规定的十三个规范中的一个，为拓展Web服务器功能，开发Web应用提供了支持

* 从整个Web服务的结构来说，Servlet 是运行在 Web 服务器或应用服务器上的程序，它是作为来自 Web 浏览器或其他
  HTTP 客户端的请求和 HTTP 服务器上的数据库或应用程序之间的中间层。一个Servlet对应一个或者多个URL，当用户访问这些URL时，对应的Servlet处理用户的请求，生成动态数据。

![image-20231012194747527](.\images\image-20231012194747527.png)

* 从代码的角度来说Servlet是Java类，服务于HTTP请求，并实现了 javax.servlet.Servlet 接口。

#### Servlet的生命周期和其对应的四个方法

* 生命周期;
  * void init(ServletConfig config) throws ServletException：init是第一次请求servlet时做初始化工作的方法，后续请求将不再调用
  * void service(ServletRequest reqeust,ServletResponse response) throws ServletException，java.io.IOException：主要处理来自客户端的请求，并可以根据HTTP请求类型来 调用对应的方法，比如 doGet()，doPost()，doPut() 等等。
  * doGet() doPost() 等：处理阶段，将主要代码逻辑写在此处。根据不同HTTP请求对 应不同方法。
  * void destroy()：destory在销毁servlet时调用，通常在卸载应用和关闭servlet容器时调用

#### 使用idea创建servlet

* 创建项目：使用Maven构建项目，Archetype选择项目的模板maven-archetype-webapp

![image-20231012200549981](.\images\image-20231012200549981.png)

* 对pom.xml的配置：每次更新pom.xml的配置后需要重新构建项目，maven会根据pom.xml配置项目、下载依赖

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
	
    <!-- 
		<groupId>公司或者组织的唯一标志，并且配置时生成的路径也是由此生成， 如com.companyname.project-group，maven会将该项目打成的jar包放本地路径：/com/companyname/project-group
		<artifactId>项目的唯一ID，一个groupId下面可能多个项目，就是靠artifactId来区分的
	-->
    <groupId>com.individuals.learn</groupId>
    <artifactId>ServletTest</artifactId>
    <version>1.0-SNAPSHOT</version>

    <properties>
        <maven.compiler.source>8</maven.compiler.source>
        <maven.compiler.target>8</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>
    
    <!-- 依赖需要使用dependency引入，所有依赖放在dependencies下 -->
    <dependencies>
        <dependency>
            <groupId>javax.servlet</groupId>
            <artifactId>javax.servlet-api</artifactId>
            <version>3.1.0</version>
            <scope>compile</scope>
        </dependency>
    </dependencies>

</project>
```

* 配置Tomcat：

  * Tomcat是什么：Tomcat=Web服务器+Servlet/JSP容器。Web服务器专注于响应HTTP请求，它的工作重心在于响应静态资源，而Web容器可以看做是根据一定的标准产生的框架，它规定了如何对HTTP请求的<u>内容</u>进行响应，重心在于根据动态资源产生静态资源；Web容器也是Web应用程序和Web服务器之间的接口，可以让Web应用程序无需考虑Web服务器的实现细节。Tomcat实现了Java ee中的servlet标准和jsp标准，表现在我们安装Tomcat之后关于servlet和JSP的内容无需额外导包，而像JDBC之类的还需要导包。**不同版本的Tomcat实现了不同版本的servlet和jsp**。
  * Tomcat的下载和安装：在官网下载合适版本，我使用的是8.5.94。

  ![image-20231012203925682](.\images\image-20231012203925682.png)

  上图中的Core是已经编译好的部分，根据自己的设备下载后解压即可使用。

  ![image-20231012204143431](.\images\image-20231012204143431.png)

  官网还可以看到其支持的不同版本servlet和jsp。

  * idea配置tomcat：