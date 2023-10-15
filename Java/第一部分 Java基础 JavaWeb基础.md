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
<!-- 仅作参考，最好在自动生成的模板上添加额外内容 -->
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

  * idea配置tomcat：我使用的是idea2023.2与之前的版本有诸多不同，因此具体的配置过程也与课件不太一样
    * 使用maven创建项目后没有web文件夹和src文件夹，src文件夹自行添加，右键点击项目生成目录时，idea也提供了快速生成的方法。关于web文件夹，先在setting->Appearance&behavior->Menus and Toolbars->搜索添加add framework support。然后选择项目，双击shift，在打开的搜索框中搜索add framework support，点击后生成在java ee下的web即可。
    
    ![image-20231013161401194](.\images\image-20231013161401194.png)
    
    * 配置tomcat：有两点注意
      * 关于热部署
      * war包部署：有两种，选择war exploded这种方式支持热部署
    * 快速生成servlet类，idea2022是可以右键选择生成servlet模板的，但是23需要稍微设置：[使用IDEA2023创建Servlet模板，使其右键显示Servlet选项_idea servlet模板_小事一撞的博客-CSDN博客](https://blog.csdn.net/onebumps/article/details/130661359)
  
* 第一个servlet:

  * 代码

  ```java
  import javax.servlet.ServletException;
  import javax.servlet.http.HttpServlet;
  import javax.servlet.http.HttpServletRequest;
  import javax.servlet.http.HttpServletResponse;
  import java.io.IOException;
  import java.io.PrintWriter;
  
  public class FirstServlet extends HttpServlet {
      @Override
      protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
          
          // 设置相应内容类型
          response.setContentType("text/html");
          
          // 输出消息
          PrintWriter out = response.getWriter();
          out.print("<h1>hello world</h1>");
      }
  
      @Override
      protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
          doGet(request,response);
      }
  }
  
  ```

  

  * 配置web.xml：在servlet中，需要根据URL路径匹配映射到对应的servlet，即在 web.xml 中注册 servlet。web.xml 被称为部署描述符，在WEB_INF目录下，我们在Java代码中部署应用也可以使用@WebServlet注解类(servlet3以后)，但是使用部署描述符有时候是比注解类更具有优越性，其一可以部署@WebServlet中没有的元素；其二，一些配置的修改无需重新编译Servlet类，如应用的路径和初始化参数等，可以直接在Web.xml中修改即可。部署描述符的中的内容可以覆盖掉注解类中的内容。

  ```xml
  <!-- 仅作参考，最好在自动生成的模板上添加额外内容 -->
  <?xml version="1.0" encoding="UTF-8"?>
  <web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
           xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
           xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
           version="4.0">
  	<!-- 映射匹配流程： /FirstServlet 路径绑定的 Servlet-name为FirstServlet ，而
  FirstServlet绑定的class是FirstServlet ，最终访问 /FirstServlet ，调用的
  类也就是 FirstServlet.class 。
   -->
      <servlet>
          <servlet-name>FirstServlet</servlet-name>
          <servlet-class>FirstServlet</servlet-class>
      </servlet>
  
      <servlet-mapping>
          <servlet-name>FirstServlet</servlet-name>
          <url-pattern>/FirstServlet</url-pattern>
      </servlet-mapping>
  
  </web-app>
  ```

  * 启动项目：
    * 控制台乱码解决：[解决Tomcat服务器控制台中文乱码问题_服务器控制台乱阿妈-CSDN博客](https://blog.csdn.net/ziyu_one/article/details/94860582)
    * Web应用的目录结构：
      * 静态资源
      * WEB-INF：受保护的，外界不能直接访问，需要访问必须配置web.xml
        * classes:存放了基本类，Servlet文件，Dao文件等工程有关的类文件。对源文件编译后的.class文件都存放在这里。
        * lib:存放web应用程序所需要用到的jar文件，一般工程所需要的其他包都放在lib下。
        * web.xml
    * 启动后产生的两个目录：
      * out：
      * target：
    * tomcat webapp下的目录：在真实生存环境中web应用直接部署在webapp目录下或ROOT中，下面是webapp下自动产生的目录的介绍。使用idea创建的web项目是不会自动把应用部署到该目录下，这是为了开发多个web项目时不产冲突。
      * ROOT：和直接部署在webapp几乎相同，区别在于ROOT相比webapps服务器优先去webapps目录下找项目，如果有则显示，没有则去ROOT找，ROOT可以去除访问路径中的项目名，如果请求路径当前不想要目录名，那么可以通过在webapps下面创建ROOT目录，然后手动将war包解压到ROOT目录，然后删除原有的war包，这样tomcat启动的时候就不会自动解压war包，同时也不会生成对应war包名称的文件。
      * doc：Tomcat介绍和操作文档等等
      * examples：示例程序
      * host-manager：有关host管理
      * manager：有关server [status](https://so.csdn.net/so/search?q=status&spm=1001.2101.3001.7020)和applications管理
        有关服务器和其他应用启动、重启、关闭等操作
        有关session，JVM 性能参数等监听并管理等操作
    * **启动tomcat后404**：正常来说该配置的都配置了，但是我运行tomcat后貌似web项目还是没有部署成功，打开相应url全是404，但是配置应该是没问题的，因为再新创建项目都一切顺利。如果全部配置完后启动tomcat404，那就新建项目即可。

### 过滤器filter

#### 是什么

* 介绍：在正确配置后，filter会指拦截请求，并对传给被请求资源的ServletRequest或者ServletResponse进行处理，它主要用于过滤字符编码，做一些统 一的业务等等。是使用 javax.servlet.Filter 接口进行实现的。在代码安全中，他 常被用于防止XSS，防SQL注入，防任意文件上传等。再配置了Filter之后，它可以统一 过滤危险字符，省时省力。**filter依赖于Servlet容器。**
* filter是使用 javax.servlet.Filter 接口进行实现的，主要有三个接口
  * Filter
  * FilterConfig
  * FilterChain

#### 示例代码

```java
package com.test.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FilterTest implements Filter {
    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        String requestURI = request.getRequestURI();

        if(requestURI.contains("/FirstServlet")){
            // 多个filter拦截同一目标资源时，会形成一个filter调用链
            filterChain.doFilter(request,response);
        }else {
            // 其他url跳转到根目录
            request.getRequestDispatcher("/").forward(request,response);
        }
    }

    @Override
    public void destroy() {

    }
}
```

在web.xml中需添加，且需要放在servlet前。如果有多个过滤器针对同一目标，则其注册顺序决定其filter链上各个filter的调用顺序。

```xml
<!--配置过滤器-->
  <filter>
    <filter-name>FilterTest</filter-name>
    <filter-class>com.test.filter.FilterTest</filter-class>
  </filter>
  <!--映射过滤器-->
  <filter-mapping>
    <filter-name>FilterTest</filter-name>
    <!--“/*”表示拦截所有的请求 -->
    <url-pattern>/*</url-pattern>
  </filter-mapping>
```

###  