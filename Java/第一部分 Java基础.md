### 一 环境搭建

#### Java版本

* JDK与JRE：JDK全称Java Development Kit，是Java开发者工具，JDK是整个JAVA的核心，包括了Java运行环境（Java Runtime Envirnment），一堆Java工具（javac/java/jdb等）和Java基础的类库（即Java API 包括rt.jar），JDK的安装目录下包括五个文件夹，一些描述文件、src、bin、lib、 jre：

  * bin：最主要的是编译器javac.exe java.exe
  * lib：库类
  * jre：java运行环境包含java虚拟机

  这里可以看出JDK包含了JRE，运行Java程序只需要安装JRE。

* JDK1.8 JDK8 Java8：总的来说，由于Java平台早期开发者的命名问题，因此有关Java版本有了多种说法，JDK1.8 JDK8 Java8都是同一个版本。

* ME SE EE：

  * Java ME（Java Micro Edition）应用于移动、无线及有限资源的环境，Java ME 为在移动设备和嵌入式设备（比如手机、PDA、电视机顶盒和打印机）上运行的应用程序提供一个健壮且灵活的环境。Java ME 包括灵活的用户界面、健壮的安全模型、许多内置的网络协议以及对可以动态下载的连网和离线应用程序的丰富支持。基于 Java ME 规范的应用程序只需编写一次，就可以用于许多设备，而且可以利用每个设备的本机功能。但要说明的是，如今的安卓开发，并不是Java ME，而是基于Java EE衍生的spring技术。
  * Java SE（Java Standard Edition）：这是我们平时接触的标准java，它包括java的基础语法和核心库类。它允许开发和部署在桌面、服务器、嵌入式环境和实时环境中使用的 Java 应用程序。Java SE 包含了支持 Java Web 服务开发的类，并为Java EE和Java ME提供基础。
  * Java EE（Java Enterprise Edition）：Java EE是SUN公司提供的一个庞大的类库，方便程序员在此基础上进行企业级开发。Java EE规范是一个比较大的规范，包括13个子规范，常见的有Servlet、JDBC等等。

#### Java版本切换脚本

```bat
@echo off
chcp 65001
SETX /M JAVA8_HOME "C:\Program Files\Java\jdk1.8.0_261"
SETX /M JAVA11_HOME "C:\Program Files\Java\jdk-11"

echo 选择切换Java版本：
echo 1.java8
echo 2.java11

set /p var=请输入:
if %var%==1 goto 1
if %var%==2 goto 2

:1
SETX /M JAVA_HOME "%JAVA8_HOME%"
java -version
javac -version
pause
exit

:2
SETX /M JAVA_HOME "%JAVA11_HOME%"
java -version
javac -version
pause
exit

```

#### Maven

* 介绍：Maven 是一个项目管理工具，它包含了一个项目对象模型（Project Object Model），反 映在配置中，就是一个 pom.xml 文件。是一组标准集合，一个项目的生命周期、一个 依赖管理系统，另外还包括定义在项目生命周期阶段的插件(plugin)以及目标(goal)。当我们使用 Maven 时，通过一个自定义的项目对象模型，pom.xml 来详细描述我 们自己的项目。 简单来说，我们开发一个JavaWeb项目是需要加载很多依赖的，使用Maven可以便于管理这些依赖。
* pom.xml：POM是项目对象模型(Project Object Model)的简称,它是Maven项目中的文件，使用XML表 示，名称叫做 pom.xml 。该文件用于管理：源代码、配置文件、开发者的信息和角 色、问题追踪系统、组织信息、项目授权、项目的url、项目的依赖关系等等。Maven项 目中必须包含 pom.xml 文件。
* Maven的安装和配置：我们直接使用IDEA内置的Maven
* IDEA创建Maven项目：

### 二 Java Web基础

### 三 文件上传

### 四 文件读取与下载

### 五 Java命令执行

### 六 数据库操作

### 七 Java反射

### 八 Java序列化与反序列化

### 九 RMI基础

### 十 JNDI基础