* 测试时注意远程加载类的存放地址

### JDNI

#### JDNI介绍

一些需要了解的概念：

* JNDI（Java Naming and Directory Interface）即 Java 命名与目录接口。
* JNDI 提供了一种统一的方式来查找和访问各种不同类型的资源。比较直观的解释是，我们在使用RMI、LDAP、JDBC等技术访问相应的资源时，使用的是不同的类和方法，有了JNDI之后，我们只需要使用JDNI相关的类和方法，就可以通过资源的URL访问它们。
* JNDI提供统一的客户端API，通过不同的访问提供者接口JNDI服务供应接口(SPI)的实现，由管理者将JNDI API映射为特定的命名服务和目录系统，使得Java应用程序可以和这些命名服务和目录服务之间进行交互。目录服务是命名服务的一种自然扩展。
* JNDI现在可以访问的目录服务有DNS、XNam 、Novell目录服务、LDAP(Lightweight Directory Access Protocol轻型目录访问协议)、 CORBA对象服务、文件系统、Windows XP/2000/NT/Me/9x的注册表、RMI、DSML v1&v2、NIS。
* 现在JNDI已经成为J2EE的标准之一，所有的J2EE容器都必须提供一个JNDI的服务。

#### JDNI的一些相关类和方法

* ### InitialContext

```txt
InitialContext() 
构建一个初始上下文。  
InitialContext(boolean lazy) 
构造一个初始上下文，并选择不初始化它。  
InitialContext(Hashtable<?,?> environment) 
使用提供的环境构建初始上下文。 
```

```java
InitialContext initialContext = new InitialContext();
```

在这JDK里面给的解释是构建初始上下文，其实通俗点来讲就是获取初始目录环境。

* ### Reference

该类也是在`javax.naming`的一个类，该类表示对在命名/目录系统外部找到的对象的引用。提供了JNDI中类的引用功能。

```txt
Reference(String className) 
	为类名为“className”的对象构造一个新的引用。  
Reference(String className, RefAddr addr) 
	为类名为“className”的对象和地址构造一个新引用。  
Reference(String className, RefAddr addr, String factory, String factoryLocation) 
	为类名为“className”的对象，对象工厂的类名和位置以及对象的地址构造一个新引用。  
Reference(String className, String factory, String factoryLocation) 
	为类名为“className”的对象以及对象工厂的类名和位置构造一个新引用。  

```

```java
String url = "http://127.0.0.1:8080";
Reference reference = new Reference("test", "test", url);
```



#### JDNI+RMI

#### JDNI+LDAP

#### JNDI+DNS