### java.lang.Runtime

* 执行原理：与之前接触过的c的exec类似，是开启一个进程，并不是直接执行shell命令。

例：

```java
String command = "cmd /c whoami";
Process process = Runtime.getRuntime().exec(command);
```

这里注意到命令执行的参数是 "cmd /c whoami"，这里是开了cmd的进程才能执行命令，也就是说，这个行为类似于：

![image-20231101172257921](.\images\image-20231101172257921.png)

* 能否执行多条命令：上面说了这个命令是开启一个进程，但是可以通过开启cmd或者powershell之后，通过&& | 等符号在其中运行多条命令
* 关于返回值：返回一个Process对象，用于管理子进程，可以通过其获取命令运行的结果和输出等。