### 使用反射进行命令执行

#### 反射Java.lang.Runtime

正常调用

```java
String command = "whoami";
Runtime.getRuntime().exec(command)
```

  对于一般的类，我们可以通过newInstance()来创建实例，但有两种情况下它无法发挥作用：①、你使用的类没有无参构造函数（newInstance()调用的无参构造函数来实例化类），②、你使用的类构造函数是私有的。Runtime就属于第二种情况，Runtime在在设计模式上属于单例模式，无论何时请求该类的实例，都返回相同的实例。

  java.lang.Runtime属于饿汉式单例模式的设计。饿汉式单例模式是指在类加载时就创建实例，无论是否需要使用该实例。在 `java.lang.Runtime` 中，这个实例是在Java虚拟机启动时创建的，因为它需要在整个应用程序生命周期中提供对运行时环境的访问。

  查看java8 Runtime源码，注意到它使用了私有构造函数，防止外部实例化；并提供了一个public的静态函数供外部访问唯一的Runtime对象。

```java
public class Runtime {
    private static Runtime currentRuntime = new Runtime();

    public static Runtime getRuntime() {
        return currentRuntime;
    }

    private Runtime() {}

    public void exit(int status) {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkExit(status);
        }
        Shutdown.exit(status);
    }

    public void addShutdownHook(Thread hook) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new RuntimePermission("shutdownHooks"));
        }
        ApplicationShutdownHooks.add(hook);
    }

    public boolean removeShutdownHook(Thread hook) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new RuntimePermission("shutdownHooks"));
        }
        return ApplicationShutdownHooks.remove(hook);
    }

    public void halt(int status) {
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkExit(status);
        }
        Shutdown.beforeHalt();
        Shutdown.halt(status);
    }

    @Deprecated
    public static void runFinalizersOnExit(boolean value) {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            try {
                security.checkExit(0);
            } catch (SecurityException e) {
                throw new SecurityException("runFinalizersOnExit");
            }
        }
        Shutdown.setRunFinalizersOnExit(value);
    }

    public Process exec(String command) throws IOException {
        return exec(command, null, null);
    }

    public Process exec(String command, String[] envp) throws IOException {
        return exec(command, envp, null);
    }

    public Process exec(String command, String[] envp, File dir)
        throws IOException {
        if (command.length() == 0)
            throw new IllegalArgumentException("Empty command");

        StringTokenizer st = new StringTokenizer(command);
        String[] cmdarray = new String[st.countTokens()];
        for (int i = 0; st.hasMoreTokens(); i++)
            cmdarray[i] = st.nextToken();
        return exec(cmdarray, envp, dir);
    }

    public Process exec(String cmdarray[]) throws IOException {
        return exec(cmdarray, null, null);
    }

    public Process exec(String[] cmdarray, String[] envp) throws IOException {
        return exec(cmdarray, envp, null);
    }

    public Process exec(String[] cmdarray, String[] envp, File dir)
        throws IOException {
        return new ProcessBuilder(cmdarray)
            .environment(envp)
            .directory(dir)
            .start();
    }

    public native long freeMemory();

    public native long totalMemory();

    public native long maxMemory();

    public native void gc();

    private static native void runFinalization0();

    public void runFinalization() {
        runFinalization0();
    }

    public native void traceInstructions(boolean on);

    public native void traceMethodCalls(boolean on);

    @CallerSensitive
    public void load(String filename) {
        load0(Reflection.getCallerClass(), filename);
    }

    synchronized void load0(Class<?> fromClass, String filename) {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkLink(filename);
        }
        if (!(new File(filename).isAbsolute())) {
            throw new UnsatisfiedLinkError(
                "Expecting an absolute path of the library: " + filename);
        }
        ClassLoader.loadLibrary(fromClass, filename, true);
    }

    @CallerSensitive
    public void loadLibrary(String libname) {
        loadLibrary0(Reflection.getCallerClass(), libname);
    }

    synchronized void loadLibrary0(Class<?> fromClass, String libname) {
        SecurityManager security = System.getSecurityManager();
        if (security != null) {
            security.checkLink(libname);
        }
        if (libname.indexOf((int)File.separatorChar) != -1) {
            throw new UnsatisfiedLinkError(
    "Directory separator should not appear in library name: " + libname);
        }
        ClassLoader.loadLibrary(fromClass, libname, false);
    }

    @Deprecated
    public InputStream getLocalizedInputStream(InputStream in) {
        return in;
    }

    @Deprecated
    public OutputStream getLocalizedOutputStream(OutputStream out) {
        return out;
    }
}
```

##### 通过getMethod获取Runtime.getRuntime()访问

```java
// 获取Runtime类
Class<?> clazz = Class.forName("java.lang.Runtime");
// 获取Runtime的方法exec(String str)
Method execMethod = clazz.getMethod("exec", String.class);
// 获取Rumtime的方法getRuntime()
Method getRuntimeMethod = clazz.getMethod("getRuntime");
// 执行Runtime.getRuntime()，获取对象runtime
Object runtime = getRuntimeMethod.invoke(clazz);
// 执行runtime.exec("calc.exe")
execMethod.invoke(runtime, "calc.exe");
```

```java
Class<?> clazz = Class.forName("java.lang.Runtime");
clazz.getMethod("exec",String.class).invoke(clazz.getMethod("getRuntime
").invoke(clazz),"calc.exe");
```

##### 通过getDeclaredConstructor获取私有构造访问

```java
Class<?> clazz = Class.forName("java.lang.Runtime");
// 获取私有构造函数同Constructor m = clazz.getDeclareMethod("Runtime",null);
Constructor m = clazz.getDeclaredConstructor();
// 改变作用域，是的私有构造可以调用
m.setAccessible(true);
Method c1 = clazz.getMethod("exec", String.class);
c1.invoke(m.newInstance(), "calc.exe");
```

#### 反射java.lang.ProcessBuilder

java.lang.ProcessBuilder没有无参构造方法，也没有类似于Runtime的静态方法，这是我们之前提到的第一种情况，这里利用共有构造函数进行构造

```java
Class<?> clazz = Class.forName("java.lang.ProcessBuilder");
Object object = clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe");
clazz.getMethod("start").invoke(object,null);
```

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
((ProcessBuilder)
clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe"))
).start();
```

```java
Class clazz = Class.forName("java.lang.ProcessBuilder");
clazz.getMethod("start").invoke(clazz.getConstructor(List.class).newInstance(Arrays.asList("calc.exe")));
```

#### 反射java.lang.ProcessImpl

```java
String[] cmds = new String[]{"whoami"};
Class clazz = Class.forName("java.lang.ProcessImpl");
Method method = clazz.getDeclaredMethod("start", String[].class,
Map.class, String.class, ProcessBuilder.Redirect[].class,
boolean.class);
method.setAccessible(true);
// 
Process process = (Process) method.invoke(null, cmds, null, ".", null,
true);
```

```java
Class pClass = Class.forName("java.lang.ProcessImpl");
//Constructor constructor = pClass.getDeclaredConstructor(); //这里是空的构造参数
//constructor.setAccessible(true);
//Object obj = constructor.newInstance();
String[] cmdarray = new String[]{"whoami"};
Method startMethod = pClass.getDeclaredMethod("start", String[].class, Map.class, String.class, ProcessBuilder.Redirect[].class, boolean.class);
startMethod.setAccessible(true);
Process p = (Process)startMethod.invoke(null,cmdarray, null, null, null, false); //这里需要的五个参数，第一个参数为null，因为调用的方法是这个类的静态方法，也可以是pClass
```
