### CC6攻击Tomcat下的Shiro

#### CC6攻击Shiro-550

#### 攻击失败的解析

TODO：目前有较多问题没有解决，先做一个记录：

* Spring下和tomcat下调用的差别，为什么一个有数组问题，一个没有；tomcat采用自己的类加载器的原因
* tomcat下异常抛出点的根本原因
* java安全漫谈中为什么说Shiro不是遇到Tomcat就一定会有数组这个问题

调试时遇到无法进入tomcat类加载器的问题，这里做一个记录，解决方法：

1. 在pom.xml中添加依赖

```xml
<dependency>
      <groupId>org.apache.tomcat.embed</groupId>
      <artifactId>tomcat-embed-core</artifactId>
      <version>9.0.91</version>
</dependency>
```

2. 设置idea的调试器

![image-20240724164740683](./images/image-20240724164740683.png)

### 改造CC链

在tomcat下的shiro由于在反序列化时使用继承ObjectInputStream的ClassResolvingObjectInputStream类的resolveClass方法在反序列化过程中查找对象，这限制序列化对象中非Java自身的数组的使用，也就是限制了CC6中使用`Transformer[] transformers = new Transformer[]{......}`，所以我们需要改造CC6，使其不使用Transformers数组。

有一个解决方法是使用JRMP（[Orange: Pwn a CTF Platform with Java JRMP Gadget](https://blog.orange.tw/2018/03/pwn-ctf-platform-with-java-jrmp-gadget.html)），但是需要出网，这里不多介绍。

所以我们要思考有没有办法改造链子，让其不要使用Transformer数组，在CC3中，我们也使用了Transformer数组，但是其长度只有2：

```java
Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(TrAXFilter.class),
                new InstantiateTransformer(
                        new Class[] { Templates.class },
                        new Object[] { obj })
        };

Transformer transformerChain = new
                ChainedTransformer(transformers);
```

我们再回顾一下，Transformer数组在CC链中是如何发挥的作用，在CC链的**某处**，调用了`ChainedTransformer(transformers).transformer(arg)`，这里实质上开始遍历执行数组transformers的元素的transformer方法。

再总结一下，这里`ChainedTransformer(transformers).transformer(arg)`实际上做了什么，它等效于一行代码。

```java
// instantiateTransformer为数组的第二个元素new InstantiateTransformer(new Class[] { Templates.class }, new Object[] { obj })
instantiateTransformer.transformer(TrAXFilter.class);
```

如果在CC链上，触发`ChainedTransformer(transformers).transformer(arg)`的arg是可控的，我们就不需要Transformer数组和ChainedTransformer了，很幸运，之前介绍的CC1、CC3、CC6都是可控的。

#### CC3的改造

CC3和CC1相比就是改变了Transformer数组的内容，这里可以说改造CC1也可以说改造CC3.
