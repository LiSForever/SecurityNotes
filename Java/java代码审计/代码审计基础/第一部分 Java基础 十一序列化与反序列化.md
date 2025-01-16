### 序列化

两个条件:

* 实现java.io.Serializable
* 所有属性可序列化，不可序列化的属性要声明为暂时的

### 例子

```java
import java.io.*;

class MyObject implements Serializable{
    public String name;
    //重写readObject()方法
    private void readObject(java.io.ObjectInputStream in) throws IOException, ClassNotFoundException, IOException {
        //执行默认的readObject()方法
        in.defaultReadObject();
        //执行打开计算器程序命令
        Runtime.getRuntime().exec("calc.exe");
    }
}

public class testSerialize {
    public static void main(String args[]) throws Exception{
        //定义myObj对象
        MyObject myObj = new MyObject();
        myObj.name = "hi";
        //创建一个包含对象进行反序列化信息的”object”数据文件
        FileOutputStream fos = new FileOutputStream("object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将myObj对象写入object文件
        os.writeObject(myObj);
        os.close();
        //从文件中反序列化obj对象
        FileInputStream fis = new FileInputStream("object");
        ObjectInputStream ois = new ObjectInputStream(fis);
        //恢复对象
        MyObject objectFromDisk = (MyObject)ois.readObject();
        System.out.println(objectFromDisk.name);
        ois.close();
    }
}
```

#### 关于readObject和writeObject

* 以下是实现刘readObject和writeObject的类的例子，可以看到进行序列化和反序列化的底层操作实际上还是依赖于ObjectInputStream和ObjectOutputStream提供的一些方法。注意readObject和writeObject必须是私有方法，而且没有继承自任何类
* 上一小节给出的例子中使用了defaultReadObject()函数，与之相对应的还有defaultWriteObject()，这两个函数的功能就是实现默认的序列化和反序列化功能，再调用它们时，它们并不会覆盖我们已经手动赋值的属性

```java
import java.io.*;

class MyClass implements Serializable {
    private String name;
    private int age;
    private String address;

    // 构造函数
    public MyClass(String name, int age, String address) {
        this.name = name;
        this.age = age;
        this.address = address;
    }

    // 其他方法

    // 自定义序列化方法
    private void writeObject(ObjectOutputStream out) throws IOException {
        // 手动序列化 name 字段
        out.writeObject(name);
        // 手动序列化 age 字段
        out.writeInt(age);
        // 手动序列化 address 字段
        out.writeObject(address);
    }

    // 自定义反序列化方法
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        // 手动反序列化 name 字段
        name = (String) in.readObject();
        // 手动反序列化 age 字段
        age = in.readInt();
        // 手动反序列化 address 字段
        address = (String) in.readObject();
    }

    // toString 方法用于方便输出对象信息
    @Override
    public String toString() {
        return "MyClass{name='" + name + "', age=" + age + ", address='" + address + "'}";
    }
}

public class SerializationExample {
    public static void main(String[] args) {
        // 创建一个对象
        MyClass obj = new MyClass("John", 25, "123 Main St");

        // 序列化对象到文件
        try (ObjectOutputStream out = new ObjectOutputStream(new FileOutputStream("object.ser"))) {
            out.writeObject(obj);
        } catch (IOException e) {
            e.printStackTrace();
        }

        // 反序列化对象
        try (ObjectInputStream in = new ObjectInputStream(new FileInputStream("object.ser"))) {
            MyClass newObj = (MyClass) in.readObject();
            System.out.println(newObj);
        } catch (IOException | ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

#### 关于readObject的调用

  在第一个例子中，MyObject objectFromDisk = (MyObject)ois.readObject()，这里调用的ois（ObjectInputStream）的readObject方法，而这个过程中，MyObject的readObject也会被调用，虽然它是私有方法，但是这个过程中会使用反射来调用它。