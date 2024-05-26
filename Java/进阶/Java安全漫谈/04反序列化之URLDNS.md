### ysoserial简单入手

#### 简单了解ysoserial

* ysoserial是一个生成java序列化payload的工具

* 大致使用方式如下

  * 可以查看可用的利用链

  ![image-20240526173633470](./images/image-20240526173633470.png)

  * 生成序列化对象,并输出到文件

```shell
# URLDNS为利用链,http://test.io为要执行的命令,当然这里由于URLDNS的特殊性,不能执行命令,这里的链接只是进行一次dnslog,payload.bin则是将序列化对象输出到文件
java -jar ysoserial-all.jar URLDNS http://test.io > payload.bin
```

![image-20240526173906876](./images/image-20240526173906876.png)

#### ysoserial的对于URLDNS的简单调试

### URLDNS

```java
```

### URLDNS的特殊意义