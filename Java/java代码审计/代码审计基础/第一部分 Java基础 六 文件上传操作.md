### Multipartfile方式文件上传

#### 简介

* MultipartFile是SpringMVC提供简化上传操作的工具类

#### idea环境搭建

* 在创建项目时：
  * 注意选择java版本和type为maven
  * 构建项目后没有web目录：
    * 手动创建webapp、WEB-INF、web.xml
    * 或者file-》project structure-》project settings-》Modules，更改type路径为 项目\src\main\webapp\WEB-INF\web.xml  更改web  Resource Directory为 项目\src\main\webapp

![image-20231023100404056](.\images\image-20231023100404056.png)

* 在pom.xml添加依赖时仍有问题：

  * 添加的servlet依赖包增加\<version\>

  ```xml
  <dependency>
              <groupId>javax.servlet</groupId>
              <artifactId>javax.servlet-api</artifactId>
              <version>3.1.0</version>
              <scope>provided</scope>
          </dependency>
  ```

  * 添加jstl存在问题：我这里是折腾了半天，最终添加了jsp的依赖后没有报错，但我也不确定这个解决方法是不是正确的

  ```xml
  <dependency>
              <groupId>javax.servlet.jsp</groupId>
              <artifactId>jsp-api</artifactId>
              <version>2.1</version>
              <scope>provided</scope>
          </dependency>
          <dependency>
              <groupId>javax.servlet</groupId>
              <artifactId>jstl</artifactId>
              <version>1.2</version>
          </dependency>
  ```

* 可以创建JSP模板供以后使用
* 项目跑不起来，“警告：源发行版本17 需要目标发行版 17”：[解决：java: 警告: 源发行版 17 需要目标发行版 17-CSDN博客](https://blog.csdn.net/angelbeautiful/article/details/131182554)
* 运行项目后报错“java: 无法访问org.springframework.boot.test.context.SpringBootTest错误的类文件:/E:/java/Maven/repository/org/springframework/boot/spring-boot-test/3.1.5/spring-boot-test-3.1.5.jar!/org/springframework/boot/test/context/SpringBootTest.class 类文件具有错误的版本 61.0, 应为 52.0请删除该文件或确保该文件位于正确的类路径子目录中。”：这是springboot版本的问题，修改pom.xml中的org.springframework.boot为2.7.1（3.0以下），或者下次创建项目时选择合适版本。
* jsp**页面无法访问**：这个问题最终也没有解决，因为这里实际上不使用jsp也可以上传文件，就直接用html了

#### 文件上传代码简单分析

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>fileUpload</title>
</head>
<body>
<form method="post" action="/upload" enctype="multipart/form-data">
    选择要上传的文件：<input type="file" name="file"><br>
    <hr>
    <input type="submit" value="提交">
</form>
</body>
</html>
```

* enctype="multipart/form-data"：multipart/form-data是指表单数据有多部分构成，既有文本数据，又有文件等二进制数据的意思。需要注意的是：默认情况下，enctype的值是application/x-www-form-urlencoded，不能用于文件上传，只有使用了multipart/form-data，才能完整的传递文件数据。application/x-www-form-urlencoded不是不能上传文件，是只能上传文本格式的文件，multipart/form-data是将文件以二进制的形式上传，这样可以实现多种类型的文件上传。

```java
/*
引用包省略
*/

@Controller
public class multipartfileController {

    @Value("${file.upload.path}")
    private String path;

    @GetMapping("/")
    public String uploadPage() {
        return "upload";
    }
    @PostMapping("/upload")
    @ResponseBody
    public String create(@RequestPart MultipartFile file) throws IOException {
        String fileName = file.getOriginalFilename();
        String filePath = path + fileName;

        File dest = new File(filePath);
        Files.copy(file.getInputStream(), dest.toPath());
        return "Upload file success : " + dest.getAbsolutePath();
    }
}
```

### ServletFileUpload方式

#### 简介

> ServletFileUpload方式文件上传依赖commons-fileupload组件。 对于commons-fileupload组件介绍：FileUpload依据规范RFC1867中”基于表单的HTML文 件上载”对上传的文件数据进行解析，解析出来的每个项目对应一个FileItem对象。 每个FileItem都有我们可能所需的属性：获取contentType，获取原本的文件名，获取文 件大小，获取FiledName(如果是表单域上传)，判断是否在内存中，判断是否属于表单 域等。 FileUpload使用FileItemFactory创建新的FileItem。该工厂可以控制每个项目的创建方 式。目前提供的工厂实现可以将项目的数据存储临时存储在内存或磁盘上，具体取决于 项目的大小（即数据字节，在指定的大小内时，存在内存中，超出范围，存在磁盘 上）。 FileUpload又依赖于Commons IO。

| 常用方法                                                     | 描述                                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| FileItemFactory                                              | 表单项工厂接口                                               |
| ServletFileUpload                                            | 文件上传类，用于解析上传的数据                               |
| FileItem                                                     | 表单项类，表示每一个表单项 boolean                           |
| xxxxxxxxxx HTTP/1.1 200 Content-Disposition: attachment;filename=C%3A%2FUsers%2FAdministrator%2FDesktop%2Fyzn.txtContent-Type: text/html;charset=UTF-8Content-Length: 17Date: Tue, 31 Oct 2023 13:00:32 GMTKeep-Alive: timeout=60Connection: keep-alive​crsf 清除缓存txt | 判断当前上传的数据格式是否是多段的格式，只有是多段数据，才能使用该方式 |
| public List parseRequest(HttpServletRequest request)         | 解析上传的数据，返回包含 表单项的 List 集合                  |
| boolean FileItem.isFormField()                               | 判断当前这个表单项，是否是普通的表单 项，还是上传的文件类型，true 表示普通类型的表单项；false 表示上传的文件类型 |
| String FileItem.getFieldName()                               | 获取表单项的 name 属性值                                     |
| String FileItem.getString()                                  | 获取当前表单项的值                                           |
| String FileItem.getName()                                    | 获取上传的文件名                                             |
| void FileItem.write( file )                                  | 将上传的文件写到 参数 file 所指向存 取的硬盘位置             |

####  idea搭建环境

* 按之前的方式搭建java web项目
* pom.xml添加依赖

```xml
<dependency>
    <groupId>commons-io</groupId>
	<artifactId>commons-io</artifactId>
	<version>2.4</version>
</dependency>

<dependency>
    <groupId>commons-fileupload<</groupId>
	<artifactId>commons-fileupload</artifactId>
	<version>1.4</version>
</dependency>
```

#### 代码

* 前端代码

```html
<!DOCTYPE html>
<html>
<head>
<title>文件上传</title>
</head>
<body>
<form action="FileUploadServlet" method="post" enctype="multipart/form-data">
用户名：<input type="text" name="name"><br>
文件1：<input type="file" name="f1"><br>
文件2：<input type="file" name="f2"><br>
<input type="submit" value="提交">
</form>
</body>
</html>
```

* 见pdf
