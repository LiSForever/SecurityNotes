### Multipartfile方式文件上传

#### 简介

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
* jsp**页面无法访问**：这个问题最终也没有解决，直接创建springboot项目，不使用jsp，而是用模板

#### 创建springboot项目

