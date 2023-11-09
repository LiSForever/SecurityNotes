### JDBC

参考之前的笔记

### Mybatis

#### idea创建项目

* 按照pdf构建
* 有几个问题
  * maven安装mysql-connector-j依赖出现问题：加上<version>8.0.31</version>
  * 运行报错mybatis版本问题

#### 项目结构分析

```txt
src
├── main
|   ├── java
|   |   ├── com
|   |   |   ├── example
|   |   |   |   ├── demo
|   |   |   |   |   ├── controller       // 控制器类，处理HTTP请求
|   |   |   |   |   |   ├── UserContoller.java
|   |   |   |   |   ├── entity       // 实体类，用于数据模型
|   |   |   |   |   |   ├── User.java
|   |   |   |   |   ├── mapper       // Mapper接口，定义数据库操作
|   |   |   |   |   |   ├── UserMapper.java
|   |   |   |   |   |   ├── impl     // Service接口的实现类
|   |   |   |   |   |   |   ├── UserServiceImpl.java
|   |   |   |   |   ├── service      // 服务层，包含业务逻辑
|   |   |   |   |   |   ├── UserService.java
|   |   |   |   ├── Application.java  // Spring Boot应用程序的入口类
|
├── resources
|   ├── mybatis                         // 存放MyBatis XML映射文件的目录
|   |   ├── UserMapper.xml
```

* 这是常见的项目结构之一，也有很多其他结构
