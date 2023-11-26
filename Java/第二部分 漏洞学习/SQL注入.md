### 前言

​	SQL注入如今发生的情况已经不多了，在Java作为后端语言的项目中就更少了，这都要归功于框架的成熟和预编译的广泛使用。但是SQL毕竟还没有死绝，一方面，即使使用了成熟的框架，也会有程序员因为对框架特性的不了解而编写出带有漏洞的代码；另一方面，预编译并不是在所有场景下都有效。

​	SQL注入产生后的利用方式可以说是五花八门，各种炫技般的payload也是令人眼花缭乱，但本篇笔记着重从Java和相关框架的角度，总结分析SQL注入在Java项目中的成因，并对防御方式做一定的探讨。

### Mybatis中的SQL注入

#### #{}和${}的区别

* #{}是占位符（预编译），${}是拼接符

### 预编译需要注意的几点

有些情况下是无法使用预编译的，或者说使用起来没有那么简单

#### like注入（占位符需要与其他字符拼接）

```sql
# 这两种写法都会报错 ERROR 1210 (HY000): Incorrect arguments to EXECUTE
# 可见 占位符不能用在引号内，后续试验发现引号内的占位符被理解为字符
prepare testq1 from "select * from test1 where username='?'";
set @a="xiaoming";
exccute testq1 using @a;
 
prepare testq1 from "select * from test1 where id='?'";
set @b=1;
exccute testq1 using @b;

# 正确写法
SELECT * FROM users WHERE name like CONCAT("%", ?, "%")
# 在mybatis中 ELECT * FROM users WHERE name like CONCAT("%", #{name}, "%")
```

#### in注入（占位符个数不定）

* 常用用法是select * from where field in (value1,value2,value3,...)

```txt
# 因为有时(value1,value2,...)其中的参数是不定的，为了方便会采取拼接的写法
select * from users where id in (${params})

# 正确写法
<!-- where in 查询场景 -->
<select id="select" parameterType="java.util.List" resultMap="BaseResultMap">
SELECT *
FROM user
WHERE name IN
<foreach collection="names" item="name" open="(" close=")" separator=",">
#{name}
</foreach>
</select>
```

#### 处理动态字段名

* 以order by注入为典型代表的一类，用户传入的是动态字段名，这时无法使用预编译，只能采取白名单控制传入SQL语句的参数

```java
// 插入数据用户可控时，应使用白名单处理
// example for order by
String orderBy = "{user input}";
String orderByField;
switch (orderBy) {
	case "name":
		orderByField = "name";break;
	case "age":
		orderByField = "age"; break;
	default:
		orderByField = "id";
}
```

### 漏洞修复

以下列出一些不同环境下常用的安全写法

* JDBC

```java
String name = "foo";
// 一般查询场景
String sql = "SELECT * FROM users WHERE name = ?";
PreparedStatement pre = conn.prepareStatement(sql);
pre.setString(1, name);
ResultSet rs = pre.executeQuery();
// like 模糊查询场景
String sql = "SELECT * FROM users WHERE name like ?";
PreparedStatement pre = conn.prepareStatement(sql);
pre.setString(1, "%"+name+"%");
ResultSet rs = pre.executeQuery();
// where in 查询场景
String sql = "select * from user where id in (";
Integer[] ids = new Integer[]{1,2,3};
StringBuilder placeholderSql = new StringBuilder(sql);
for(int i=0,size=ids.length;i<size;i++) {
	placeholderSql.append("?");
    if (i != size-1) {
		placeholderSql.append(",");
	}
}
placeholderSql.append(")");
PreparedStatement pre = conn.prepareStatement(placeholderSql.toString());
for(int i=0,size=ids.length;i<size;i++) {
	pre.setInt(i+1, ids[i]);
}
ResultSet rs = pre.executeQuery();
```

* spring JDBC

```java
JdbcTemplate jdbcTemplate = new JdbcTemplate(app.dataSource());
// 一般查询场景
String sql = "select * from user where id = ?";
Integer id = 1;
UserDO user = jdbcTemplate.queryForObject(sql,
BeanPropertyRowMapper.newInstance(UserDO.class), id);
// like 模糊查询场景
String sql = "select * from user where name like ?";
String like_name = "%" + "foo" + "%";
UserDO user = jdbcTemplate.queryForObject(sql,
BeanPropertyRowMapper.newInstance(UserDO.class), like_name);
// where in 查询场景
NamedParameterJdbcTemplate namedJdbcTemplate = new
NamedParameterJdbcTemplate(app.dataSource());
MapSqlParameterSource parameters = new MapSqlParameterSource();
parameters.addValue("names", Arrays.asList("foo", "bar"));
String sql = "select * from user where name in (:names)";
List<UserDO> users = namedJdbcTemplate.query(sql, parameters,
BeanPropertyRowMapper.newInstance(UserDO.class));
```

* Mybatis XML Mapper

```xml
<!-- 一般查询场景 -->
<select id="select" parameterType="java.lang.String" resultMap="BaseResultMap">
SELECT *
FROM user
WHERE name = #{name}
</select>
<!-- like 查询场景 -->
<select id="select" parameterType="java.lang.String" resultMap="BaseResultMap">
SELECT *
FROM user
WHERE name like CONCAT("%", #{name}, "%")
</select>
<!-- where in 查询场景 -->
<select id="select" parameterType="java.util.List" resultMap="BaseResultMap">
SELECT *
FROM user
WHERE name IN
<foreach collection="names" item="name" open="(" close=")" separator=",">
#{name}
</foreach>
</select>
```

* Mybatis Criteria

```java
public class UserDO {
    private Integer id;
    private String name;
    private Integer age;
}
public class UserDOExample {
	// auto generate by Mybatis
}
UserDOMapper userMapper = session.getMapper(UserDOMapper.class);
UserDOExample userExample = new UserDOExample();
UserDOExample.Criteria criteria = userExample.createCriteria();
// 一般查询场景
criteria.andNameEqualTo("foo");
// like 模糊查询场景
criteria.andNameLike("%foo%");
// where in 查询场景
criteria.andIdIn(Arrays.asList(1,2));
List<UserDO> users = userMapper.selectByExample(userExample);
```
