### 前言

​	SQL注入如今发生的情况已经不多了，在Java作为后端语言的项目中就更少了，这都要归功于框架的成熟和预编译的广泛使用。但是SQL毕竟还没有死绝，一方面，即使使用了成熟的框架，也会有程序员因为对框架特性的不了解而编写出带有漏洞的代码；另一方面，预编译并不是在所有场景下都有效。

​	SQL注入产生后的利用方式可以说是五花八门，各种炫技般的payload也是令人眼花缭乱，但本篇笔记着重从Java和相关框架的角度，总结分析SQL注入在Java项目中的成因，并对防御方式做一定的探讨。

### Mybatis中的SQL注入

#### #{}和${}的区别

* #{}是占位符（预编译），${}是拼接符

### 预编译需要注意的几点

有些情况下是无法使用预编译的，或者说使用起来没有那么简单

#### order by注入

#### like注入

```txt
```



#### in注入

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

#### 动态字段名

### 漏洞修复

