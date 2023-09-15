### PHP代码审计

#### 审计内容

* 工具扫描人工排查
* 一些工具无法扫描的漏洞，例如逻辑漏洞
  * 用户登录、修改密码等
  * 文件上传、管理等
  * 过滤函数，是否可以绕过

#### 常规漏洞的排查

部分常见漏洞的一些存在形式通过黑盒或者通过工具代码审计难以发现

##### SQL注入

* http头部注入
* 宽字节注入 “SET NAME”
* 二次ulrdecode，urldecode、rawurldecode函数
* 二次注入

##### XSS

* 敏感函数
  * echo、print系列、var_export、var_dump

##### 文件包含

* 相关设置
  * open_basedir：设置php有权限操作的目录
  * upload_tmp_dir：文件上传临时目录
  * allow_url_fopen：是否允许文件操作函数将http/ftp url当做文件打开
  * allow_url_include：是否允许远程文件包含
    * [include](https://www.php.net/manual/zh/function.include.php)、[include_once](https://www.php.net/manual/zh/function.include-once.php)、[require](https://www.php.net/manual/zh/function.require.php) 及 [require_once](https://www.php.net/manual/zh/function.require-once.php) 的使用需要上面两个都设置为On
* 敏感函数：[include](https://www.php.net/manual/zh/function.include.php)、[include_once](https://www.php.net/manual/zh/function.include-once.php)、[require](https://www.php.net/manual/zh/function.require.php) 及 [require_once](https://www.php.net/manual/zh/function.require-once.php) 

##### 文件下载和读取

* 黑盒测试比较方便，可以直接在前端查看有哪些功能点访问了文件内容，直接去尝试更改url或者其他参数

* 敏感函数
  * file_get_contents()、highlight_file()、fopen()、readfile()、fread()、fgetss()、fgets()、parse_ini_file()、show_source()、file()

##### 文件上传

* 敏感函数
  * move_uploaded_file如果是基于黑名单过滤，主要看有没有过滤到位

##### 代码执行

* 代码执行函数

  * eval、assert 执行php代码
  * call_user_func、call_user_func_array、array_map 调用函数
  * create_function
  * call_user_func_array
  * array_filter
  * preg_replace()

  ```php
  preg_replace('正则规则','替换字符'，'目标字符')
  执行命令和上传文件参考assert函数(不需要加分号)。
  将目标字符中符合正则规则的字符替换为替换字符，此时如果正则规则中使用/e修饰符，则存在代码执行漏洞。
  <?php
      preg_replace("/test/e",$_POST["cmd"],"jutst test");
  ?>
  这里可以使用chr()函数转换ASCII编码来执行代码。
   
  #phpinfo();
  eval(chr(112).chr(104).chr(112).chr(105).chr(110).chr(102).chr(111).chr(40).chr(41).chr(59))
  ```

  

  * 动态函数($a($b))

##### 命令执行

* 命令执行函数
  * system
  * passthru
  * exec
  * pcntl_exec
  * shell_exec
  * popen
  * proc_popen

##### 变量覆盖

* 危险函数
  * extract
  * parse_str
  * import_request_variables







#### 其他思路

##### 直接寻找外部输入值

