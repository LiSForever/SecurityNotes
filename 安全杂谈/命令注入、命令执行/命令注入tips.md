#### 特殊字符

* `反引号`
* 
* 

#### 常见绕过

#### 突破长度限制

#### 关于shell脚本的审计

* shell常常被后端程序调用，传入参数过程中容易发生二次注入

```shell
# test.sh 'ls -l'
$1
`$1` # `'$1'`不行 `""$1"`可以
$($1) # $('$1')不行 $("$1")可以
eval $1 # 同上
exec $1 # 同上
source
bash -c / sh -c
```

