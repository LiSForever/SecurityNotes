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

### 写ssh-keygen公钥

### 写计划任务

### redis主从复制getshell

#### 远程主从

#### 本地主从

### CVE-2022-0543

## 实战案例

### redis到shiro反序列化

