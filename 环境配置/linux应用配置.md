#### docker代理

```shell
# mkdir -p /etc/systemd/system/docker.service.d
# vim /etc/systemd/system/docker.service.d/http-proxy.conf
添加以下内容
[Service]
Environment="HTTP_PROXY=http://proxy.example.com:3128"      # 这里填自己真实的代理
Environment="HTTPS_PROXY=http://proxy.example.com:3128"

# 如果有内部镜像服务器，可以配置`NO_PROXY`参数， 比如
Environment="NO_PROXY=localhost,127.0.0.1,docker-registry.example.com,.corp"   # 多个地址用,号隔开
```



#### docker操作

```shell
docker ps -a
docker stop <容器ID或容器名称>
docker start <容器ID或容器名称>
docker exec -it <容器ID或容器名称> /bin/bash

```

