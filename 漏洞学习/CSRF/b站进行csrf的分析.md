#### 分析

* 功能点：修改个性签名
* url：api.bilibili.com/x/member/web/sign/update

* 请求头
  * referer：可为空，可不存在；不能错
  * origin: 可为空，可不携带；不能错
* post携带的数据
  * user_sign:  个性签名
  * csrf；为固定值，但是必须携带；且这个字段在cookie中为bili_jct

#### 尝试

> 结论，如果能利用XSS等漏洞够获得cookie，则就可以完成csrf