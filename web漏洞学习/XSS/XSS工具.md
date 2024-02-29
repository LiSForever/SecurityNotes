### XSpear

```shell
# 只显示结果
xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 0

# 显示进度条 默认
xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 1

# 显示扫描详细信息
xspear -u "http://testphp.vulnweb.com/listproducts.php?cat=123" -v 3

# post 并输出json结果
xspear -u "http://testphp.vulnweb.com/search.php?test=query" -d "searchFor=yy" -o json -v 0

# 设置扫描线程
xspear -u "http://testphp.vulnweb.com/search.php?test=query" -t 30

# 选择扫描参数
xspear -u "http://testphp.vulnweb.com/search.php?test=query&cat=123&ppl=1fhhahwul" -p cat,test

# 测试所有参数
xspear -u "http://testphp.vulnweb.com/search.php?test=query&cat=123&ppl=1fhhahwul" -a 

# 盲打
xspear -u "http://testphp.vulnweb.com/search.php?test=query" -b "https://hahwul.xss.ht" -a
```



### xsstrike

```shell
# GET
python3 xsstrike.py -u "http://192.168.26.138/xss.php?payload=1"

# POST
python3 xsstrike.py -u "http://example.com/search.php" --data "q=query"
python3 xsstrike.py -u "http://example.com/search.php" --data '{"q":"query"} --json'

# 测试url路径
python3 xsstrike.py -u "http://example.com/search/form/query" --path

# 从该url开始爬,-l表示爬取深度
python3 xsstrike.py -u "http://example.com/page.php" --crawl -l 3

# 添加种子或是测试文件中的URL
python xsstrike.py --seeds urls.txt

# 分析html和暴力破解寻找隐藏参数
python3 xsstrike.py -u "http://example.com/page.php" --params

# 盲扫，尝试向html表单的每个变量拆入XSS
python3 xsstrike.py -u http://example.com/page.php?q=query --crawl --blind

#模糊测试，-d设置延迟
python3 xsstrike.py -u "http://example.com/search.php?q=query" --fuzzer -d 1
```

