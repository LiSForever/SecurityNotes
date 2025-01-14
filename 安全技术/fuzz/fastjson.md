```txt
JSON#parseObject(String text)
	JSON#parse(String text)
		JSON#parse(String text, int features)
			DefaultJSONParser#DefaultJSONParser(final String input, final ParserConfig config, int features) # 初始化一个用于解析的DefaultJSONParser
			DefaultJSONParser#parse()
				DefaultJSONParser#parse(Object fieldName)
					DefaultJSONParser#parseObject(final Map object, Object fieldName) # for循环遍历json字符串。如果没有@type，则将解析出的key和value put进入一个JSONObject中，这个过程没有加载类的操作；如果有@type，则会继续调用下列函数
						TypeUtils#loadClass(String className, ClassLoader classLoader) # 加载类
						
						
```

