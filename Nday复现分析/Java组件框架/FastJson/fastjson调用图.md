* 1.2.24 不指定expectClass

```txt
JSON#parseObject(String text)
	JSON#parse(String text)
		JSON#parse(String text, int features)
			DefaultJSONParser#DefaultJSONParser(final String input, final ParserConfig config, int features) # 初始化一个用于解析的DefaultJSONParser
			DefaultJSONParser#parse()
				DefaultJSONParser#parse(Object fieldName)
					DefaultJSONParser#parseObject(final Map object, Object fieldName) # for循环遍历json字符串，一些过滤和解码操作使得我们有绕waf的空间。如果没有@type，则将解析出的key和value put进入一个JSONObject中，这个过程没有加载类的操作；如果有@type，则会继续调用下列函数
						TypeUtils#loadClass(String className, ClassLoader classLoader) # 加载类
						ParserConfig#getDeserializer(Type type) # 获取反序列化器
							IdentityHashMap#get(K key) # 尝试从内置类中获取
							ParserConfig#getDeserializer(Class<?> clazz, Type type) # 获取反序列化器，一些黑名单中的类被禁止获取反序列化器。
								ParserConfig#createJavaBeanDeserializer(Class<?> clazz, Type type) # 创建一个反序列化器
									JavaBeanDeserializer#JavaBeanDeserializer(ParserConfig config, Class<?> clazz, Type type)
										JavaBeanInfo#build(Class<?> clazz, Type type, PropertyNamingStrategy propertyNamingStrategy) # 获取了类的构造方法、属性，依次从类的setXxx、类的public属性、类的满足特定要求的getXxx获取反序列化器
						JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName) # 反序列化json对象
							JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName, int features)
								JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName, Object object, int features) # 反序列化json对象，包含实例化类，和从json中反序列化类的属性
									JavaBeanDeserializer#createInstance(DefaultJSONParser parser, Type type) # 实例化类，后面解析json属性，基本类型直接setValue赋值，非基本属性还需要反序列化
										DefaultFieldDeserializer#parseField(DefaultJSONParser parser, Object object, Type objectType, Map<String, Object> fieldValues)  # 从json字符串中解析到非基本类型的属性，无法直接赋值，需要通过反序列化器进行解析。先获取反序列化器，再反序列化对象，再通过setValue赋值
											DefaultFieldDeserializer#getFieldValueDeserilizer(ParserConfig config) # 获取反序列化器
											JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName, int features) # 反序列化对象
											DefaultFieldDeserializer#setValue(Object object, Object value) # 赋值
												
										DefaultFieldDeserializer#setValue(Object object, Object value) # 通过反射，或者通过先前获取反序列化器中的函数赋值
											
								
								
						
```

* 1.2.25 expectClass为内置类

```txt
JSON#parseObject(String text, Class<T> clazz)
	JSON#parseObject(String json, Class<T> clazz, Feature... features)
		JSON#parseObject(String input, Type clazz, ParserConfig config, ParseProcess processor, int featureValues, Feature... features)
			DefaultJSONParser#parseObject(Type type, Object fieldName)
				ParserConfig#getDeserializer(Type type) # 获取expectClass的反序列化器
				JavaObjectDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName)
					DefaultJSONParser#parse(Object fieldName) # 到这里，后续代码和expectClass为null的情况一致了
						DefaultJSONParser#parseObject(final Map object, Object fieldName)
							ParserConfig#checkAutoType(String typeName, Class<?> expectClass) # 这里expectClass为空
```

* 1.2.25 expectClass为非内置类

```txt
JSON#parseObject(String text, Class<T> clazz)
	JSON#parseObject(String json, Class<T> clazz, Feature... features)
		JSON#parseObject(String input, Type clazz, ParserConfig config, ParseProcess processor, int featureValues, Feature... features)
			DefaultJSONParser#parseObject(Type type, Object fieldName)
				ParserConfig#getDeserializer(Type type) # 获取expectClass的反序列化器
				JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName)
					JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName, int features)
						JavaBeanDeserializer#deserialze(DefaultJSONParser parser, Type type, Object fieldName, Object object, int features)
							ParserConfig#checkAutoType(String typeName, Class<?> expectClass) # 这里expectClass为显式指定的类
							
```

* 1.2.43 `[`开头调用链

```java
public final static int LPAREN               = 10; // ("("),
//
public final static int RPAREN               = 11; // (")"),
//
public final static int LBRACE               = 12; // ("{"),
//
public final static int RBRACE               = 13; // ("}"),
//
public final static int LBRACKET             = 14; // ("["),
//
public final static int RBRACKET             = 15; // ("]"),
//
public final static int COMMA                = 16; // (","),
//
public final static int COLON                = 17; // (":"),
```



```txt
JSON#parseObject(String text)
	JSON#parse(String text)
		JSON#parse(String text, int features)
			DefaultJSONParser#DefaultJSONParser(final String input, final ParserConfig config, int features) # 初始化一个用于解析的DefaultJSONParser
			DefaultJSONParser#parse()
				DefaultJSONParser#parse(Object fieldName)
					DefaultJSONParser#parseObject(final Map object, Object fieldName) # for循环遍历json字符串，一些过滤和解码操作使得我们有绕waf的空间。如果没有@type，则将解析出的key和value put进入一个JSONObject中，这个过程没有加载类的操作；如果有@type，则会继续调用下列函数
```

