### SpEL表达式

#### 定位

```java
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
```

 ```txt
 在注解、xml配置文件等，#开头字符串
 @Value("#{systemProperties['java.home']}")
 ```



### SpringBoot SpEL注入调试分析