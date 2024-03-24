## SpringMVC从URL到对于Controller的过程分析

### 代码梳理

```java
protected void doDispatch(HttpServletRequest request, HttpServletResponse response) throws Exception {
		HttpServletRequest processedRequest = request;
		HandlerExecutionChain mappedHandler = null;
		boolean multipartRequestParsed = false;

		WebAsyncManager asyncManager = WebAsyncUtils.getAsyncManager(request);

		try {
			ModelAndView mv = null;
			Exception dispatchException = null;

			try {
                  // 检查是否是一个多部分请求
				processedRequest = checkMultipart(request);
				multipartRequestParsed = (processedRequest != request);

				// 根据当前请求获取对应的处理器执行链（HandlerExecutionChain），其中包括处理器对象以及拦截器链等信息。
                 // 处理器执行链（HandlerExecutionChain）包含了一个处理器对象（通常是一个 Controller 或处理器适配器返回的处理器），以及一个或多个拦截器（HandlerInterceptor）
                 // 处理器（Handler）是指用于处理特定请求的组件，通常是一个普通的 Java 类或者是一个标注了 @Controller 注解的类。处理器负责处理请求并生成响应。
				mappedHandler = getHandler(processedRequest);
                  
                  // 处理器执行链为空或没有找到合适处理器
				if (mappedHandler == null || mappedHandler.getHandler() == null) {
                      // 自定的处理方式，定义了没有找到path时的处理方法，例如返回一个404页面
					noHandlerFound(processedRequest, response);
					return;
				}

				// 根据处理器对象获取对应的处理器适配器，用于执行处理器
                  // 执行处理器（HandlerAdapter）是一个接口，定义了用于执行处理器的方法。在 Spring MVC 中，不同类型的处理器（比如普通的 Java 对象、Controller、RESTful 控制器等）可能需要不同的执行方式，因此需要不同的处理器适配器来执行它们
				HandlerAdapter ha = getHandlerAdapter(mappedHandler.getHandler());

				// 这段代码的作用是处理 GET 或 HEAD 请求，并根据请求的 Last-Modified 值来决定是否返回 304 Not Modified 状态码
				String method = request.getMethod();
				boolean isGet = "GET".equals(method);
				if (isGet || "HEAD".equals(method)) {
					long lastModified = ha.getLastModified(request, mappedHandler.getHandler());
					if (logger.isDebugEnabled()) {
						logger.debug("Last-Modified value for [" + getRequestUri(request) + "] is: " + lastModified);
					}
					if (new ServletWebRequest(request, response).checkNotModified(lastModified) && isGet) {
						return;
					}
				}
                
                  // 应用处理器前置拦截器，如果有前置拦截器返回 false，则直接返回
				if (!mappedHandler.applyPreHandle(processedRequest, response)) {
					return;
				}

				// 通过处理器适配器执行处理器，并获取处理器执行后的返回结果
				mv = ha.handle(processedRequest, response, mappedHandler.getHandler());

                  //  异步请求处理相关
				if (asyncManager.isConcurrentHandlingStarted()) {
					return;
				}

				applyDefaultViewName(processedRequest, mv);
                
                  // 应用处理器后置拦截器，处理器执行后再应用后置拦截器
				mappedHandler.applyPostHandle(processedRequest, response, mv);
			}
			catch (Exception ex) {
				dispatchException = ex;
			}
			catch (Throwable err) {
				// As of 4.3, we're processing Errors thrown from handler methods as well,
				// making them available for @ExceptionHandler methods and other scenarios.
				dispatchException = new NestedServletException("Handler dispatch failed", err);
			}
             
             // 处理处理器执行的结果，包括视图解析、视图渲染等操作
			processDispatchResult(processedRequest, response, mappedHandler, mv, dispatchException);
		}
		catch (Exception ex) {
             // 触发请求处理完成后的处理，包括清理资源、执行后置处理器等操作
			triggerAfterCompletion(processedRequest, response, mappedHandler, ex);
		}
		catch (Throwable err) {
			triggerAfterCompletion(processedRequest, response, mappedHandler,
					new NestedServletException("Handler processing failed", err));
		}
		finally {
			if (asyncManager.isConcurrentHandlingStarted()) {
				// Instead of postHandle and afterCompletion
				if (mappedHandler != null) {
					mappedHandler.applyAfterConcurrentHandlingStarted(processedRequest, response);
				}
			}
			else {
				// Clean up any resources used by a multipart request.
				if (multipartRequestParsed) {
					cleanupMultipart(processedRequest);
				}
			}
		}
	}
```

```java
protected HandlerExecutionChain getHandler(HttpServletRequest request) throws Exception {
         // 
		for (HandlerMapping hm : this.handlerMappings) {
			if (logger.isTraceEnabled()) {
				logger.trace(
						"Testing handler map [" + hm + "] in DispatcherServlet with name '" + getServletName() + "'");
			}
			HandlerExecutionChain handler = hm.getHandler(request);
			if (handler != null) {
				return handler;
			}
		}
		return null;
	}
```

