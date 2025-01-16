### 基础

#### 简述

* JSP作为模板时和freemarker、Thymeleaf、Velocity.md等模板引擎不太一样，后三者的注入场景基本上不可能发生在预先写好的模板文件中，而JSP作为模板引擎的注入则相反，当然这也就需要依赖模板文件是如何写的。
* JSP本质上就是servlet，JSP中甚至可以直接嵌入Java代码，所以JSP作为模板引擎的风险还挺多的，如果我们输入的参数不止是被预先定义的模板当做数据，而且作为代码执行，则会造成很大危害。
* JSP中可以进行数据库操作等很多操作（这超出了模板引擎的用法，现在不常见），所以有时JSP还有SQL注入等常规漏洞的风险

#### JSP语法

  JSP是HTML+JSP语法，可能存在风险的地方在JSP语法中，JSP语法有：

* 指令：指令提供了有关JSP页面整体结构的指令给JSP引擎。这些指令控制处理页面的方式。主要的指令包括

```jsp
<%-- page: 定义页面依赖属性，如内容类型、缓存需求、错误处理页面等 --%>
<%@ page language="java" contentType="text/html; charset=UTF-8" %>

<%-- include: 用于在当前JSP页面中静态包含其他文件 --%>
<%@ include file="header.jsp" %>

<%-- taglib: 用于引入自定义标签库 --%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
```

* 动作:JSP动作用于执行那些不适合用Java代码表达的操作，例如实例化JavaBean组件、在Bean之间设置属性等。

```jsp
<%-- jsp:include: 执行动态包含其他资源 --%>
<jsp:include page="header.jsp" />

<%-- jsp:forward: 将请求转发到另一个资源 --%>
<jsp:forward page="success.jsp" />

<%-- jsp:useBean: 查找或实例化一个JavaBean --%>
<jsp:forward page="success.jsp" />
```

* 脚本元素：脚本元素允许在JSP页面中嵌入Java代码

```jsp
<%-- 声明（Declarations）: 用于定义方法或变量，这些方法或变量可供后续的Java代码和表达式使用 --%>
<%! int counter = 0; %>
<%! public void incrementCounter() { counter++; } %>

<%-- 表达式（Expressions）: 用于在JSP输出中插入值，表达式在输出时自动转换为字符串 --%>
<%= "Hello, " + userName + "!" %>

<%-- 脚本片段（Scriptlets）: 用于嵌入执行任何Java代码，不自动输出到页面上 --%>
<%
  Date date = new Date();
  out.println("Current Date: " + date.toString());
%>
```

* EL表达式：JSP 2.0 引入了表达式语言（EL），它简化了Web页面开发者在页面中访问和操作数据的方式。

```jsp
<%-- 语法 --%>
${expression}
```

* JSTL：JSTL 提供了一组用于常见任务的标准标签，如迭代、条件处理、国际化和格式化。

```jsp
<c:forEach var="item" items="${items}">
  Item: ${item}<br/>
</c:forEach>
```

### 如何定位注入点

* 搜素${}和<%关键字，寻找JSP语法，并确定传入参数是否可以控



