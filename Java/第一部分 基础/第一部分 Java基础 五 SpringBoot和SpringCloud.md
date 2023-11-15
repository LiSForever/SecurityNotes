#### idea创建springboot项目

Spring Initializr：注意java版本要选择自己安装的版本，而且这个不同的java版本支持的springboot版本也不同；注意选择type为maven

![image-20231025104316006](.\images\image-20231025104316006.png)

在之后的页面选在要添加的依赖，这里不选也可以，后续pom.xml可以再添加，我们这里选择web里的spring web

![image-20231025104552697](.\images\image-20231025104552697.png)

创建项目后运行，会报错，这还是java版本设置的问题

![image-20231025105005228](.\images\image-20231025105005228.png)

有两个解决方法，一个是把java版本切换为17满足框架的需求，但是大多数人用的都是java8，我们就用另一种解决方法，[解决：java: 警告: 源发行版 17 需要目标发行版 17-CSDN博客](https://blog.csdn.net/angelbeautiful/article/details/131182554)

还有报错，这仍然是框架版本的问题，把pom.xml中的springboot改为2.7.1即可

![image-20231025105804583](.\images\image-20231025105804583.png)

#### 关于Springboot项目

* 项目结构：[SpringBoot项目目录结构解析 - 知乎 (zhihu.com)](https://zhuanlan.zhihu.com/p/198191092)；[SpringBoot : 一个较完整的SpringBoot项目的目录结构_springboot项目目录结构_全智能时代的博客-CSDN博客](https://blog.csdn.net/qq_31432773/article/details/115768079)

* application.properties
  * 关于application.properties和application.yml：[面试突击74：properties和yml有什么区别？ - 掘金 (juejin.cn)](https://juejin.cn/post/7131896794543292430)

* 设置静态资源路径：
  * 一般的静态资源无需设置路径，直接放在 项目/resources/static下即可
  * 关于默认页面不指向index.html：暂未解决，且向采用controller返回视图，出新的问题，一是无法返回static下的html，二是无法将 "/"与其他视图映射

* 编写controller
  * controller必须在启动类同层或者下层目录
  
    ![image-20231026190804546](.\images\image-20231026190804546.png)

