### 模板注入的发生

```html
<!-- hello.html -->
<html>
	<h1>Hello World!</h1>
	<h2>{{name}}</h2>
</html>
```

* 不存在漏洞的代码

```python
from flask import Flask, request, render_template
app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', default='guest')
    # 
    return render_template('index.html', name=name)

app.run()
```

* 存在漏洞

```python
from flask import Flask, request, render_template_string
from jinja2 import Template
app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name', default='guest')
    t = '''
        <html>
            <h1>Hello %s</h1>
        </html>
        ''' % (name)
    # 将一段字符串作为模板进行渲染
    return render_template_string(t)

"""这样的代码同样存在漏洞
def index():
    name = request.args.get('name', default='guest')
    t = Template(
        '''
        <html>
            <h1>Hello %s</h1>
        </html>
        ''' % name
    )
    # 对模板对象进行渲染
    return t.render()
"""
app.run()
```

* 通过观察以上代码，我们可以发现漏洞出现的原因：服务器端将用户可控的输入**直接拼接到模板中进行渲染**，导致漏洞出现。反之，要解决该漏洞，则只需**先将模板渲染，再拼接**字符串。
* 深入到Flask渲染函数原理来讲，render和render_template_string由用户拼接，字符串不会自动转义，而render_template会对字符串计进行**自动转义**，因此避免了参数被作为表达式执行。

### 不同类型的引擎分辨

![img](.\images\1596031074.jpg)

### 漏洞利用

#### 通用的利用思路

#### 常用payload

* 获取配置信息
* XSS
* RCE

### 针对防护的绕过（实际不常用）

### 工具Tplmap的使用

