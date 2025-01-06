**在自动化工具fuzz出目录后进一步fuzz**

* 前言
* 字典的收集
  * 常见字典
    * 列举
    * 优化
  * 自己生成
    * 特定文件（名＋后缀），通用文件名+指定后缀
    * 字典生成工具
    * 使用AI
* ffuf的使用
* 继续魔改dirsearch

### 前言

  在测试web项目时必不可少的一步是使用dirsearch、御剑等目录扫描工具对目录进行扫描，但笔者常常遇到一个问题，工具跑出来一些目录，如何对这些目录进行进一步探索呢？比较好的方法是以这些目录为基础进行展开fuzz。

**实例**

这里对一个ipc设备进行漏洞挖掘，前期使用dirsearch扫描出了一些目录

![image-20250106153132061](C:\Users\tlj\Desktop\l11267doc\webSecurityNotes\安全技术\fuzz\images\image-20250106153132061.png)

能够确定扫出的401目录是接口对应的目录，而/conf/ /js/ /xml/下是一些静态文件，想要fuzz一下有没有未授权接口和尽可能多的静态文件

### 字典的

fuzz就离不开字典，一种说法是字典在精不在多，而笔者认为多和精同样重要。

#### 常见字典收集&选择

这里列出一些优秀项目：

* [TheKingOfDuck/fuzzDicts: You Know, For WEB Fuzzing ! 日站用的字典。](https://github.com/TheKingOfDuck/fuzzDicts)
* [danielmiessler/SecLists: SecLists is the security tester's companion. It's a collection of multiple types of lists used during security assessments, collected in one place. List types include usernames, passwords, URLs, sensitive data patterns, fuzzing payloads, web shells, and many more.](https://github.com/danielmiessler/SecLists)
* [assetnote/wordlists：由Assetnote提供的自动和手动Wordlists](https://github.com/assetnote/wordlists)

网上的字典资源很多，我们不可能把它们全部拿来跑一遍，所以字典的筛序和去重非常重要，以之前给出的实例为例子，我们在前期测试和信息收集的过程中了解到目标大概率是C或C++写的后端，而且在测试过程中发现所有接口都是没有后缀的，于是我们在挑选fuzz接口的目录时，不用考虑例如`.php` `.jsp` `.asp` `.do`之类的字典；由于测试过程中发现`/xml/`目录下的文件都是`.xml`后缀，`/conf/`下都是`.js`，于是我们在挑选字典时也要选择相应后缀。当然，刚刚说的这个规则并不绝对，这取决于其web服务器的配置和后端逻辑。

### ffuf的使用

fuzz工具的挑选也同样重要，虽然dirsearch、御剑等工具的本质也是fuzz，但是用它们在跑出的目录基础上继续跑效率太低，我们需要更加直接的fuzz工具，这里选择ffuf。