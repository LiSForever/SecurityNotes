### 敏感文件

windows

```txt
boot.ini #查看系统版本
c:/windows/php.ini #php配置信息
c:/windows/my.ini #MYSQL配置文件，记录管理员登陆过的MYSQL用户名和密码
c:/winnt/php.ini
c:/winnt/my.ini
c:\mysql\data\mysql\user.MYD #mysql.user表中的数据库连接密码
c:\Program Files\RhinoSoft.com\Serv-U\ServUDaemon.ini #存储了虚拟主机网站路径和密码
c:\Program Files\Serv-U\ServUDaemon.ini
c:\windows\system32\inetsrv\MetaBase.xml #查看IIS的虚拟主机配置
c:\windows\repair\sam #WINDOWS系统初次安装的密码
c:\Program Files\ Serv-U\ServUAdmin.exe #6.0版本以前的serv-u管理员密码
c:\Program Files\RhinoSoft.com\ServUDaemon.exe
C:\Documents and Settings\All Users\Application Data\Symantec\pcAnywhere\*.cif文件
#存储了pcAnywhere的登陆密码
c:\Program Files\Apache Group\Apache\conf\httpd.conf 或C:\apache\conf\httpd.conf
#查看WINDOWS系统apache文件
c:/Resin-3.0.14/conf/resin.conf #查看jsp开发的网站resin文件配置信息.
c:/Resin/conf/resin.conf /usr/local/resin/conf/resin.conf #查看linux系统配置的JSP虚
拟主机
d:\APACHE\Apache2\conf\httpd.conf
C:\Program Files\mysql\my.ini
C:\mysql\data\mysql\user.MYD #存在MYSQL系统中的用户密码
C:\Windows\System32\drivers\etc\hostswinserver配置Telnet信息
```

linux

```textile
/etc/httpd/conf/httpd.conf
/etc/rc.local 有时可以读出来apache的路径
/usr/local/apache/conf/httpd.conf
/var/www/html/apache/conf/httpd.conf
/home/httpd/conf/httpd.conf
/usr/local/apache2/conf/httpd.conf
/usr/local/httpd/conf/httpd.conf
/etc/apache/httpd.conf
/usr/local/lib/php.ini
/etc/hosts.deny 定义禁止访问本机的主机
/etc/bashrc bash shell 的系统全局配置
/etc/group 系统用户组的定义文件
/etc/httpd/httpd.conf
/etc/issue 显示Linux核心的发行版本信息（用于本地登陆用户）
/etc/issue/net 显示Linux核心和发行版本信息（用于远程登陆用户）----没成功
/etc/ssh/ssh_config ssh配置文件
/etc/termcap 终端定义和配置文件
/etc/xinetd.d
/etc/mtab 包含当前安装的文件系统列表 有时可以读取到当前网站的路径
redhat-release:包含识别当前Red Hat 版本号的字符串
shells:列出可用在系统上的shell命令行解释器(bash,sh,csh等).
/etc/vsftpd/vsftpd.conf
/etc/xinetd.conf xinetd 配置文件
/etc/protocols 列举当前可用的协议
/etc/logrotate.conf 维护 /var/log 目录中的日志文件
/etc/ld.so.conf “动态链接程序”（Dynamic Linker）的配置。
我在我的系统中安装了非常有用的 wget 实用程序。/etc/ 中有一个 /etc/wgetrc 文件
/etc/wgetrc
Linux操作系统用户配置文件
/etc/passwd
/etc/shadow
/etc/inputrc
DNS客户机配置文件，设置DNS服务器的IP地址及DNS域名
/etc/resolv.conf
内容为Default Router的ip地址
Redhat 5.x: /etc/sysconfig/network
/etc/sendmail.cf (Linux) Sendmail(EMAIL服务器)配置文件
/etc/sendmail.cw 本地主机名
```

### 审计步骤

* 确定功能点
  
  * 常规地通过文档、前端测试得到
  
  * 审计关键字

```textile
org.apache.commons.io.FileUtils
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.util.Scanner
sun.nio.ch.FileChannelImpl
java.io.File.list/listFiles
java.io.FileInputStream
java.io.FileOutputStream
java.io.FileSystem/Win32FileSystem/WinNTFileSystem/UnixFileSystem
sun.nio.fs.UnixFileSystemProvider/WindowsFileSystemProvider
java.io.RandomAccessFile
sun.nio.fs.CopyFile
sun.nio.fs.UnixChannelFactory
sun.nio.fs.WindowsChannelFactory
java.nio.channels.AsynchronousFileChannel
FileUtil/IOUtil
BufferedReader
readAllBytes
scanner
```

* 文件名是否可控

* 文件路径是否可控
