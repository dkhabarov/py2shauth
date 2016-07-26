# py2shauth

Простая обёртка к шелу, позволяющая добавить дополнительный способ аутентификации на серверах на базе linux. Временный пароль будет отправлен по средствам sms, используя сервис http://sms.ru/ Будет работать при использовании SSH, su и физическом доступе к консоли сервера. Однако писалось только для серверов. Никаких DE. Протестировано пока только под Ubuntu 12.4, python 2.7.

_just for fun_

Использование:
```shell
cp .py2shauth.conf.yaml /usr/local/etc/.py2shauth.conf.yaml
vim/nano /usr/local/etc/.py2shauth.conf.yaml
mkdir /home/username/.config
cp userconfig.yaml  /home/username/.config/py2shauth.yaml
vim/nano /home/username/.config/py2shauth.yaml
mkdir /usr/share/py2shauth/
cp py2shauth.py /usr/share/py2shauth/py2shauth.py
chmod +x /usr/share/py2shauth/py2shauth.py
usermod -s /usr/share/py2shauth/py2shauth.py username
```
##Требования:

Наличие модуля pyyaml и ipaddr

```
pip install yaml
pip install ipaddr
```
Debian/Ubuntu:

```apt-get install python-yaml python-ipaddr```

CentOS: Сначала надо будет подключить репозиторий rpmforge, потом

```yum -y install python-yaml python-ipaddr```

Gentoo/Calculate Linux:
```
emerge dev-python/pyyaml
emerge dev-python/ipaddr
```
Убедительная просьба!!! Пожалуйста, сообщайте обо всех ошибках!

**Внимание! Используйте этот скрипт только на свой страх и риск!!!**

Минус этого решения: Отказываемся от sftp/scp.

Возможные проблемы и их решение

В некоторых дистрибутивах при аутентификации происходит провека валидности шела при помощи pam_shells. Например, я замечал в Calculate Scratch Server 13 в файле /etc/pam.d/system-login:
```
auth            required        pam_shells.so
```
В таком случае, нужно будет прописать полный путь до py2shauth.py и имя скрипта в файл /etc/shells:
```
# cat /etc/shells 
# /etc/shells: valid login shells
/bin/bash
/bin/csh
/bin/esh
/bin/fish
/bin/ksh
/bin/sash
/bin/sh
/bin/tcsh
/bin/zsh
/usr/share/py2shauth/py2shauth.py
```
