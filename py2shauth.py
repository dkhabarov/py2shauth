#!/usr/bin/env python
# -*- coding: utf-8 -*-
# py2shauth - simple two-step authentication script.

# Copyright © 2012 Denis 'Saymon21' Khabarov
# E-Mail: saymon at hub21 dot ru (saymon@hub21.ru)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3
# as published by the Free Software Foundation.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os, sys, string, yaml, syslog
from urllib2 import urlopen, URLError
from urllib import quote
from socket import getfqdn, gethostname
from random import choice, randint
from hashlib import sha512
check_nets=False
try:
	from ipaddr import IPAddress, IPNetwork
	check_nets=True
except ImportError as errmsg:
	print >> sys.stderr, "\033[31mWARNING!!!\033[0m "+str(errmsg)
	

		

def logger(priority,msg):
	syslog.openlog("py2shauth", syslog.LOG_PID)
	syslog.syslog(priority,msg)
	syslog.closelog()

chars = string.ascii_letters + string.digits
def get_security_code(config):
    return "".join(choice(chars) for x in range(randint(config['extra']['sec_code_min_len'], config['extra']['sec_code_max_len'])))

def get_ip():
	if os.environ.has_key('SSH_CONNECTION'):
		return os.getenv("SSH_CONNECTION").split()[0]

def exclude_ip(exclude_ips):
	if get_ip() in exclude_ips:
		return True

def exclude_net(nets):
	if not IPAddress:
		return None
	for net in nets:
		if IPAddress(get_ip()) in IPNetwork(net):
			return True
		
def get_token():
	try:
		res=urlopen(url="http://sms.ru/auth/get_token",timeout=10)
	except URLError as errstr:
		print("\033[31mAn error occurred while sending a secret code. Please try again later. \033[0m")
		logger(syslog.LOG_ERR,'Unable to get \'get_token\': %s' %(errstr))
		sys.exit(1)
	
	return res.read()

def send_sms(login, password, to, code):
	user=os.getenv("USER")
	token=get_token()
	shahash=sha512(password+token).hexdigest()
	
	if get_ip() is not None:
		msg="Attempt authorization on %s IP: %s for user: %s. Security code: %s" %(getfqdn(gethostname()),get_ip(),user,str(code))
	else:
		msg="Attempt authorization on %s for user %s. Security code: %s" %(getfqdn(gethostname()),user,code)

	url="http://sms.ru/sms/send?login=%s&token=%s&sha512=%s&to=%s&text=%s&partner_id=3805" %(str(login),token,shahash,to,quote(msg))
	try:
		res=urlopen(url=url,timeout=10)
	except URLError as errstr:
		print("\033[31mAn error occurred while sending a secret code. Please try again later. \033[0m ")
		logger(syslog.LOG_ERR,'Unable to send sms message: %s' %(errstr))
		sys.exit(1)
	service_result=res.read().splitlines()
	if service_result is not None and int(service_result[0]) != 100:
		print("\033[31m["+str(service_result[0])+"] An error occurred while sending a secret code. Please try again later. \033[0m")
		logger(syslog.LOG_ERR,"Unable to send sms message when service returned code: %s"%(str(service_result[0])))
		
		sys.exit(1)

def is_allowed_shell(shell):
	for line in open("/etc/shells", 'rb').readlines():
		line = line.strip()
		if line == "":
			continue
		if line[0] == "#":
			continue
		if shell == line:
			return True

def run_command_line(config):
	if is_allowed_shell(config['extra']['set_shell']):
		os.execv(config['extra']['set_shell'], ['',])
	else:
		print("\033[31m[108]: Error! Please contact to system administrator!\033[0m")
		logger(syslog.LOG_ERR,"Shell %s is not allowed!" %(config['extra']['set_shell']))
		sys.exit(1)
		
def validate_key(key, expectedkey):
	if key == None:
		return False
	elif key == expectedkey:
		return True
	else:
		return False
	
def send_question(phoneend):
	print("\033[32mWe sent a security code to your phone number ending in "+phoneend+". \033[0m")
	try:
		answer=raw_input("Enter security code: ")
	except KeyboardInterrupt:
		print("\n\033[31m Recv SIGINT. Exiting....\n\033[0m")
		logger(syslog.LOG_ERR,'Recv SIGINT. Exiting...')
		sys.exit(1)
		
	if not (len(answer)== 0):
		return answer
	else:
		print("\033[31mAuthentication failed! You're not sends security code!\033[0m")
		logger(syslog.LOG_ERR,"Authentication failed! You're not sends security code!")
		sys.exit(1) 

def main():
	try:
		fp=open("/usr/local/etc/.py2shauth.conf.yaml")
	except IOError as errstr:
		logger(syslog.LOG_ERR, errstr)
		sys.exit(1)
	try:
		config=yaml.load(fp.read())
	except yaml.YAMLError as errstr:
		logger(syslog.LOG_ERR,errstr)
		sys.exit(1)
	
	code=get_security_code(config)
	user=os.getenv('USER')
	
	
	userconfig="%s/.config/py2shauth.yaml" % (os.getenv("HOME"))
	if os.path.isfile(userconfig):
		try:
			ufp=open(userconfig)
		except IOError as errstr:
			print("\033[31m[157]: Error! Please contact to system administrator!\033[0m")
			logger(syslog.LOG_ERR,"IOError for %s: %s"%(userconfig,errstr))
			sys.exit(1)
		try:
			usrcfg=yaml.load(ufp.read())
		except yaml.YAMLError as errstr:
			print("\033[31m[163]: Error! Please contact to system administrator!\033[0m")
			logger(syslog.LOG_INFO,"YAMLError: %s" %(errstr))
			sys.exit(1)
	else:
		print("\033[31m[167]: Error for user: "+user+". Please contact to system administrator!\033[0m")
		logger(syslog.LOG_ERR,"Error for read: %s"%(userconfig))
		sys.exit(1)
				
	if user in usrcfg['users'] and usrcfg['users'][user].has_key('exclude_ips') and exclude_ip(usrcfg['users'][user]['exclude_ips']):
		logger(syslog.LOG_INFO,"User=%s, DSTIP=%s; authentication successfully when this ip has been excluded." % (user, get_ip()))
		run_command_line(config)
	elif check_nets and user in usrcfg['users'] and usrcfg['users'][user].has_key('exclude_nets') and exclude_net(usrcfg['users'][user]['exclude_nets']):
		logger(syslog.LOG_INFO,"User=%s, DSTIP=%s; authentication successfully when this subnet has been excluded." % (user, get_ip()))
		run_command_line(config)
	else:
		if user in usrcfg['users'] and usrcfg['users'][user].has_key('phone'):
			send_sms(login=str(config['sms_service']['login']), password=str(config['sms_service']['password']),to=str(usrcfg['users'][user]['phone']), code=code)
			answer = send_question(str(usrcfg['users'][user]['phone'])[-4:len(str(usrcfg['users'][user]['phone']))])
			validate=validate_key(answer, code)
			if not validate:
				print('\033[31m[183] Access denied! \033[0m')
				logger(syslog.LOG_ERR,"Authentication failure for %s from %s" %(user,get_ip()))
				sys.exit(1)
			else:
				logger(syslog.LOG_INFO,"User=%s, DSTIP=%s; authentication successfully" % (user, get_ip()))
				run_command_line(config)
		else:
			if config['extra'].has_key('deny_access_for_none_user') and config['extra']['deny_access_for_none_user']:
				print("\033[31m[191] Access denied! \033[0m")
				logger(syslog.LOG_ERR,"Authentication failure for %s from %s" %(user,get_ip()))
				sys.exit(1)
			else:
				run_command_line(config)

if __name__ == '__main__':
	main()
