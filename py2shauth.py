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

import os, sys, string, yaml, logging
from urllib2 import urlopen, URLError
from urllib import quote
from socket import getfqdn, gethostname
from random import choice, randint
from hashlib import sha512

logger = logging.getLogger('py2shauth')
hdlr = logging.FileHandler('/tmp/.py2shauth.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)

chars = string.ascii_letters + string.digits
def get_security_code(config):
    return "".join(choice(chars) for x in range(randint(config['extra']['sec_code_min_len'], config['extra']['sec_code_max_len'])))

def get_ip():
	if os.environ.has_key('SSH_CONNECTION'):
		return os.getenv("SSH_CONNECTION").split()[0]

def exclude_ip(exclude_ips):
	if get_ip() in exclude_ips:
		return True

def get_token():
	try:
		res=urlopen("http://sms.ru/auth/get_token")
	except URLError:
		print("\033[31mAn error occurred while sending a secret code. Please try again later. \033[0m")
		logger.error('Unable to get \'get_token\'')
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
		res=urlopen(url)
	except URLError as errstr:
		print("\033[31mAn error occurred while sending a secret code. Please try again later. \033[0m ")
		logger.error('Unable to send sms message: %s' %(errstr))
		sys.exit(1)
	service_result=res.read().splitlines()
	if service_result is not None and int(service_result[0]) != 100:
		print("\033[31m["+str(service_result[0])+"] An error occurred while sending a secret code. Please try again later. \033[0m")
		logger.error("Unable to send sms message when service returned code: %s"%(str(service_result[0])))
		
		sys.exit(1)
		
def validate_key(key, expectedkey):
	if key == None:
		send_question()
		return False
	elif key == expectedkey:
		return True
	else:
		return False
	
def send_question(phoneend):
	print("\033[32mWe sent a security code to your phone number ending in "+phoneend+". \033[0m")
	try:
		answer=raw_input("Enter security code:")
	except KeyboardInterrupt:
		print("\n\033[31m Recv SIGINT. Exiting....\n\033[0m")
		logger.info('Recv SIGINT. Exiting...')
		sys.exit(1)
		
	if not (len(answer)== 0):
		return answer
	else:
		print("\033[31mAuthentication failed! You're not sends security code!\033[0m")
		logger.error("Authentication failed! You're not sends security code!")
		sys.exit(1) 

def main():
	try:
		fp=open("/usr/local/etc/.py2shauth.conf.yaml")
	except IOError as errstr:
		logger.error(errstr)
		sys.exit(1)
	try:
		config=yaml.load(fp.read())
	except yaml.YAMLError as errstr:
		logger.error(errstr)
		sys.exit(1)
	
	code=get_security_code(config)
	user=os.getenv('USER')
	if config['users'][user].has_key('exclude_ips') and exclude_ip(config['users'][user]['exclude_ips']):
		logger.info("User=%s, DSTIP=%s; authentication successfully when this ip has been excluded." % (user, get_ip()))
		os.execv(config['extra']['set_shell'], ['',])
	
	if user in config['users'] and config['users'][user].has_key('phone'):
		send_sms(login=str(config['sms_service']['login']), password=str(config['sms_service']['password']),to=str(config['users'][user]['phone']), code=code)
		answer = send_question(str(config['users'][user]['phone'])[-4:len(str(config['users'][user]['phone']))])
		validate=validate_key(answer, code)
		if not validate:
			print('\033[31mAccess denied! \033[0m')
			logger.info("User=%s, DSTIP=%s; authentication failed when recv bad security code." %(user,get_ip()))
			sys.exit(1)
		else:
			logger.info("User=%s, DSTIP=%s; authentication successfully" % (user, get_ip()))
			os.execv(config['extra']['set_shell'], ['',])
	else:
		if config['extra'].has_key('deny_access_for_none_user') and config['extra']['deny_access_for_none_user']:
			print("\033[31mAccess denied! \033[0m")
			sys.exit(1)
		else:
			#print("Hello!")
			os.execv(config['extra']['set_shell'], ['',])

if __name__ == '__main__':
	main()
