import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii
from requests import codes, Session


LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"

def do_login_form(sess, username,password):
	data_dict = {"username":username,\
			"password":password,\
			"login":"Login"
			}
	response = sess.post(LOGIN_FORM_URL,data_dict)
	return response.status_code == codes.ok

def do_setcoins_form(sess,uname, coins):
	data_dict = {"username":uname,\
			"amount":str(coins),\
			}
	response = sess.post(SETCOINS_FORM_URL, data_dict)
	return response.status_code == codes.ok


def do_attack():
	sess = Session()
  	#you'll need to change this to a non-admin user, such as 'victim'.
	uname ="victim"
	pw = "victim"
	target_uname = uname
	amount = 5000
	assert(do_login_form(sess, uname,pw))
	#Maul the admin cookie in the 'sess' object here
	_block_size_bytes = 16
	ctxt = sess.cookies.get("admin")
	print(ctxt)
	ctxt = bytes.fromhex(ctxt)
	iv = ctxt[:_block_size_bytes]
	rest = ctxt[_block_size_bytes:]
	l = [bin(x) for x in list(iv)]
	fist_byte_IV = l[0]
	fist_byte_IV = list(fist_byte_IV)
	if fist_byte_IV[-1] == '1':
		fist_byte_IV[-1] = '0'
	else:
		fist_byte_IV[-1] = '1'
	fist_byte_IV = ''.join(fist_byte_IV)
	l[0] = fist_byte_IV
	ctxt = bytes([int(x, 0) for x in l])
	ctxt = ctxt+rest
	sess.cookies.set("admin", None)
	sess.cookies.set("admin", ctxt.hex())  	
	result = do_setcoins_form(sess, target_uname,amount)
	print("Attack successful? " + str(result))


if __name__=='__main__':
	do_attack()
