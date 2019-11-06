import os
from cryptography.hazmat.primitives import hashes, padding, ciphers
from cryptography.hazmat.backends import default_backend
import base64
import binascii


def format_plaintext(is_admin, password):
    tmp = bytearray(str.encode(password))
    return bytes(bytearray((is_admin).to_bytes(1,"big")) + tmp)

def is_admin_cookie(decrypted_cookie):
    return decrypted_cookie[0] == 1

class Encryption(object):
    def __init__(self, in_key=None):
        self._backend = default_backend()
        self._block_size_bytes = int(ciphers.algorithms.AES.block_size/8)
        if in_key is None:
            self._key = os.urandom(self._block_size_bytes)
        else:
            self._key = in_key

    def encrypt(self, msg):
        iv = os.urandom(self._block_size_bytes)
        encryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
                                   ciphers.modes.GCM(iv),
                                   self._backend).encryptor()
        _ciphertext = encryptor.update(msg) + encryptor.finalize()
        _ciphertext = encryptor.tag + iv + _ciphertext 
        return _ciphertext
    
    def decrypt(self, ctx):
        tag_size = 16
        tag, iv, ctx = ctx[:tag_size], ctx[tag_size:tag_size+self._block_size_bytes], ctx[tag_size+self._block_size_bytes:]
        decryptor = ciphers.Cipher(ciphers.algorithms.AES(self._key),
                                   ciphers.modes.GCM(iv, tag),
                                   self._backend).decryptor()       
        try:
            msg = decryptor.update(ctx) + decryptor.finalize()
            return msg  # Successful decryption
        except ValueError:
            return False  # Error!!

    

        
if __name__=='__main__':
    test_encr_decr()
