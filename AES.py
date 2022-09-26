import binascii
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad,unpad
from os import urandom
import os


plaintext = []
result = ""
infile = "in.txt"               #add plaintext
outfile = "out.txt"
s = ""

def readFile(file):
    with open(file,'r') as f:
        for inline in f:
            plaintext.append(inline)
        f.close()

def writeFile(file):
    with open(file,'w') as f:
        f.write(str(binascii.hexlify(result).decode('ascii')))
        f.close()

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = b''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + str.encode(password) + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

class AES_CBC:
    def encrypt(plaintext,key,iv):
        data_bytes = bytes(str(plaintext),'utf-8')
        padded_bytes = pad(data_bytes,AES.block_size)
        AES_obj = AES.new(key,AES.MODE_CBC,iv)
        ciphertext = AES_obj.encrypt(padded_bytes)
        return ciphertext

    def decrypt(ciphertext,key,iv):
        AES_obj = AES.new(key,AES.MODE_CBC,iv)
        raw_bytes=AES_obj.decrypt(ciphertext)
        extracted_bytes = unpad(raw_bytes,AES.block_size)
        return extracted_bytes

class AES_CFB:
    def encrypt(plaintext,key,iv):
        data_bytes = bytes(str(plaintext),'utf-8')
        padded_bytes = pad(data_bytes,AES.block_size)
        AES_obj = AES.new(key,AES.MODE_CFB,iv)
        ciphertext = AES_obj.encrypt(padded_bytes)
        return ciphertext

    def decrypt(ciphertext,key,iv):
        AES_obj = AES.new(key,AES.MODE_CFB,iv)
        raw_bytes=AES_obj.decrypt(ciphertext)
        extracted_bytes = unpad(raw_bytes,AES.block_size)
        return extracted_bytes

class AES_OFB:
    def encrypt(plaintext,key,iv):
        data_bytes = bytes(str(plaintext),'utf-8')
        padded_bytes = pad(data_bytes,AES.block_size)
        AES_obj = AES.new(key,AES.MODE_OFB,iv)
        ciphertext = AES_obj.encrypt(padded_bytes)
        return ciphertext

    def decrypt(ciphertext,key,iv):
        AES_obj = AES.new(key,AES.MODE_OFB,iv)
        raw_bytes=AES_obj.decrypt(ciphertext)
        extracted_bytes = unpad(raw_bytes,AES.block_size)
        return extracted_bytes

class AES_ECB:
    def encrypt(plaintext,key):
        data_bytes = bytes(str(plaintext),'utf-8')
        padded_bytes = pad(data_bytes,AES.block_size)
        AES_obj = AES.new(key,AES.MODE_ECB)
        ciphertext = AES_obj.encrypt(padded_bytes)
        return ciphertext

    def decrypt(ciphertext,key):
        AES_obj = AES.new(key,AES.MODE_ECB)
        raw_bytes=AES_obj.decrypt(ciphertext)
        extracted_bytes = unpad(raw_bytes,AES.block_size)
        return extracted_bytes

class AES_CTR:
    def encrypt(plaintext,key):
        data_bytes = bytes(str(plaintext),'utf-8')
        AES_obj = AES.new(key,AES.MODE_CTR)
        ciphertext = AES_obj.encrypt(data_bytes)
        return ciphertext,AES_obj.nonce

    def decrypt(ciphertext,key,nonce):
        AES_obj = AES.new(key,AES.MODE_CTR,nonce=nonce)
        raw_bytes=AES_obj.decrypt(ciphertext)
        return raw_bytes

if __name__ == '__main__':
    while True:
        choice = int(input("1. AES_CBC\n2. AES_CFB\n3. AES_OFB\n4. AES_ECB\n5. AES_CTR\nYour choice: "))
        if choice >0 and choice <6:
            readFile(infile)
            password = str(input("type your password :"))
            salt = urandom(AES.block_size)
            key_length = 32
            key,iv = derive_key_and_iv(password,salt,key_length,AES.block_size)
            s = "".join(plaintext)       #all plaintext
            # print(f"salt : {salt}")
            # print(f"key : {key}")
            # print(f"iv : {iv}")
            if choice == 1:
                result = AES_CBC.encrypt(s,key,iv)
                print(f'result : {result}')
                writeFile(outfile)
                with open(outfile,'r') as f:
                    a = binascii.unhexlify(f.read())
                source = AES_CBC.decrypt(a,key,iv)
                print(f"decode neh :{source.decode('ascii')}")
                break
            if choice == 2:
                result = AES_CFB.encrypt(s,key,iv)
                print(f'result : {result}')
                writeFile(outfile)
                with open(outfile,'r') as f:
                    a = binascii.unhexlify(f.read())
                source = AES_CFB.decrypt(a,key,iv)
                print(f"decode neh :{source.decode('ascii')}")
                break
            if choice == 3:
                result = AES_OFB.encrypt(s,key,iv)
                print(f'result : {result}')
                writeFile(outfile)
                with open(outfile,'r') as f:
                    a = binascii.unhexlify(f.read())
                source = AES_OFB.decrypt(a,key,iv)
                print(f"decode neh :{source.decode('ascii')}")
                break
            if choice == 4:
                result = AES_ECB.encrypt(s,key)
                print(f'result : {result}')
                writeFile(outfile)
                with open(outfile,'r') as f:
                    a = binascii.unhexlify(f.read())
                source = AES_ECB.decrypt(a,key)
                print(f"decode neh :{source.decode('ascii')}")
                break
            if choice == 5:
                result,nonce = AES_CTR.encrypt(s,key)
                print(f'result : {result}')
                writeFile(outfile)
                with open(outfile,'r') as f:
                    a = binascii.unhexlify(f.read())
                source = AES_CTR.decrypt(a,key,nonce)
                print(f"decode neh :{source.decode('ascii')}")
                break
            else:
                print("Run again")
                exit()
        else:
            print("Out of range")
