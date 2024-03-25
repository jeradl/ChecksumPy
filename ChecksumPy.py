from hashlib import sha3_512, sha512, sha3_256, sha256, sha1, md5
from zlib import crc32
from tkinter import messagebox
import sys

def CalcHashes(bits):
    strg = "SHA3-512: " + sha3_512(bits).hexdigest().upper() + "\n\n"
    strg += "SHA-512: " + sha512(bits).hexdigest().upper() + "\n\n"
    strg += "SHA3-256: " + sha3_256(bits).hexdigest().upper() + "\n\n"
    strg += "SHA-256: " + sha256(bits).hexdigest().upper() + "\n\n"
    strg += "SHA-1: " + sha1(bits).hexdigest().upper() + "\n\n"
    strg += "MD5: " + md5(bits).hexdigest().upper() + "\n\n"
    strg += "CRC32: " + str(crc32(bits)) 
    return strg
    
path = sys.argv[1]
file = open(path, "rb")
data = file.read()

hashes = CalcHashes(data)
messagebox.showinfo("Hash", hashes)