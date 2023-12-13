from hashlib import sha3_512, sha512, sha3_256, sha256, sha1, md5
from tkinter import messagebox
import sys

def CalcHashes(bits):
    str = "SHA3-512: " + sha3_512(bits).hexdigest().upper() + "\n\n"
    str += "SHA-512: " + sha512(bits).hexdigest().upper() + "\n\n"
    str += "SHA3-256: " + sha3_256(bits).hexdigest().upper() + "\n\n"
    str += "SHA-256: " + sha256(bits).hexdigest().upper() + "\n\n"
    str += "SHA-1: " + sha1(bits).hexdigest().upper() + "\n\n"
    str += "MD5: " + md5(bits).hexdigest().upper()
    return str
    
path = sys.argv[1]
file = open(path, "rb")
data = file.read()

hashes = CalcHashes(data)
messagebox.showinfo("Hash", hashes)