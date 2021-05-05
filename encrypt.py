#!/usr/bin/python3

from cryptography.fernet import Fernet
from getpass import getpass

import os

key = Fernet.generate_key()
f = open("./cipher.key","w")
f.write(key.decode("utf-8"))
f.close()
cipher_suite = Fernet(key)
password = getpass("Enter Password : ").encode("utf-8")
ciphered_text = cipher_suite.encrypt(password).decode("utf-8")
print(ciphered_text)
