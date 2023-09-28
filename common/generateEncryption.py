#!/usr/bin/python3
from cryptography.fernet import Fernet
import os
import getpass
import sys

def main():
    password = getpass.getpass('Enter the password: ')
    confirm_password = getpass.getpass('Please reconfirm password: ')
    if password != confirm_password:
        print('\nPasswords do not match: program exit')
        sys.exit()
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt(password.encode())
    print('Randomly generated key: %s' % (key.decode()))
    print('Encrypted password:     %s' % (token.decode()))
if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)

