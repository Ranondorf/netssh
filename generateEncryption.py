#!/usr/bin/python3
from cryptography.fernet import Fernet
import os

def main():
    password = input('Enter the password: ')
    key = Fernet.generate_key()
    f = Fernet(key)
    token = f.encrypt('dfdfdf')
    #print(f)
    #print(token)

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)

