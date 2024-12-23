#!/usr/bin/python3


from cryptography.fernet import Fernet
import os
import getpass
import sys
import json


def create_entry() -> tuple[str, str, str]:
    '''Create a login, multipass combo'''
    login_name = input("Please enter a login name:")
    password = get_password()
    next_password = input('''Is there another password required for higher privileges 
    that is different from the previous password?''')
    if next_password.lower()[0] == 'y':
        enable_password = get_password()
    else:
        enable_password = password
    return login_name, password, enable_password

def get_password() -> str:
    '''Basic function for getting a password'''
    while True:
        password = getpass.getpass('Enter the password: ')
        confirm_password = getpass.getpass('Please reconfirm password: ')
        if password != confirm_password:
            print('\nPasswords do not match: please re-enter the passwords')
        else:
            break


    return password


def write_credentials(key_chain: dict, file_name: str):
    

    with open(file_name, 'w') as cred_file:
        json.dump(key_chain, cred_file, indent=4)


def create_key_chain():
    welcome = """This is the encrypted password generator for netssh. Using this allows you to stick encrypted passwords in files
    please follow the prompts."""
    print(welcome)



    current = 'default_creds'
    num_cred = input('How many unique credentials would you like to create?')
    print(f'{num_cred} entries will be created:')
    key_chain = {current : {} }    
    

    for i in range(1, int(num_cred)):
        current = f"cred_{i}"
        key_chain[current]={}


    # print(*key_chain.keys(), sep='\n')

    encryption_key = Fernet.generate_key()
    f = Fernet(encryption_key)


    for key in key_chain.keys():


        print("Entering details for:", key)
        credentials = create_entry()
        key_chain[key]['username'] = credentials[0]
        token = f.encrypt(credentials[1].encode())
        key_chain[key]['password'] = token.decode()
        token = f.encrypt(credentials[2].encode())
        key_chain[key]['enable_pass'] = token.decode()

    
    print(key_chain)
    
    write_credentials(key_chain, "creds.json")

    print("got here")
    with open('encrypt.txt', 'w') as enc_file:
        enc_file.write(encryption_key.decode())




def main():
    welcome = """This is the encrypted password generator for netssh. Using this allows you to stick encrypted passwords in files
    please follow the prompts."""
 
    create_key_chain()

    '''
    print('Randomly generated key: %s' % (key.decode()))
    print('Encrypted password:     %s' % (token.decode()))
    print(key)'''

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)

