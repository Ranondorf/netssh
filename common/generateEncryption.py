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


    current = 'cred_default'
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
        key_chain[key]['secret'] = token.decode()

    
    # print(key_chain)
    creds_filename = "creds.json"
    write_credentials(key_chain, creds_filename)
    
    enc_key_filename = 'enc_key'
    with open(enc_key_filename, 'w') as enc_file:
        enc_file.write(encryption_key.decode())


    print(f'\n\nThe encryption file is {enc_key_filename} and the credentials file is {creds_filename}')


def one_off_password():
    encryption_key = Fernet.generate_key()
    f = Fernet(encryption_key)

    unencrypted_password = get_password()
    token = f.encrypt(unencrypted_password.encode())

    print(f'Encryption key: {encryption_key.decode()}\nEncrypted password: {token.decode()}')


def main():
    welcome = """This is the encrypted password generator for netssh. Using this allows you to stick encrypted passwords in files
    please follow the prompts."""
    print(welcome)
 
    while True:
        try:
            option = int(input("Would you like to create a credential chain (1) or a single password (2)?:"))
        except TypeError as e:
            print(f'Invalid input with error as {str(e)}')
        else:
            if option == 1:
                create_key_chain()
                break
            elif option == 2:
                one_off_password()
                break
            else:
                print("Invalid input. Please enter 1 or 2")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)

