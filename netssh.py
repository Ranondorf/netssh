import os
import getpass
from netmiko import ConnectHandler
import time
import math
import sys
import re
from queue import Queue
from threading import Thread
from threading import Lock
from zipfile import ZipFile
from zipfile import ZIP_DEFLATED
from cryptography.fernet import Fernet
import shutil
import json
# scriptlogger and mailattachment are currently not functioning.
import common.scriptlogger as scriptlogger
import common.mailattachment as mailattachment


class NetworkObject:
    """ Network Object defines an object with all necessary data to form an SSH connection to it. 
    The results of the SSH query are stored in the unassigned varibles with the None values.
    """
    
    def __init__(self, hostname: str, device_type: str, group: str, credential_set: str):
        self.hostname = hostname
        self.device_type = device_type
        self.group = group
        self.credential_set = credential_set
        self.result: str = None
        self.error: str = None
        self.outputs: dict = None


class MyThread (Thread):
    """ Class that defines thread objects. This allows use of multithreading the ssh function.
    """

    def __init__(self, thread_id: str, q: Queue, commands: dict[str, dict[str, list[str]]]):
        super().__init__()
        self.thread_id = thread_id
        self.q = q
        self.commands = commands

    def run(self):
        """ Calls ssh function for a particular thread instance. 'q' contains the network objects
        """

        print("Starting thread ID:  "+str(self.thread_id))
        ssh_command(self.thread_id, self.q, self.commands)
        print("Ending thread ID:  "+str(self.thread_id))


def pretty_print_hostname(hostname: str) -> str:
    """ Pretty prints the hostname in a banner, this is returned as a string.
    """

    length = 80
    hash_line = ''
    for i in range(length):
        hash_line += '#'

    blank_line = '#'
    for i in range(length-2):
        blank_line += ' '
    blank_line += '#'

    host_line = '#'
    for i in range(int(length/2-1-math.ceil(len(hostname)/2))):
        host_line += ' '
    host_line += hostname

    for i in range(length-len(host_line)-1):
        host_line += ' '
    host_line += '#'

    pretty_hostname = '%s\n%s\n%s\n%s\n%s\n\n\n' % (hash_line, blank_line, host_line, blank_line, hash_line)

    return pretty_hostname


def read_config_file(config_file_name:str) -> dict:
    """ This function reads the configuration file. Not all options have to be set.
    """

    parameters = {'commands': 'commands.txt',
                  'devices': 'devices.txt',
                  'output': 'output.txt',
                  'username': '', 
                  'key': '', 
                  'encryptedPassword': '', 
                  'zipEnable': False,
                  'deleteFiles': False,
                  'jsonOutput': False,
                  'sitePackagePath': '',
                  'emailSource': '',
                  'emailDestination': '',
                  'emailSubject': '', 
                  'emailBody': '', 
                  'thread_count': '', 
                  'emailUsername': '', 
                  'emailKey': '', 
                  'emailEncryptedPassword': '', 
                  'smtpPort': '',
                  'useTls' : True,
                  'smtpServer': ''
    }

    try:
        with open(config_file_name, 'r') as config_file:
    
            for line in config_file:
                split_line = line.split('=')
                # Work in a try block here
                if split_line[0] in parameters:
                    split_line[1] = split_line[1].rstrip(' \t\n')
                    # Read files for key and encrypted password and convert values to byte values to be used in decryption later
                    if (split_line[0] == 'key' or split_line[0] == 'emailKey' or split_line[0] == 'emailEncryptedPassword') and split_line[1] != "''":
                        try:
                            with open(split_line[1], 'r') as read_file:
                                single_line = read_file.readline().rstrip('\n')
                                parameters[split_line[0]] = single_line.encode()
                        except Exception as e:
                            print('Failed to open file containing %s with Exception %s. This happened when trying to parse "%s" in the configuration file.' % (split_line[1], e, split_line[0]))
                    elif split_line[0] == 'emailDestination':
                        parameters[split_line[0]] = split_line[1].split(',')
                    elif (split_line[0] == 'zipEnable' or split_line[0] == 'deleteFiles' or split_line[0] == 'useTls'):
                        if split_line[1].lower() == 'false':
                            parameters[split_line[0]] = False
                        elif split_line[1].lower() == 'true':
                            parameters[split_line[0]] = True
                    else:
                        parameters[split_line[0]] = split_line[1]

    except Exception as e:
        print("Configuration file failed to open with this message: %s" % e)
        return parameters

    return parameters


def read_command_file(command_file_name: str) -> dict[str, dict[str, list[str]]]:
    """ This reads the file that contains the commands to be run. This section identifies groups and device types.
    Groups allow the same device type to have different commands run against them.
    """

    commands = {}
    with open(command_file_name, 'r') as commands_file:
        device_type = ''
        group = "DEFAULT"
        comment = False
        for line in commands_file:
            line = line.rstrip('\n\r\t')
            if not line:
                # Catches blank line
                pass
            # Single line comment
            elif line[0:3] == '"""' and line[-3:] == '"""' and len(line) >= 6 or line[0] == '#':
                pass
            # Any lines enclosed by '#' is considered to be in a commeynt block
            elif line[0:3] == '"""' or line[-3:] == '"""':
                comment = not comment
            elif line[0] == '<' and line[-1] == '>' and not comment:
                group = line.lstrip('<').rstrip('>')
                # Shortcut to specify default group, that is you can type <> instead of <DEFAULT>
                if group == "":
                    group = "DEFAULT"
            elif line[0] == '[' and line[-1] == ']' and not comment:
                # Catches line matching device type, eg: ios_xr, netscaler, etc
                device_type = line.lstrip('[').rstrip(']')
            elif re.search('con.* t', line) is not None:
                # Catches conf t and its variants
                pass
            elif device_type == 'netscaler' and re.search('^(unbind|bind|add|rm)', line):
                # Catches netscaler config commands
                pass
            elif not comment:
                # print("Got in here: %s %s" % (group, device_type))
                # Should match actual "commands"
                if group not in commands:
                    commands[group] = {}
                if device_type not in commands[group]:
                    commands[group][device_type] = []
                if not line in commands[group][device_type]:
                    # Do nothing, first time command has been seen
                    pass
                else:
                    # handle duplicate commands by appending a number to the end
                    command_count = 2
                    duplicate_line = line
                    while duplicate_line in commands[group][device_type]:
                        duplicate_line = line + ' (instance #' + str(command_count) + ')'
                        command_count += 1
                    line = duplicate_line
                commands[group][device_type].append(line)
                
    return commands


def read_device_file(device_file_name: str) -> list[NetworkObject]:
    """ Read file with devices. Returns a list of NetworkObjects. NetworkObjects will have their
    hostname, device type, group and credential set assigned.
    """

    with open(device_file_name, 'r') as devices_file:
        hosts = []
        valid_device_types = [
            "[cisco_asa]", 
            "[cisco_ios]", 
            "[cisco_xe]", 
            "[cisco_xr]", 
            "[netscaler]", 
            "[cisco_nxos]", 
            "[linux]"
            ]
        comment = False
        group = "DEFAULT"
        credential_set = "cred_default"
        device_type = None
        for line in devices_file:
            hostname = line.rstrip('\n\r\t')
            hostname = hostname.lower()
            # Used to test if the current line is blank
            if not hostname:
                pass
            # Catches comments that are only a single line
            elif (hostname[0:3] == '"""' and hostname[-3:] == '"""' and len(hostname) >= 6
                or hostname[0] == '#'):
                pass
            # Toggles block comments. An unterminated block will be
            # considered to be run till EOF 
            elif hostname[0:3] == '"""' or hostname[-3:] == '"""':
                comment = not comment
            elif hostname in valid_device_types and not comment:
                device_type = hostname.lstrip('[').rstrip(']')
                # set the device_type as long as the comment flag is false
            elif hostname[0:6] == '<cred_'  and not comment:
                credential_set = hostname.lstrip('<').rstrip('>')
            elif hostname[0] == '<' and hostname[-1] == '>' and not comment:
                group = hostname.lstrip('<').rstrip('>')
                if group == "" or group == "default":  # Two alternative ways to specify
                    group = "DEFAULT"                  # DEFAULT group
            elif not comment and device_type:
                hosts.append(NetworkObject(hostname, device_type, group, credential_set))
            else:
                pass  # This covers block comments

    return hosts
    

def zip_output_file(output_file_name: str, raw_output_files: list[str]) -> str:
    """ This function works in 2 ways. One way is when a list of more than one output files are presented. In this case output_file_name is a directory.
    But if the list is a single output file, then it is expected that output_file_name is an empty string.
    """
    if len(raw_output_files) > 1:
        zipped_output_file_name = output_file_name + '.zip'
    elif len(raw_output_files) == 1:
        zipped_output_file_name = raw_output_files[0] + '.zip'

    with ZipFile(zipped_output_file_name, mode="w", compression=ZIP_DEFLATED) as zipped_output_file:
        for raw_output_file in raw_output_files:
            try:   
                zipped_output_file.write(os.path.join(output_file_name, raw_output_file), raw_output_file)
            except Exception as e:
                print("Writing to zipfile failed with error: %s" % e)
    os.chmod(zipped_output_file_name, 0o666)

    return zipped_output_file_name


def ssh_command(thread_id: str, q: Queue, commands):
    """ SSH function. Takes objects of a queue and runs the appropriate commands against this. This is function is used by multiple threads, hence the queue_lock 
    when accessing the object queue. Likewise when storing results in the list of network objects, a list_lock is utilized.

    This is where the networkObject will have its undefined variables potentially set. The 'result' will always be set. Depending on if the ssh function working 
    or not, either the 'error' or 'outputs' will be set.
    """

    global exit_flag
    global queue_lock
    global list_lock
    global processed_hosts


    while not exit_flag:
        queue_lock.acquire()
        if not q.empty():
            host = q.get()
            queue_lock.release()
            attempt_number = 1
            max_retries = 3
            process_next_ConnectHandler = False
            outputs = {}
            #A specific catch needs to be made to see if commandSubset fails
            while not process_next_ConnectHandler and attempt_number < max_retries + 1:
                try:
                    net_connect = ConnectHandler(device_type=host.device_type, host=host.hostname, username=host.username, password=host.password,
                    secret=host.secret, timeout=10)
                    process_next_ConnectHandler = True
                except Exception as e:
                    print('%s failed on login attempt %s' % (host.hostname, attempt_number))
                    if attempt_number == max_retries:
                        host.result = 'fail'
                        host.error = e
                    attempt_number += 1                            
            try:
                commandSubset = commands[host.group][host.device_type]
            except Exception as e:
                print('Failed assigning a list of commands to host %s, group %s and device type %s : %s' % (host.hostname, host.group, host.device_type, e))
                host.result = 'fail'
                host.error = e
                process_next_ConnectHandler = False

            if process_next_ConnectHandler:
                for command in commandSubset:
                    raw_command = re.sub(r" \(instance #[0-9]*\)", '', command)
                    attempt_number = 1
                    process_next_ConnectHandler = False
                    while not process_next_ConnectHandler and attempt_number < max_retries + 1:
                        try:
                            outputs[command] = net_connect.send_command(command_string=raw_command, read_timeout=90)
                            process_next_ConnectHandler = True
                        except Exception as e:
                            print('%s failed on attempt %s for command , \'%s\'' % (host.hostname, attempt_number, raw_command))
                            if attempt_number == max_retries:
                                host.result = 'fail'
                                host.error = e
                                process_next_ConnectHandler = False
                            attempt_number += 1    
                # At this stage the function should start the exit process
            if process_next_ConnectHandler:    
                net_connect.disconnect()
                host.result = 'success'
                host.outputs = outputs

            # This needs to be executed irrespective of an error raised or a success
            list_lock.acquire()
            processed_hosts.append(host)
            list_lock.release()
            host_status = host.hostname + " processed by thread ID: " + str(thread_id)
            for i in range(50 - len(host_status)):
                host_status += '.'
            host_status += host.result + '\n'

            print(host_status)
        else:
            queue_lock.release()


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


def get_passwords(username: str, cred_name: str) -> dict:
    '''Creates 2 passwords and returns them in a JSON dict format'''

    password = get_password()
    next_password = input('''Is there another password required for higher privileges 
    that is different from the previous password?''')
    if next_password.lower()[0] == 'y':
        secret = get_password()
    else:
        secret = password
    return {cred_name : {"username": username , "password": password, "secret": secret}}
 


def timer(func):
    """ Wrapper function used to time the program run time.
    """

    def wrapper():
        start_time = time.time()
        func()
        print(f'Script run time is {str(time.time() - start_time)} seconds\n')
    return wrapper


@timer
def device_connect():
    """ Effectively the main function. Defines the core code and makes use of all other functions in this file.
    """


    # Variable initializations. Only 2 variables are assigned here. Core input variables are set in read_config_file.
    # With the exception of config_file_name which points to the file that sets the configuration, it is advised to not set any other variable from here.
    
    # Exit Flag for multithreading component
    global exit_flag
    exit_flag = False
    # Lock for accessing queue
    global queue_lock
    queue_lock = Lock()
    # Lock for accessing processed_hosts
    global list_lock
    list_lock = Lock()
    
    # Hosts after they have been processed (via SSH function)
    global processed_hosts
    # processed_hosts = list[NetworkObject]
    processed_hosts = []
    
    # JSON result is only used when the json_output flag is set
    json_result = []

    work_queue = None
    threads = []
    thread_count = None

    command_file_name = None
    device_file_name = None
    output_file_name = None
    # Default config file name, this can be overriden at the CLI
    config_file_name = 'config.txt'
    
    zip_output = None
    delete_output = None
    json_output = None
    username = None
    filter_string = ''
    
    # Email parameters
    mail_to = []
    email_body = None
    email_subject = None
    email_username = None
    email_password = None
    smtp_port = None
    use_tls = None

    # List for hosts read straight from device
    raw_hosts: list[NetworkObject] = []
    # Refined list of hosts to be processed (via SSH function)
    hosts: list[NetworkObject] = []
    failed_list = []
    passed_list = []
    match_set = set()

    # Block for parsing command line args####
    # Parse none default arguments to the program and use those instead of the default file names
    # -o specifies the output file, -u the username, -m to match a string, -s to specify an email target, -c the command file and -d the device file. Order does not matter.
 

    if len(sys.argv) > 1:
        for i in range(1, len(sys.argv)):
            if sys.argv[i] == '-c':
                i += 1
                command_file_name = sys.argv[i]
            elif sys.argv[i] == '-d':
                i += 1
                device_file_name = sys.argv[i]
            elif sys.argv[i] == '-o':
                i += 1
                output_file_name = sys.argv[i]
            elif sys.argv[i] == '--find':
                i += 1
                filter_string = sys.argv[i]
            elif sys.argv[i] == '-u':
                i += 1
                username = sys.argv[i]
            elif sys.argv[i] == '-s':
                i += 1
                mail_to.append(sys.argv[i])
            elif sys.argv[i] == '-f':
                i += 1
                config_file_name = sys.argv[i]
            # Manually set the thread count
            elif sys.argv[i] == '-t':
                i += 1
                thread_count = int(sys.argv[i])
            # Zips the output files. This is False by default, -z turns it on.
            elif sys.argv[i] == '-z':
                zip_output = True
            # Delete the output files. This is False by default, --delete turns it on.
            elif sys.argv[i] == '--delete':
                delete_output = True
            elif sys.argv[i] == '-j':
                json_output = True
            elif sys.argv[i] == '--subject':
                i += 1
                email_subject = sys.argv[i]
            elif sys.argv[i] == '--body':
                i += 1
                email_body = sys.argv[i] + '\n\n'

                    
    config_file_output = read_config_file(config_file_name)

        
    # config_file_output will pass defaults (set in the read_config_file() above) if the configuration file is not found
    # The following 5 values are the bare minimum needed to run the program
    if not command_file_name:
        command_file_name = config_file_output['commands']
    if not device_file_name:
        device_file_name = config_file_output['devices']
    if not output_file_name:
        output_file_name = config_file_output['output']
    
    
    try:
        commands = read_command_file(command_file_name)
        raw_hosts = read_device_file(device_file_name)
    except IOError as e:
        print("\nCould not open required input file (make sure there are no typos or if the file exists). IOError with message: %s\n\n" % e)
        sys.exit()
    
    # Sys argv block above checks if username was passed with -u on command line, this takes precedence
    if username:
        key_chain = get_passwords(username, 'cred_default')
    

    # Second priority is setting the 'key' in the configuration file
    # Default val is '' - Test this in the config file by leaving it blank.
    elif config_file_output['key']:

        try:
            fnet_key = Fernet(config_file_output['key'])
            with open(config_file_output['encryptedPassword'], 'r') as json_file:
                key_chain = json.load(json_file)
        

        except Exception as e:
            print("\nSomething went wrong with encryption key file or key chain file. Please make sure they are properly defined. IOError with message: %s\n\n" % e)
            sys.exit()


        for key in key_chain.keys():
            key_chain[key]['password'] = fnet_key.decrypt(key_chain[key]['password']).decode()
            key_chain[key]['secret'] = fnet_key.decrypt(key_chain[key]['secret']).decode()

    # Check if username is set in config file, this is the 3rd option
    elif config_file_output['username']:
        key_chain = get_passwords(config_file_output['username'], 'cred_default')


    # Prompt for a username is the final and fourth option.
    else:
        username = input("Please enter your username")
        key_chain = get_passwords(username, 'cred_default')


    # setup the hosts variable with username and password.
    # Add in a case to deal with a credential_set not existing.
    for host in raw_hosts:
        try:
            host.username = key_chain[host.credential_set]['username']
            host.password = key_chain[host.credential_set]['password']
            host.secret = key_chain[host.credential_set]['secret']
            hosts.append(host)
        except KeyError as e:
            host.result = 'fail'
            host.error = f'According to device file the credential is {e}, but no such credential exists in the credentials file'
            failed_list.append(host)

    
    # End of mandatory values
    # sys.exit() 

    if not zip_output:
        zip_output = config_file_output['zipEnable']


    if not delete_output:
        delete_output = config_file_output['deleteFiles']

    if not json_output:
        json_output = config_file_output['jsonOutput']


    # Logging configuration to troubleshoot netmiko issues


    if not email_subject:
        email_subject = config_file_output['emailSubject']
    if not email_subject:
        email_subject = 'Output File for script: %s' % os.path.basename(__file__)
    if not email_body:
        email_body = config_file_output['emailBody']
    if not smtp_port:
        smtp_port = config_file_output['smtpPort']
    if not email_username:
        email_username = config_file_output['emailUsername']
    if not use_tls:
        use_tls = config_file_output['useTls']

    
    
    if not thread_count:
        try:
            thread_count = int(config_file_output['thread_count'])
        except:
            pass


    email_source = config_file_output['emailSource']
    smtp_server = config_file_output['smtpServer']
    # Check to see if mail passwords are set: ie, secure SMTP server authentication
    if config_file_output['emailKey'] != '':
        fnet_key = Fernet(config_file_output['emailKey'])
        email_password = fnet_key.decrypt(config_file_output['emailEncryptedPassword']).decode()


    mail_to += config_file_output['emailDestination']


    print("\n\nAttempting connecting to hosts:\n\n")

    # Multithreading block of code
    
    # Set the number of threads if value has not been passed from CLI
    if not thread_count:
        thread_count = len(hosts)
        if thread_count > 100:
            thread_count = 100
    elif thread_count > len(hosts):
        thread_count = len(hosts)
    
    work_queue = Queue(len(hosts))

    # create actual threads from thread names. MyThread gets the SSH command executed
    for thread_id in range(1, thread_count+1):
        thread = MyThread(thread_id, work_queue, commands)
        thread.start()
        threads.append(thread)


    for host in hosts:
        work_queue.put(host)
    # This clears hosts for the next bit. Might be better to rename this processed_hosts

    while not work_queue.empty():
        pass

    exit_flag = True
    for t in threads:
        t.join()

    processed_hosts = sorted(processed_hosts, key=lambda host: host.hostname)

#######################################
########Output processing block########
#######################################

######################################
#Process output if filter flag set
######################################


    if filter_string:
        print("\n\nMatch flag '--find' has been set, no output file will be generated\n")
        # Main loop writing processed output into the output file. Also creates a list for the "match string" if that is set
        # Change the set to a list here to be consistent with the rest of the program
        for processed_host in processed_hosts:
            if processed_host.result == 'success':     
                for command in processed_host.outputs:
                    if filter_string in processed_host.outputs[command]:
                        match_set.add(processed_host.hostname)
                    else:
                        pass
                        # No match
                        # Hosts that failed are appended to a list
            elif processed_host.result == 'fail':
                failed_list.append(processed_host)
        if len(match_set) != 0:
            match_set_string = "\n\nThe filter, \'%s\' was matched in the following hosts:\n\n" % (filter_string)
            for i in range(len(match_set)):
                popped = match_set.pop()
                match_set_string += popped + '\n'
        else:
            match_set_string = "\n\nThe filter, \'%s\' failed to match on any hosts where the commands ran successfully\n\n" % (filter_string)
        email_body += match_set_string

        if len(failed_list) != 0:
            failed_list_string = "\n\nCommands failed on the following devices with error messages:\n\n"
            for host in failed_list:
               failed_list_string += "%s: %s\n" % (host.hostname,host.error)
            email_body += failed_list_string

        mailattachment.send_mail(email_source, mail_to, email_subject, email_body, None, smtp_server, smtp_port, use_tls, email_username, email_password)



    # #################################################
    # Process output if multiple output files required
    # #################################################
    #    When SPLIT is invoked to produce individual output files per device, there are two paths to take. Zipped and unzipped.
    #    If Zip is set:
    #     - then the local dir with the raw files is deleted. But the zip file will remain locally and also emailed.
    #     - to delete the zipped local file as well, you need delete_output = True, that is adding the --delete on the command line or
    #    setting the equivalent in the config file.
    #    If zip is not set:
    #     - File will not be emailed, files will not be zipped. Local dir and raw files are kept.
    #     - Setting the delete flag here has no effect on the files above
    #     - No email can be sent, you must have the zip flag

    elif output_file_name == "SPLIT":
        output_dirpath = "output_" + time.strftime("%Y%m%d_%H%M%S")
        print("\n\nSplit option specified for multiple output files. Files will be available in directory, \"%s\": unless -z flag set" % (output_dirpath))
        os.mkdir(output_dirpath, 0o777)
        for processed_host in processed_hosts:
            if processed_host.result == 'success':
                try:
                    with open(os.path.join(output_dirpath, processed_host.hostname + ".txt"),'w') as output_file:
                        if not json_output:
                            output_file.write(pretty_print_hostname(processed_host.hostname))
                            for command in processed_host.outputs:
                                output_file.write("--------- %s " % command)
                                tail = ''
                                for i in range(57 - len(command)): #Might need to catch here for long commands
                                    tail += '-'
                                output_file.write("%s\n%s\n\n" % (tail,processed_host.outputs[command]))
                        else:
                            json.dump({processed_host.hostname : processed_host.outputs}, output_file, indent=4)

                    passed_list.append(processed_host)
                except IOError as e:
                    print("\nCould not open input file. IOError with message: %s\n\n" % e)
                    sys.exit()
            ####Hosts that failed are appended to a list#####
            elif processed_host.result == 'fail':
                failed_list.append(processed_host)
        if len(passed_list) != 0:
            passed_list_string = "\n\nCommand was successful on the following devices:\n\n"
            for host in passed_list:
               passed_list_string += "%s\n" % host.hostname
            email_body += passed_list_string
        if len(failed_list) != 0:
            failed_list_string = "\n\nCommand failed on the following devices with error messages:\n\n"
            for host in failed_list:
               failed_list_string += "%s: %s\n" % (host.hostname,host.error)
            email_body += failed_list_string         
        ###ADD BLOCK for handling no output files
        
        if zip_output:
            output_file_name = zip_output_file(output_dirpath, os.listdir(output_dirpath))
            try:
                shutil.rmtree(output_dirpath)
            except OSError as e:
                print("Error deleting directory after zipping file. Error: %s - %s." % (e.filename, e.strerror))
            
            mailattachment.send_mail(email_source, mail_to, email_subject, email_body, [output_file_name], smtp_server, smtp_port, use_tls, email_username, email_password)


            # If delete is set, this removes the zip file, leaving no output on the host machine. Use this if you are counting on the email for output data.
            if delete_output:
                try:
                    os.remove(output_file_name)
                except OSError as e2:
                    print("Error deleting local zip file. Error: %s - %s." % (e2.filename, e2.strerror))
                    
##################################################
#Process output if single output file is required
##################################################
    else:
    
        try:     
            with open(output_file_name,'w') as output_file:
            ####Main loop writing processed output into the output file. Also creates a list for the "match string" if that is set####
                for processed_host in processed_hosts:
                    if processed_host.result == 'success':
                        if not json_output:
                            output_file.write(pretty_print_hostname(processed_host.hostname))
                            for command in processed_host.outputs:
                                output_file.write("--------- %s " % command)
                                tail = ''
                                for i in range(57 - len(command)): #Might need to catch here for long commands
                                    tail += '-'
                                output_file.write("%s\n%s\n\n" % (tail, processed_host.outputs[command]))
                        else:
                            json_result.append({ processed_host.hostname : processed_host.outputs})
                        passed_list.append(processed_host)
                    ####Hosts that failed are appended to a list#####
                    elif processed_host.result == 'fail':
                        failed_list.append(processed_host)
                else:
                    if json_output:
                        json.dump(json_result, output_file, indent=4)
        except IOError as e:
            print("\nCould not open output file. IOError with message: %s\n\n" % e)
            sys.exit()
        except Exception as e:
            print("\nSomething else went wrong when attempting to write output file. Exception with message: %s\n\n" % e)
            sys.exit()

        
        if len(passed_list) != 0:
            passed_list_string = "\n\nCommand was successful on the following devices:\n\n"
            for host in passed_list:
               passed_list_string += "%s\n" % (host.hostname)
            email_body += passed_list_string
        if len(failed_list) != 0:
            failed_list_string = "\n\nCommand failed on the following devices with error messages:\n\n"
            for host in failed_list:
               failed_list_string += "%s: %s\n" % (host.hostname,host.error)
            email_body += failed_list_string         
    

        # Zip flag or file over 5MB forces zipping. Once zipped, original file removed.
        if os.stat(output_file_name).st_size > 5000000 or zip_output is True:
            print("\n\nFile size is greater than 5MB or compress flag set: output file will be compressed")
            try:
                old_output_file_name = output_file_name
                output_file_name = zip_output_file('', [output_file_name])
                os.remove(old_output_file_name)
            except Exception as e:
                print("\n\nUnable to compress file")
                print("Error generated is: " + e)
                # Unset mail_to prevent email being sent
                mail_to = [] 
            # os.chmod(output_file_name,0o666)

        
        mailattachment.send_mail(email_source, mail_to, email_subject, email_body, [output_file_name], smtp_server, smtp_port, use_tls,  email_username, email_password)

        

        # Deletes output file (zipped or unzipped). Use this if you are relying on email to get the output out. This is set with --delete on the CLI
        if delete_output:
            try:
                os.remove(output_file_name)
            except OSError as e:
                print("Error deleting local file. Error: %s - %s." % (e.filename, e.strerror))          


    # Generating end of program summary, reusing email body here
    print(email_body)
    
    
    # Try and log script execution stats to log file#
    
    '''try:
        scriptlogger.add_log_entry(start_time,finish_time,os.path.basename(__file__),username)
    except Exception as e:
        print("\n\nPlease note unable to write script stats to log file: %s\n" % str(e))'''


def main():
    device_connect()


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(e)
        os._exit(1)