import os
import getpass
from netmiko import ConnectHandler
import time
import math
import sys
import re
import queue
import threading
from zipfile import ZipFile
from zipfile import ZIP_DEFLATED
from cryptography.fernet import Fernet
import pprint
import shutil
import json
import common.scriptlogger as scriptlogger
import common.mailattachment as mailattachment

class NetworkObject():

    
    def __init__(self, hostname, device_type, group, credential_set):
        self.hostname = hostname
        self.device_type = device_type
        self.group = group
        self.credential_set = credential_set


def pretty_print_hostname(hostname):
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

# ###Introduce debug flag####


def read_config_file(config_file_name):
    # The defaults for the return value are preset.
    parameters = {'commands': 'commands.txt', 'devices': 'devices.txt', 'emailDestination': '', 'output': 'output.txt',
                  'username': '', 'smtpServer': '', 'emailSource': '', 'devModeEnable': '', 'zipEnable': '',
                  'sitePackagePath': '', 'emailSubject': '', 'emailBody': '', 'key': '', 'encryptedPassword': '', 'threadCount': '', 'emailUsername': '', 'emailKey': '', 'emailEncryptedPassword': '', 'smtpPort': ''}
    try:
        config_file = open(config_file_name, 'r')
    except Exception as e:
        print("Configuration file failed to open with this message: %s" % (str(e)))
        return parameters
    for line in config_file:
        split_line = line.split('=')
        # Work in a try block here
        if split_line[0] in parameters:
            split_line[1] = split_line[1].rstrip('\n')
            # Read files for key and encrypted password and convert values to byte values to be used in decryption later
            if (split_line[0] == 'key' or split_line[0] == 'emailKey' or split_line[0] == 'emailEncryptedPassword') and split_line[1] != "''":
                try:
                    read_file = open(split_line[1], 'r')
                    single_line = read_file.readline().rstrip('\n')
                    parameters[split_line[0]] = single_line.encode()
                    read_file.close()
                except Exception as e:
                    print('Failed to open file containing %s with Exception %s' % (split_line[1], str(e)))
            elif split_line[0] == 'emailDestination':
                parameters[split_line[0]] = split_line[1].split(',')
            else:
                parameters[split_line[0]] = split_line[1]
    config_file.close()
    # pprint.pprint(parameters)
    return parameters


def read_command_file(command_file_name):
    commands = {}
    commands_file = open(command_file_name, 'r')
    device_type = ''
    group = "DEFAULT"
    comment = False
    for line in commands_file:
        line = line.rstrip('\n\r\t')
        if not line:
            # Catches blank line
            pass
        elif line[0] == '#':
            # Any lines enclosed by '#' is considered to be in a comment block
            comment = not comment
        elif line[0:2] == '//':
            pass
            # single line comment
        elif line[0] == '<' and line[-1] == '>' and not comment:
            group = line.lstrip('<').rstrip('>')
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
    commands_file.close()
    return commands

def read_device_file(device_file_name):
    devices_file = open(device_file_name, 'r')
    hosts = []
    valid_device_types = ["[cisco_asa]", "[cisco_ios]", "[cisco_xe]", "[cisco_xr]", "[netscaler]", "[cisco_nxos]", "[linux]"]
    comment = False
    group = "DEFAULT"
    credential_set = "cred_default"
    device_type = None
    for line in devices_file:
        hostname = line.rstrip('\n\r\t')
        hostname = hostname.lower()
        if not hostname:
            pass
            # Catches blank line
        elif hostname[0] == '#':
            # Any lines enclosed by '#' is considered to be in a comment block
            comment = not comment
        elif hostname[0:2] == '//':
            pass
            # single line comment
        elif hostname in valid_device_types and not comment:
            device_type = hostname.lstrip('[').rstrip(']')
            # set the device_type as long as the comment flag is false
        elif hostname[0:6] == '<cred_'  and not comment:
            credential_set = hostname.lstrip('<').rstrip('>')
        elif hostname[0] == '<' and hostname[-1] == '>' and not comment:
            group = hostname.lstrip('<').rstrip('>')
            if group == "":
                group = "DEFAULT"
        elif not comment and device_type:
            hosts.append(NetworkObject(hostname, device_type, group, credential_set))
        else:
            pass
            #Presumably comments
    devices_file.close()  
    return hosts
    

def zip_output_file(output_file_name, raw_output_files):
    zipped_output_file_name = output_file_name + '.zip'
    zipped_output_file = ZipFile(zipped_output_file_name, mode="w", compression=ZIP_DEFLATED)
    for raw_output_file in raw_output_files:
        try:    
            zipped_output_file.write(os.path.join(output_file_name, raw_output_file), raw_output_file)
        except Exception as e:
            print("Writing to zipfile failed with error: %s" % (str(e)))
    zipped_output_file.close()
    os.chmod(zipped_output_file_name, 0o666)
    return zipped_output_file_name


class MyThread (threading.Thread):
    def __init__(self, threadID, q, commands):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.q = q
        self.commands = commands

    def run(self):
        print("Starting thread ID:  "+str(self.threadID))
        ssh_command(self.threadID, self.q, self.commands)
        print("Ending thread ID:  "+str(self.threadID))

##########Look at introducing 3 attempts per host#############
def ssh_command(threadID, q, commands):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            host = q.get()
            queueLock.release()
            attempt_number = 1
            max_retries = 3
            process_next_ConnectHandler = False
            outputs = {}
            #A specific catch needs to be made to see if commandSubset fails
            while not process_next_ConnectHandler and attempt_number < max_retries + 1:
                try:
                    if devModeEnable:
                        net_connect = ConnectHandler(device_type=host.device_type, host=host.hostname, username=host.username, password=host.password,
                        secret=host.secret, timeout=10, session_log='logs/netmiko_session_output/'+host.hostname+'.log')
                    else:
                        net_connect = ConnectHandler(device_type=host.device_type, host=host.hostname, username=host.username, password=host.password,
                        secret=host.secret, timeout=10)
                    process_next_ConnectHandler = True
                except Exception as e:
                    print('%s failed on login attempt %s' % (host.hostname, attempt_number))
                    if attempt_number == max_retries:
                        host.result = 'fail'
                        host.error = str(e)
                    attempt_number += 1                            
            try:
                commandSubset = commands[host.group][host.device_type]
            except Exception as e:
                print('Failed assigning a list of commands to host %s, group %s and device type %s : %s' % (host.hostname, host.group, host.device_type, str(e)))
                host.result = 'fail'
                host.error = str(e)
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
                                host.error = str(e)
                                process_next_ConnectHandler = False
                            attempt_number += 1    
                # At this stage the function should start the exit process
            if process_next_ConnectHandler:    
                net_connect.disconnect()
                host.result = 'success'
                host.outputs = outputs

            # This needs to be executed irrespective of an error raised or a success
            listLock.acquire()
            processed_hosts.append(host)
            listLock.release()
            host_status = host.hostname + " processed by thread ID: " + str(threadID)
            for i in range(50 - len(host_status)):
                host_status += '.'
            host_status += host.result + '\n'

            print(host_status)
        else:
            queueLock.release()


def timer(func):
    def wrapper():
        start_time = time.time()
        func()
        print(f'Script run time is {str(time.time() - start_time)} seconds\n')
    return wrapper


@timer
def device_connect():
    # Variable initializations. Only 2 variables are assigned here. Core input variables are set in read_config_file.
    # With the exception of config_file_name which points to the file that sets the configuration, it is advised to not set any other variable from here.
    global exitFlag
    global workQueue
    global queueLock
    global listLock
    global processed_hosts
    global devModeEnable
    command_file_name = ''
    device_file_name = ''
    output_file_name = ''
    config_file_name = 'config.txt'
    devModeEnable = False
    zip_output = ''
    delete_output = False
    threadCount = ''
    username = ''
    filter_string = ''
    mail_to = []
    email_body = ''
    email_subject = ''
    email_username = ''
    email_password = ''
    smtpPort = ''
    processed_hosts = []
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
            elif sys.argv[i] == '-t':
                i += 1
                threadCount = int(sys.argv[i])
            elif sys.argv[i] == '-D':
                devModeEnable = True
            elif sys.argv[i] == '-z':
                zip_output = True
            elif sys.argv[i] == '--delete':
                delete_output = True
            elif sys.argv[i] == '--subject':
                i += 1
                email_subject = sys.argv[i]
            elif sys.argv[i] == '--body':
                i += 1
                email_body = sys.argv[i] + '\n\n'

                    

    configFileOutput = read_config_file(config_file_name)

        
    # configFileOutput will pass defaults (set in the read_config_file() above) if the configuration file is not found
    # The following 5 values are the bare minimum needed to run the program
    if not command_file_name:
        command_file_name = configFileOutput['commands']
    if not device_file_name:
        device_file_name = configFileOutput['devices']
    if not output_file_name:
        output_file_name = configFileOutput['output']
    
    
    try:
        commands = read_command_file(command_file_name)
        hosts = read_device_file(device_file_name)
    except IOError as e:
        print("\nCould not open required input file (make sure there are no typos or if the file exists). IOError with message: %s\n\n" % (str(e)))
        sys.exit()
    
    
    # Sys argv block above checks if username was passed with -u on command line, this takes precedence
    if username:
        password = 'blank'
        confirm_password = 'blank2'
        while password != confirm_password:
            password = getpass.getpass('Login Password: ')
            confirm_password = getpass.getpass('Reconfirm Password: ')
            if password != confirm_password:
                print('Passwords do not match, please try again.')
    # Default val is '' - Test this in the config file by leaving it blank.
    elif configFileOutput['key']:
        fnet_key = Fernet(configFileOutput['key'])


        with open(configFileOutput['encryptedPassword'], 'r') as json_file:
            key_chain = json.load(json_file)

        for key in key_chain.keys():
            key_chain[key]['password'] = fnet_key.decrypt(key_chain[key]['password']).decode()
            key_chain[key]['secret'] = fnet_key.decrypt(key_chain[key]['secret']).decode()

        print(json.dumps(key_chain, indent=4))


    # setup the hosts variable with username and password.
    for host in hosts:
        host.username = key_chain[host.credential_set]['username']
        host.password = key_chain[host.credential_set]['password']
        host.secret = key_chain[host.credential_set]['secret']
        # print(host.__dict__)
    # End of mandatory values
    



    #### FORCED STOP For Development ####
    # print(f'Program terminated')
    # sys.exit()

    
    if not email_subject:
        email_subject = configFileOutput['emailSubject']
    if not email_subject:
        email_subject = 'Output File for script: %s' % os.path.basename(__file__)
    if not email_body:
        email_body = configFileOutput['emailBody']
    if not smtpPort:
        smtpPort = configFileOutput['smtpPort']
    if not email_username:
        email_username = configFileOutput['emailUsername']
    if not threadCount:
        try:
            threadCount = int(configFileOutput['threadCount'])
        except:
            pass

    if not zip_output:
        if configFileOutput['zipEnable'] == 'True':
            zip_output = True
        elif configFileOutput['zipEnable'] == 'False':
            zip_output = False
    emailSource = configFileOutput['emailSource']
    smtpServer = configFileOutput['smtpServer']
    # Check to see if mail passwords are set: ie, secure SMTP server authentication
    if configFileOutput['emailKey'] != '':
        fnet_key = Fernet(configFileOutput['emailKey'])
        email_password = fnet_key.decrypt(configFileOutput['emailEncryptedPassword']).decode()


    mail_to += configFileOutput['emailDestination']

    # Logging configuration to troubleshoot netmiko issues
    if devModeEnable:    
        '''logging.basicConfig(filename='logs/netmiko_debug.log', level=logging.DEBUG)
        logger = logging.getLogger("netmiko")'''


    print("\n\nAttempting connecting to hosts:\n\n")

    # Multithreading block of code
    
    # Set the number of threads if value has not been passed from CLI
    if not threadCount:
        threadCount = len(hosts)
        if threadCount > 100:
            threadCount = 100
    elif threadCount > len(hosts):
        threadCount = len(hosts)
    exitFlag = 0
    queueLock = threading.Lock()
    workQueue = queue.Queue(len(hosts))
    listLock = threading.Lock()
    threads = []
 

    # create actual threads from thread names. MyThread gets the SSH command executed
    for threadID in range(1, threadCount+1):
        thread = MyThread(threadID, workQueue, commands)
        thread.start()
        threads.append(thread)

    queueLock.acquire()

    for host in hosts:
        workQueue.put(host)
    # This clears hosts for the next bit. Might be better to rename this processed_hosts

    queueLock.release()

    while not workQueue.empty():
        pass

    exitFlag = 1
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
        try:
            mailattachment.send_mail(emailSource,mail_to,email_subject,email_body,None,smtpServer,smtpPort,email_username,email_password)
            print("\n\nEmail sent")
        except Exception as e:
            print("\n\nEmail not sent,", "Error message: " + str(e))


    # #################################################
    # Process output if multiple output files required
    # #################################################
    #    When SPLIT is invoked to produce individual output files per device, there are two paths to take. Zipped and unzipped.
    #    If Zip is set:
    #     - then the local dir with the raw files is deleted. But the zip file will remain locally and also emailed.
    #    If zip is not set:
    #     - File will not be emailed, files will not be zipped. Local dir and raw files are kept.


    elif output_file_name == "SPLIT":
        output_dirpath = "output_" + time.strftime("%Y%m%d_%H%M%S")
        print("\n\nSplit option specified for multiple output files. Files will be available in directory, \"%s\": unless -z flag set" % (output_dirpath))
        os.mkdir(output_dirpath, 0o777)
        for processed_host in processed_hosts:
            if processed_host.result == 'success':
                try:
                    output_file = open(os.path.join(output_dirpath, processed_host.hostname + ".txt"),'w')
                    output_file.write(pretty_print_hostname(processed_host.hostname))
                    for command in processed_host.outputs:
                        output_file.write("--------- %s " % command)
                        tail = ''
                        for i in range(57 - len(command)): #Might need to catch here for long commands
                            tail += '-'
                        output_file.write("%s\n%s\n\n" % (tail,processed_host.outputs[command]))
                    output_file.close()
                    passed_list.append(processed_host)
                except IOError as e:
                    print("\nCould not open input file. IOError with message: %s\n\n" % (str(e)))
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
            try:
                mailattachment.send_mail(emailSource,mail_to,email_subject,email_body,[output_file_name],smtpServer,smtpPort,email_username,email_password)
                print("\n\nEmail sent")
            except Exception as e2:
                print("\n\nEmail not sent,", "Error message: " + str(e2))
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
            output_file = open(output_file_name,'w')
        except IOError as e:
            print("\nCould not open output file. IOError with message: %s\n\n" % (str(e)))
            sys.exit()

    ####Main loop writing processed output into the output file. Also creates a list for the "match string" if that is set####
        for processed_host in processed_hosts:
            if processed_host.result == 'success':
                output_file.write(pretty_print_hostname(processed_host.hostname))
            
                for command in processed_host.outputs:
                    output_file.write("--------- %s " % command)
                    tail = ''
                    for i in range(57 - len(command)): #Might need to catch here for long commands
                        tail += '-'
                    output_file.write("%s\n%s\n\n" % (tail, processed_host.outputs[command]))
                passed_list.append(processed_host)
            ####Hosts that failed are appended to a list#####
            elif processed_host.result == 'fail':
                failed_list.append(processed_host)
        output_file.close()
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
    
        # Look at zipping the file if it is too large
        # ADD BLOCK for catching empty output file
        if os.stat(output_file_name).st_size > 5000000 or zip_output is True:
            print("\n\nFile size is greater than 5MB or compress flag set: output file will be compressed")
            try:
                old_output_file_name = output_file_name
                output_file_name = zip_output_file(output_file_name, [output_file_name])
                os.remove(old_output_file_name)
            except Exception as e:
                print("\n\nUnable to compress file")
                print("Error generated is: "+str(e))
                # Unset mail_to prevent email being sent
                mail_to = [] 
            # os.chmod(output_file_name,0o666)

        try:
            mailattachment.send_mail(emailSource, mail_to, email_subject, email_body, [output_file_name], smtpServer, smtpPort, email_username, email_password)
            print("\n\nEmail sent")
        except Exception as e:
            print("\n\nEmail not sent,", "Error message: " + str(e))
            
        if delete_output:
            try:
                os.remove(output_file_name)
            except OSError as e:
                print("Error deleting local zip file. Error: %s - %s." % (e.filename, e.strerror))          


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
        print(str(e))
        os._exit(1)
