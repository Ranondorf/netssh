#!/usr/bin/python3
import sys
import os
import getpass
from netmiko import ConnectHandler
#from netmiko.ssh_exception import NetMikoTimeoutException, \
#    NetMikoAuthenticationException
from paramiko.ssh_exception import SSHException
import time
import math
import sys
import re
import queue
import threading
import paramiko
import logging
from zipfile import ZipFile
from zipfile import ZIP_DEFLATED
import mailattachment


class network_object(object):
    hostname = ""
    device_type = ""
    
    def __init__(self, hostname, device_type):
        self.hostname = hostname
        self.device_type = device_type

def pretty_print_hostname (hostname):

    length = 80
    hashline = ''
    for i in range(length):
        hashline+=('#')

    blankline = '#'
    for i in range(length-2):
        blankline+=(' ')
    blankline+= '#'

    hostline = '#'
    for i in range(int(length/2-1-math.ceil(len(hostname)/2))):
        hostline+=(' ')
    hostline+=hostname

    for i in range(length-len(hostline)-1):
        hostline+=(' ')
    hostline += '#'

    pretty_hostname = '%s\n%s\n%s\n%s\n%s\n\n\n' % (hashline,blankline,hostline,blankline,hashline)

    return pretty_hostname

####Introduce debug flag####
def read_config_file(config_file_name):
    parameters = {'commands':'commands.txt','devices':'devices.txt','emailDestination':'','output':'output.txt',\
            'username':'','smtpServer':'','emailSource':'','absPath':'','devModeEnable':'','zipEnable':'','sitePackagePath':'','emailSubject':'','emailBody':'','password':''}
    config_file=open(config_file_name,'r')
    for line in config_file:
        rg = re.split(r'(=)',line)
        if rg[0] in parameters:
            parameters[rg[0]]=rg[2].rstrip('\n')
    config_file.close()
    return parameters

def read_command_file(command_file_name):
    commands = {}
    commands_file = open(command_file_name,'r')
    key = ''
    comment = False
    for line in commands_file:
        line = line.rstrip('\n\r\t')
        if not line:
        #Catches blank line    
            pass
        elif line[0] == '#':
            #Any lines enclosed by '#' is considered to be in a comment block
            comment = not comment
        elif line[0:2] == '//':
            pass
            #single line comment        
        elif line[0] == '[' and line[-1] == ']':
        #Catches line matching device type, eg ios_xr, netscaler, etc
            key = line.lstrip('[').rstrip(']')
            commands[key] = []
        elif re.search('con.*\st',line) is not None:
        #Catches conf t and its variants 
           pass
        elif key == 'netscaler' and re.search('^(unbind|bind|add|rm)',line):
        #Catches netscaler config commands
           pass
        elif comment == False:
        #Should match actual "commands"    
            if not line in commands[key]:
                #Do nothing, first time command has been seen
                pass
            else:
                #handle duplicate commands by appending a number to the end
                command_count = 2
                duplicate_line = line
                while duplicate_line in commands[key]:
                    duplicate_line = line + ' (instance #' + str(command_count) + ')'
                    command_count += 1
                line = duplicate_line
            commands[key].append(line)
    commands_file.close()
    return commands

def read_device_file(device_file_name):
    devices_file = open(device_file_name,'r')
    hosts = []
    valid_device_types = ["[cisco_asa]","[cisco_ios]","[cisco_xe]","[cisco_xr]","[aruba_os]","[netscaler]","[cisco_nxos]"]
    comment = False
    for line in devices_file:
        hostname=line.rstrip('\n\r\t')
        hostname=hostname.lower()
        if not hostname:
            pass
            #Catches blank line
        elif hostname[0] == '#':
            #Any lines enclosed by '#' is considered to be in a comment block
            comment = not comment
        elif hostname[0:2] == '//':
            pass
            #single line comment
        elif hostname in valid_device_types and not comment:
            device_type = hostname.lstrip('[').rstrip(']')
            #set the device_type as long as the comment flag is false            
        elif not comment:
            hosts.append(network_object(hostname,device_type))
    devices_file.close()  
    return hosts
    
#def create_output_file(output_file_name):

def zipOutputFile (output_file_name,raw_output_files,path=''):
    zipped_output_file = output_file_name + '.zip'
    zippedOutputFile = ZipFile(zipped_output_file,mode="w",compression=ZIP_DEFLATED)
    for raw_output_file in raw_output_files:
        try:    
            zippedOutputFile.write(path + raw_output_file,raw_output_file)
        except Exception as e:
            print("Writing to zipfile failed with error: %s" % (str(e)))
    zippedOutputFile.close()
    os.chmod(zipped_output_file,0o666)
    return zipped_output_file


class myThread (threading.Thread):
   def __init__(self, threadID,q,username,password,commands):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.username = username
      self.q = q
      self.password = password
      self.commands = commands
   def run(self):
      print("Starting thread ID:  "+str(self.threadID))
      ssh_command(self.threadID,self.q,self.username,self.password,self.commands)
      print("Ending thread ID:  "+str(self.threadID))

##########Look at introducing 3 attempts per host#############
def ssh_command (threadID,q,username,password,commands):
    while not exitFlag:
        queueLock.acquire()
        if not workQueue.empty():
            host = q.get()
            queueLock.release()
            attempt_number = 1
            max_retries = 3
            process_next_ConnectHandler = False
            #A specific catch needs to be made to see if commandSubset fails
            while not process_next_ConnectHandler and attempt_number < max_retries + 1:
                try:
                    outputs = {}
                    commandSubset = commands[host.device_type]
                    
                    if devModeEnable:
                        net_connect = ConnectHandler(device_type=host.device_type, host=host.hostname, username=username, password=password,\
                        secret = password, timeout=10, session_log='logs/netmiko_session_output/'+host.hostname+'.log')
                    else:
                        net_connect = ConnectHandler(device_type=host.device_type, host=host.hostname, username=username, password=password,\
                        secret = password, timeout=10)
                    process_next_ConnectHandler = True
                except Exception as e:
                    print('%s failed on login attempt %s' % (host.hostname, attempt_number))
                    if attempt_number == max_retries:
                        host.result = 'fail'
                        host.error = str(e)
                    attempt_number += 1                            
            if process_next_ConnectHandler:             
                for command in commandSubset:
                    raw_command = re.sub("\s\(instance\s#[0-9]*\)", '', command)
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
                #####At this stage the function should start the exit process                                
            if process_next_ConnectHandler:    
                net_connect.disconnect()
                host.result = 'success'
                host.outputs = outputs

            ##This needs to be executed irrespective of an error raised or a success
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

def main ():
    #Script start time
    start_time = time.time()


    #Variable initializations. Only 2 variables are assigned here. Core input variables are set in read_config_file.
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
    delete_dir = False
    threadCount = ''
    username = ''
    filter_string = ''
    mail_to = []
    email_body = ''
    email_subject = ''
    abs_path = ''
    processed_hosts = []
    failed_list = []
    passed_list = []
    match_set = set()

    ####Block for parsing command line args####
    #Parse none default arguements to the program and use those instead of the default file names
    # -o specifes the output file, -u the username, -m to match a string, -s to specify an email target, -c the command file and -d the device file. Order does not matter.
 

    if len(sys.argv) > 1:
        for i in range(1,len(sys.argv)):
            if sys.argv[i] == '-c':
                i+=1
                command_file_name = sys.argv[i]
            elif sys.argv[i] == '-d':
                i+=1
                device_file_name = sys.argv[i]
            elif sys.argv[i] == '-o':
                i+=1
                output_file_name = sys.argv[i]
            elif sys.argv[i] == '--find':
                i+=1
                filter_string = sys.argv[i]
            elif sys.argv[i] == '-u':
                i+=1
                username = sys.argv[i]
            elif sys.argv[i] == '-s':
                i+=1
                mail_to.append(sys.argv[i])
            elif sys.argv[i] == '-f':
                i+=1
                config_file_name = sys.argv[i]
            elif sys.argv[i] == '-t':
                i+=1
                threadCount = int(sys.argv[i])
            elif sys.argv[i] == '-D':
                devModeEnable = True
            elif sys.argv[i] == '-z':
                zip_output = True
            elif sys.argv[i] == '--delete':
                delete_dir = True
            elif sys.argv[i] == '--subject':
                i+=1
                email_subject = sys.argv[i]
            elif sys.argv[i] == '--body':
                i+=1
                email_body = sys.argv[i] + '\n\n'

                    
    ####Remove try block####
    try:
        configFileOutput = read_config_file(config_file_name)
    except Exception as e:
        print("Configuration file failed to open with this message: %s" % (str(e)))
        
    #configFileOutput will pass defaults if the configuration file is not found
    if not command_file_name:
       command_file_name = configFileOutput['commands']
    if not device_file_name:
       device_file_name = configFileOutput['devices']
    if not output_file_name:
       output_file_name = configFileOutput['output']
    if not email_subject:
        email_subject = configFileOutput['emailSubject']
    if not email_subject:
        email_subject = 'Output File for script: %s' % os.path.basename(__file__)
    if not email_body:
        email_body = configFileOutput['emailBody']
    if not username:
        username = configFileOutput['username']
    if not username:
        username = input('Username: ')
    if not zip_output:
        if configFileOutput['zipEnable'] == 'True':
            zip_output = True
        elif configFileOutput['zipEnable'] == 'False':
            zip_output = False
    emailSource = configFileOutput['emailSource']
    smtpServer = configFileOutput['smtpServer']
    if configFileOutput['password'] != '':
        adpassword = configFileOutput['password']
    else:
        adpassword = getpass.getpass('Login Password: ')
        confirmpassword = getpass.getpass('Reconfirm Password: ')
        if adpassword != confirmpassword:
            print('\nPasswords do not match')
            sys.exit()
    ####These values can only be passed from the configuration file
    mail_to.append(configFileOutput['emailDestination'])
    abs_path = configFileOutput['absPath']
    ####Import common utilities, local logging and email####

    try:
        import scriptlogger
        #import mailattachment
    except Exception as e:
        print("\nCould not import mail and script stat files. Program will continue without these options.")


    try:
        commands = read_command_file(command_file_name)
        hosts = read_device_file(device_file_name)         
        #output_file = open(output_file_name,'w')
    except IOError as e:
        print("\nCould not open input file. IOError with message: %s\n\n" % (str(e)))
        sys.exit()

    ####Read SSH credentials####
    #Basic check to see if a user can enter the same password twice. Doesn't guard against 2 identical wrong inputs (which will lock your AD account when run on multiple devices).
    '''adpassword = getpass.getpass('Login Password: ')
    confirmpassword = getpass.getpass('Reconfirm Password: ')

    if adpassword != confirmpassword:
        print("\nPasswords do not match")
        sys.exit()'''

    ####Logging configuration to troubleshoot netmiko issues####
    if devModeEnable:    
        '''logging.basicConfig(filename='logs/netmiko_debug.log', level=logging.DEBUG)
        logger = logging.getLogger("netmiko")'''
        paramiko.util.log_to_file("logs/filename.log")


    print("\n\nAttempting connecting to hosts:\n\n")

    ####Multithreading block of code####
    
    ##Set the number of threads if value has not been passed from CLI
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
 

#create actual threads from thread names. myThread gets the SSH command executed
    for threadID in range(1,threadCount+1):
        thread = myThread(threadID, workQueue, username, adpassword, commands)
        thread.start()
        threads.append(thread)

    queueLock.acquire()

    for host in hosts:
        workQueue.put(host)
    #This clears hosts for the next bit. Might be better to rename this processed_hosts

    queueLock.release()

    while not workQueue.empty():
        pass

    exitFlag = 1
    for t in threads:
        t.join()


#######################################
########Output processing block########
#######################################

######################################
#Process output if filter flag set
######################################
    if filter_string:
        print("\n\nMatch flag '--find' has been set, no output file will be generated\n")
        ####Main loop writing processed output into the output file. Also creates a list for the "match string" if that is set####
        for processed_host in processed_hosts:
            if processed_host.result == 'success':     
                for command in processed_host.outputs:               
                    if filter_string in processed_host.outputs[command]:
                        match_set.add(processed_host.hostname)
                    else:
                        pass
                        #No match
                        ####Hosts that failed are appended to a list#####
            elif processed_host.result == 'fail':
                failed_list.append(processed_host)
        if len(match_set) != 0:
            match_set_string = "\n\nThe filter, \'%s\' was matched in the following hosts:\n\n" % (filter_string)
            for i in range(len(match_set)):
                popped = match_set.pop()
                match_set_string += popped + '\n'
            email_body += match_set_string

        if len(failed_list) != 0:
            failed_list_string = "\n\nCommand failed on the following devices with error messages:\n\n"
            for host in failed_list:
               failed_list_string += "%s: %s\n" % (host.hostname,host.error)
            email_body += failed_list_string

        try:
            mailattachment.send_mail(emailSource,mail_to,email_subject,email_body,None,smtpServer)
            print("\n\nEmail sent")
        except Exception as e:
            print("\n\nEmail not sent")
            print(str(e))


##################################################
#Process output if multiple output files required
##################################################

    elif output_file_name == "SPLIT":
        output_dirpath = abs_path + "output_" + time.strftime("%Y%m%d_%H%M%S") + "/"
        print("\n\nSplit option specified for multiple output files. Files will be available in directory, \"%s\"" % (output_dirpath))
        os.mkdir(output_dirpath, 0o777)
        for processed_host in processed_hosts:
            if processed_host.result == 'success':
                try:
                    output_file = open(output_dirpath + processed_host.hostname + ".txt",'w')
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
               passed_list_string += "%s\n" % (host.hostname)
            email_body += passed_list_string
        if len(failed_list) != 0:
            failed_list_string = "\n\nCommand failed on the following devices with error messages:\n\n"
            for host in failed_list:
               failed_list_string += "%s: %s\n" % (host.hostname,host.error)
            email_body += failed_list_string         
        if delete_dir:
            pass
            #os.<delete directory#
        
        if zip_output:
            output_file_name = zipOutputFile(output_dirpath[:-1],os.listdir(output_dirpath),output_dirpath)
            try:
                mailattachment.send_mail(emailSource,mail_to,email_subject,email_body,[output_file_name],smtpServer)
                print("\n\nEmail sent")
            except Exception as e:
                print("\n\nEmail not sent")
                print(str(e))
                
        
         
         
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
                    output_file.write("%s\n%s\n\n" % (tail,processed_host.outputs[command]))
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
    
        #Look at zipping the file if it is too large    
        if os.stat(output_file_name).st_size > 5000000 or zip_output is True:
            print("\n\nFile size is greater than 5MB or compress flag set: output file will be compressed")
            try:
                old_output_file_name = output_file_name
                output_file_name = zipOutputFile(output_file_name,[output_file_name])
                os.remove(old_output_file_name)
            except Exception as e:
                print("\n\nUnable to compress file")
                print("Error generated is: "+str(e))
                #Unset mail_to prevent email being sent
                mail_to = [] 
        #os.chmod(output_file_name,0o666)

        try:
            mailattachment.send_mail(emailSource,mail_to,email_subject,email_body,[output_file_name],smtpServer)
            print("\n\nEmail sent")
        except Exception as e:
            print("\n\nEmail not sent")
            print(str(e))


    #Generating end of program summary, reusing email body here
    print(email_body)
    

    finish_time = time.time()
    print("\n\nScript execution time is %s seconds\n" % str(finish_time - start_time))
    
    #Try and log script execution stats to log file#
    try:
        scriptlogger.add_log_entry(start_time,finish_time,os.path.basename(__file__),username)
    except Exception as e:
        print("\n\nUnable to write script stats to log file\n")
        print(str(e))
    





if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)
