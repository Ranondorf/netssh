#!/usr/bin/python3

import os



def write_input_files(lines,target_file_name):
    target_file = open(target_file_name, 'w')
    for line in lines:
        target_file.write(line+'\n')

    target_file.close()


# Run this from your working directory
# eg if netssh.py is in netssh/, so not that directory

# print(os.getcwd())

tests = []




tester_dir = os.path.dirname(os.path.realpath(__file__))
commands_file = tester_dir + "/commands.txt" 
devices_file = tester_dir + "/devices.txt"
netssh_file = tester_dir[:-13] + "netssh.py" 
print(netssh_file)


write_input_files(["[linux]","date"],commands_file)





