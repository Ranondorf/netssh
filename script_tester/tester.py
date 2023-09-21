#!/usr/bin/python3

import os
import subprocess


class test():
    def __init__(self, commands, devices):
        self.commands = commands
        self.devices = devices




def write_input_files(lines,target_file_name):
    target_file = open(target_file_name, 'w')
    for line in lines:
        target_file.write(line+'\n')

    target_file.close()


# Run this from your working directory
# eg if netssh.py is in netssh/, so not that directory

# print(os.getcwd())


def main():


    test_object_list = []

    test_object_list.append(test(["[linux]","date"],["[linux]","alias1","alias2","alias3"]))
    test_object_list.append(test(["[linux]","date","<monkey>","ls"],["[linux]","alias1","<monkey>","alias2","alias3"]))
    tester_dir = os.path.dirname(os.path.realpath(__file__))
    commands_file = tester_dir + "/commands.txt" 
    devices_file = tester_dir + "/devices.txt"
    output_file = tester_dir + "/output.txt"
    netssh_file = tester_dir[:-13] + "netssh.py"

    for i in range(len(test_object_list)):
        write_input_files(test_object_list[i].commands,commands_file)
        write_input_files(test_object_list[i].devices,devices_file)
        # Check if subprocess run can take in a list
        run_program = subprocess.run([netssh_file,'-c',commands_file,'-d',devices_file,'-o',tester_dir + "/test_result/test_result%s.txt" % i])
        print("The exit code was: %d" % run_program.returncode)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)



