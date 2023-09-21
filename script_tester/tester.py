#!/usr/bin/python3

import os
import subprocess
import filecmp

class test():
    def __init__(self, commands, devices):
        self.commands = commands
        self.devices = devices




def write_input_files(lines,target_file_name):
    target_file = open(target_file_name, 'w')
    for line in lines:
        target_file.write(line+'\n')

    target_file.close()



def compare_text_files(results_file,expected_results_file):
    return filecmp.cmp(results_file,expected_results_file,shallow=False)


# Run this from your working directory
# eg if netssh.py is in netssh/, so not that directory

# print(os.getcwd())


def main():


    test_object_list = []
    # Basic test of a single device type
    test_object_list.append(test(["[linux]","echo \"This is a test command\""],["[linux]","alias1","alias2","alias3"]))
    # Single device type, introducing a grouping
    test_object_list.append(test(["[linux]","echo \"This is a test command\"","<monkey>","echo \"This is another command\""],["[linux]","alias1","<monkey>","alias2","alias3"]))
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

    for i in range(len(test_object_list)):
        comp_result = compare_text_files(tester_dir + "/test_result/test_result%s.txt" % i,tester_dir + "/test_expected_result/test_result%s.txt" % i)
        if comp_result:
            print(f'Test {i}, passed')
        else:
            print(f'Test {i}, failed')

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(str(e))
        os._exit(1)



