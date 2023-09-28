import datetime
import time
import random
import os

def add_log_entry(start_time,finish_time,script_name,username):
    start_timestamp = datetime.datetime.fromtimestamp(start_time).strftime('%Y/%m/%d %H:%M:%S')
    end_timestamp = datetime.datetime.fromtimestamp(finish_time).strftime('%Y/%m/%d %H:%M:%S')
    id = random.randint(1,1000000000)
    log_file = open('logs/script_logs.log','a')
    #log_file = open(os.path.dirname(os.path.abspath(__file__)) + '/logs/script_logs.log','a')
    log_file.write('%s \'%s\' has been started by \'%s\' with ID %s\n' % (start_timestamp, script_name, username, id))
    log_file.write('%s \'%s\' has ended. Username \'%s\' with ID %s\n' % (end_timestamp, script_name, username, id))
    log_file.close()
    return

