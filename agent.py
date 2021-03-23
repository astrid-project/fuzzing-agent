import fuzzer
from flask import Flask
from flask import request, jsonify
from time import sleep
from json import dumps
from kafka import KafkaProducer
import os
import os.path as path
import subprocess
import json
import warnings
import datetime
import signal
import argparse


'''
Fuzzer instance class
'''
fuzz_instance = ""
crash_list = ""
queue_list = ""

'''
    Builds the fuzzing instance class and the deploy string for the subprocess
'''
def deploy_string(fuzz, testing_dir, findings_dir, binary, config, profile) :
    global fuzz_instance
    if not fuzz_instance :
        fuzz_instance = fuzzer.Fuzzer(fuzz,testing_dir,findings_dir,binary,config,profile)

def deploy(fuzzer):
    for each in fuzzer.deploy_string :
        p = subprocess.Popen(each, stdout=subprocess.DEVNULL)

'''
    Creates a new test case file with the given input for the fuzzing
'''

def add_testcase(testcase) :
    global fuzz_instance
    file_name = int(max(os.listdir(fuzz_instance.testing_dir)))
    if not file_name :
        file_name = 0
    file_name = file_name + 1
    f = open(fuzz_instance.testing_dir + "/" + str(file_name), "w")
    f.write(testcase)
    f.close()

'''
    Provides a json formatted output of fuzzing stats of all the fuzzers deployed. Detailed
'''
def stats(fuzzer, dataset):
    stats = []
    for each in fuzzer.deploy_string :
        dir_stat = {}
        slave_dir = each[6]
        path = fuzzer.findings_dir + "/" + slave_dir + "/fuzzer_stats"
        if os.path.isfile(path) :
            for line in open(path, "r"):
                key = line.split(":")[0]
                value = line.split(":")[1]
                key = key.strip().replace(" ", "")
                if key != "command_line" :
                    value = value.strip().replace(" ", "")
                time_list = ["last_crash", "last_path", "last_update", "start_time"]
                if key in time_list :
                    value = datetime.datetime.fromtimestamp(int(value))
                if dataset:
                    if key in dataset:
                        dir_stat[key] = str(value)
                else:
                    dir_stat[key] = str(value)
        stats.append(dir_stat)
    return json.dumps(stats, indent=4, sort_keys=True)


def crashes(fuzzer) :
    global crash_list
    crash = []
    for each in fuzzer.deploy_string :
        thread_crash = []
        slave_dir = each[6]
        path = fuzzer.findings_dir + "/" + slave_dir + "/crashes"
        if os.path.exists(path) :
            crashdir_list = os.listdir(path)
            for each in crashdir_list :
                dir_crash = {}
                id = each.split(",")[0]
                grammar = each[len(id) + 1 : ]
                dir_crash["id"] = id.strip("id:").lstrip("0")
                dir_crash["grammar"] = grammar
                dir_crash["path"] = path + "/" + each
                dir_crash["size"] = os.path.getsize(dir_crash["path"])
                thread_crash.append(dir_crash)
            crash.append(thread_crash)
    crash_list = crash
    return json.dumps(crash, indent=4, sort_keys=True)

def queues(fuzzer) :
    global queue_list
    queues = []
    for each in fuzzer.deploy_string :
        thread_queues = []
        slave_dir = each[6]
        path = fuzzer.findings_dir + "/" + slave_dir + "/queue"
        if os.path.exists(path) :
            crashdir_list = os.listdir(path)
            for each in crashdir_list :
                dir_crash = {}
                id = each.split(",")[0]
                grammar = each[len(id) + 1 : ]
                dir_crash["id"] = id.strip("id:").lstrip("0")
                dir_crash["grammar"] = grammar
                dir_crash["path"] = path + "/" + each
                dir_crash["size"] = os.path.getsize(dir_crash["path"])
                thread_queues.append(dir_crash)
            queues.append(thread_queues)
    queue_list = queues
    return json.dumps(queues, indent=4, sort_keys=True)

def kill(fuzzer):
    stat = json.loads(stats(fuzzer, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGKILL)

def pause(fuzzer):
    stat = json.loads(stats(fuzzer, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGSTOP)

def resume(fuzzer):
    stat = json.loads(stats(fuzzer, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGCONT)

def push_report(ip, topic):
    global fuzz_instance
    producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
    data = stats(fuzz_instance, "")
    producer.send(topic, value=data)

def push_compressed_report(ip, topic):
    dataset = ["last_crash", "last_path", "last_update", "start_time", "execs_per_sec", 
                "unique_crashes", "unique_hangs", "execs_done", "paths_favored", "paths_total"]
    global fuzz_instance
    producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
    data = stats(fuzz_instance, dataset)
    producer.send(topic, value=data)

def push_queue(ip, topic):
    global queue_list, fuzz_instance
    if not queue_list :
        data = queues(fuzz_instance)
    else :
        diff = []
        old_data = queue_list.copy()
        new_data = json.loads(queues(fuzz_instance))
        for id, value in enumerate(old_data):
            diff = [i for i in new_data[id] + value if i not in new_data[id] or i not in value]
        data = json.dumps(diff, indent=4, sort_keys=True)
    print(data)
    #if data :
    #    producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
    #    producer.send(topic, value=data)

def push_crashes(ip, topic):
    global crash_list, fuzz_instance
    if not crash_list :
        data = crashes(fuzz_instance)
    else :
        diff = []
        old_data = crash_list.copy()
        new_data = json.loads(crashes(fuzz_instance))
        for id, value in enumerate(old_data):
            diff = [i for i in new_data[id] + value if i not in new_data[id] or i not in value]
        data = json.dumps(diff, indent=4, sort_keys=True)
    print(data)
    #if data :
    #    producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
    #    producer.send(topic, value=data)

def push_testcase(ip, topic):
    global fuzz_instance
    path = fuzz_instance.testing_dir
    testcases = []
    data = ""
    if os.path.exists(path) :
        filedir_list = os.listdir(path)
        for each in filedir_list :
            dir_testcase = {}
            dir_testcase["name"] = each
            dir_testcase["path"] = path + "/" + each
            dir_testcase["size"] = os.path.getsize(dir_testcase["path"])
            f = open(dir_testcase["path"], "r")
            dir_testcase["content"] = f.read()
            testcases.append(dir_testcase)
        data = json.dumps(testcases, indent=4, sort_keys=True)
    print(data)
    #if data :
    #    producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
    #    producer.send(topic, value=data)


'''
TODO : 
    # How to call these functions ?
    # Interface to call the kafka production 
    # How to integrate the test cases ?
'''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzzing agent for ASTRID")
    parser.add_argument('--fuzzer', '-f', help='Fuzzer to be used for fuzzing (AFL/driller)', required=True)
    parser.add_argument('--input', '-i', help='Testcases directory for input')
    parser.add_argument('--output', '-o', help='Working output directory for input')
    parser.add_argument('--binary', '-b', help='The binary to be used for fuzzing', required=True)
    parser.add_argument('--config', '-c' ,help='Path to the configuration file')
    parser.add_argument('--profile', '-p',help='Execution profile for the agent', required=True)
    parser.add_argument('--ip', help='IP for the Kafka bus', required=True)
    parser.add_argument('-topics','-t', nargs='+', help='Topics for the kafka bus [report, comp_report, queue, crash, testcase]', required=True)
    args = parser.parse_args()
    
    #fuzz = Fuzzer("AFL", "./demos/afl-demo/testcases" , "./demos/afl-demo/findings", "./demos/afl-demo/aflbuild/afldemo",'', '')
    deploy_string(args.fuzzer, args.input, args.output, args.binary, args.config, args.profile)
    deploy(fuzz_instance)
    ip = args.ip
    topic = args.topics
    while True:
        push_report(ip, topic[0])
        push_compressed_report(ip, topic[1])
        push_queue(ip, topic[2])
        push_crashes(ip, topic[3])
        push_testcase(ip, topic[4])
        sleep(10)
