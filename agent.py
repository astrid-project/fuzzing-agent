from parser import parse_instance
import kafka
import fuzzer
import parser
import flask
from flask import Flask
from flask import request, jsonify
from kafka import KafkaProducer
import os
import sys
import json
import os.path as path
import subprocess
import warnings
import datetime
import signal
from distutils import util
import argparse
from time import sleep
from json import dumps
from multiprocessing import Process, Value

'''
Fuzzer instance class
'''
fuzz_instance = ""
crash_list = ""
queue_list = ""

with open("config/agent.cfg" , "r") as infile :
     config_data = json.load(infile)

app = flask.Flask(__name__)
app.config["DEBUG"] = bool(util.strtobool(os.getenv('FUZZING_AGENT_DEBUG', 'True')))

process_state = Value('b', True)

def output_data(data, topic) :
    if bool(util.strtobool(os.getenv('FUZZING_AGENT_DEBUG', 'True'))) :
        print(data)
    else :
        ip = os.getenv('KAFKA_ENDPOINT', '127.0.0.1:9092')
        producer = KafkaProducer(bootstrap_servers=ip,value_serializer=lambda x: dumps(x).encode('utf-8'))
        producer.send(topic, value=data)

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

@app.route('/add_testcase', methods=['GET'])
def add_testcase() :
    testcase = request.args.get('file')
    global fuzz_instance
    file_name = max([int(each) for each in os.listdir(fuzz_instance.testing_dir)])
    if not file_name :
        file_name = 0
    file_name = file_name + 1
    f = open(fuzz_instance.testing_dir + "/" + str(file_name), "w")
    f.write(testcase)
    f.close()
    return "Testcase added."

@app.route('/kill', methods=['GET'])
def kill():
    global fuzz_instance
    global p
    stat = json.loads(stats(fuzz_instance, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGKILL)
    p.terminate()
    os.kill(os.getpid(), signal.SIGTERM)
    return "Fuzzer killed."

@app.route('/pause', methods=['GET'])
def pause():
    global fuzz_instance
    global process_state
    stat = json.loads(stats(fuzz_instance, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGSTOP)
    process_state.value = False
    return "Fuzzer paused."

@app.route('/resume', methods=['GET'])
def resume():
    global fuzz_instance
    global process_state
    stat = json.loads(stats(fuzz_instance, ""))
    for each in stat :
        pid = int(each["fuzzer_pid"])
        os.kill(pid, signal.SIGCONT)
    process_state.value = True
    return "Fuzzer resumed."

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

def push_report():
    global fuzz_instance
    data = stats(fuzz_instance, "")
    output_data(data, config_data["topics"]["report"])

def push_compressed_report():
    dataset = ["last_crash", "last_path", "last_update", "start_time", "execs_per_sec", 
                "unique_crashes", "unique_hangs", "execs_done", "paths_favored", "paths_total"]
    global fuzz_instance
    data = stats(fuzz_instance, dataset)
    output_data(data, config_data["topics"]["comp_report"])

def push_queue():
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
    if data :
        output_data(data, config_data["topics"]["queue"])
    
def push_crashes():
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
    if data :
        output_data(data, config_data["topics"]["crash"])

def push_testcase():
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
    if data :
        output_data(data, config_data["topics"]["testcase"])

def push_global() :
    global process_state
    global fuzz_instance
    while True:
        if process_state.value :
            parse_instance(fuzz_instance)
            push_report()
            push_compressed_report()
            push_queue()
            push_crashes()
            push_testcase()
            sleep(int(os.getenv('SERVICE_TIMEOUT', 10)))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzzing agent for ASTRID")
    parser.add_argument('--fuzzer', '-f', help='Fuzzer to be used for fuzzing (AFL/driller)', required=True)
    parser.add_argument('--input', '-i', help='Testcases directory for input')
    parser.add_argument('--output', '-o', help='Working output directory for input')
    parser.add_argument('--binary', '-b', help='The binary to be used for fuzzing')
    parser.add_argument('--config', '-c' ,help='Path to the configuration file')
    parser.add_argument('--profile', '-p',help='Execution profile for the agent', required=True)
    args = parser.parse_args()
    
    if not args.binary :
        args.binary = os.getenv('BINARY_PATH')

    deploy_string(args.fuzzer, args.input, args.output, args.binary, args.config, args.profile)
    print(fuzz_instance.deploy_string)
    deploy(fuzz_instance)

    p = Process(target = push_global)
    p.start()
    port = os.getenv('FLASK_PORT', 5000)
    app.run(host="localhost", port=port, use_reloader=False)
    p.join()

