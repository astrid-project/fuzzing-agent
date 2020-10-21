import os
import os.path as path
import subprocess
import json

def is_installed(package):
    retval = subprocess.call(["which", package])
    if retval == 0:
        return True
    return False

class Fuzzer :
    def __init__(self, fuzzer, testing_dir=None, findings_dir=None, binary=None, profile=None):   
        self.set_fuzzer(fuzzer)
        self.set_testing_dir(testing_dir)
        self.set_findings_dir(findings_dir)
        self.set_binary(binary)
        self.set_config(profile, self.fuzzer)
        self.set_crashes(fuzzer)
        self.set_queue(fuzzer)
    
    def set_fuzzer(self, fuzzer):
        if fuzzer == "AFL" and is_installed("afl-fuzz"):
            self.fuzzer = "afl-fuzz"
        if fuzzer == "driller" and is_installed("shellphuzz"):
            self.fuzzer = "shellphuzz"
    
    def set_crashes(self, fuzzer):
        if fuzzer == "AFL" and is_installed("afl-fuzz"):
            self.crashdir = path.join(self.findings_dir, self.config["crashdir"])
        if fuzzer == "driller" and is_installed("shellphuzz"):
            self.crashdir = path.join(self.findings_dir, path.basename(self.binary), self.config["crashdir"])
    
    def set_queue(self,fuzzer):
        if fuzzer == "AFL" and is_installed("afl-fuzz"):
            self.queuedir = path.join(self.findings_dir, self.config["queuedir"])
        if fuzzer == "driller" and is_installed("shellphuzz"):
            self.queuedir = path.join(self.findings_dir, path.basename(self.binary), self.config["queuedir"])
            
    def set_testing_dir(self, testing_dir):
        if path.exists(path.abspath(testing_dir)):
            self.testing_dir = path.abspath(testing_dir)
        else:
            raise OSError("Input directory doesn't exist")
    
    def set_findings_dir(self, findings_dir):
        if path.exists(path.abspath(findings_dir)):
            self.findings_dir = path.abspath(findings_dir)
        else:
            raise OSError("Output directory doesn't exist") 
    
    def set_binary(self, binary):
        if path.exists(path.abspath(binary)):
            self.binary = path.abspath(binary)
        else:
            raise OSError("Binary doesn't exist") 
    
    def set_config(self, profile, fuzzer):
        if not profile:
            profile = "fuzzing.cfg"
        if path.exists(path.abspath(profile)):
            with open(path.abspath(profile)) as json_file:
                config = json.load(json_file)
                self.config = config[fuzzer]
        else:
            OSError("Configuration file doesn't exist")