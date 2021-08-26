import os
import os.path as path
import subprocess
import json
import warnings

with open('config/agent.cfg', "r") as config_file:
    config_data = json.load(config_file)

def is_installed(package):
    retval = subprocess.call(["which", package])
    if retval == 0:
        return True
    return False

class Fuzzer :
    def __init__(self, fuzzer, testing_dir=None, findings_dir=None, binary=None, config=None, profile=None):
        self.deploy_string = []
        self.set_fuzzer(fuzzer)
        self.set_testing_dir(testing_dir)
        self.set_findings_dir(findings_dir)
        self.set_binary(binary)
        self.set_config(config, self.fuzzer)
        self.set_crashes(fuzzer)
        self.set_queue(fuzzer)
        self.set_profile(profile, self.config)
        self.build_deploy()
        self.build_profile()
        
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
        safe_testing_dir = config_data["paths"]["testing"]
        if not testing_dir:
            if not path.exists(safe_testing_dir) :
                os.makedirs(safe_testing_dir)
            self.testing_dir = path.abspath(safe_testing_dir)
            f = open(safe_testing_dir + "/1", "w")
            f.write("Hope this works")
            f.close()
        elif path.exists(path.abspath(testing_dir)):
            self.testing_dir = path.abspath(testing_dir)
        else:
            raise OSError("Input directory doesn't exist")
    
    def set_findings_dir(self, findings_dir):
        safe_findings_dir = config_data["paths"]["finding"]
        if not findings_dir :
            if not path.exists(safe_findings_dir) :
                os.makedirs(safe_findings_dir)
            self.findings_dir = path.abspath(safe_findings_dir)
        elif path.exists(path.abspath(findings_dir)):
            self.findings_dir = path.abspath(findings_dir)
        else:
            raise OSError("Output directory doesn't exist") 
    
    def set_binary(self, binary):
        if path.exists(path.abspath(binary)):
            self.binary = path.abspath(binary)
        else:
            raise OSError("Binary doesn't exist") 
    
    def set_config(self, config, fuzzer):
        if not config or config:
            config = config_data["paths"]["config"]
        if path.exists(path.abspath(config)):
            with open(path.abspath(config)) as json_file:
                config_json = json.load(json_file)
                self.config = config_json[fuzzer]
        else:
            OSError("Configuration file doesn't exist")
    
    def set_profile(self, profile, config):
        if not profile or profile not in config["profile"]:
            warnings.warn("Profile not found, setting Normal")
            profile = "normal"
        self.profile = config["profile"][profile]
    
    def set_args(self, args, params=None):
        if args not in self.config["parameters"]:
            raise ValueError("Argument not availabe")
        if (isinstance(self.deploy_string[0] , list)):
            for each in self.deploy_string :
                each.insert(-1, "-" + self.config["parameters"][args])
                if params:
                    each.insert(-1, params)
        else : 
            self.deploy_string.insert(-1, "-" + self.config["parameters"][args])
            if params:
                self.deploy_string.insert(-1, params)
    
    def build_deploy(self) :
        self.deploy_string.append(self.config["execute"])
        self.deploy_string.append(self.binary)
        self.set_args("input", self.testing_dir)
        self.set_args("output", self.findings_dir)
    
    def build_profile(self):
        if self.fuzzer == "afl-fuzz" :
            #Hacky fix
            builder = []
            for core in range(int(self.profile["core"])):
                temp = self.deploy_string.copy()
                if core == 0:
                    temp.insert(-1,"-M")
                    temp.insert(-1,"fuzzer-master")
                else :
                    temp.insert(-1,"-S")
                    temp.insert(-1,"fuzzer" + str(core).zfill(2))
                builder.append(temp)
            self.deploy_string = builder[:]
            self.set_args("memory", self.profile["memory"])
            self.set_args("timeout", self.profile["timeout"])
        if self.fuzzer == "shellphuzz" :
            self.set_args("core", self.profile["core"])
            self.set_args("drill", self.profile["drill"])
            self.set_args("memory", self.profile["memory"])
            self.set_args("timeout", self.profile["timeout"])

#fuzz = Fuzzer("AFL", "./demos/afl-demo/testcases" , "./demos/afl-demo/findings", "./demos/afl-demo/aflbuild/afldemo",'', '')
#fuzz = Fuzzer("AFL", "" , "", "./demos/afl-demo/aflbuild/afldemo",'', '')
#fuzz = Fuzzer("AFL", "" , "", "./demos/afl-demo/aflbuild/afldemo",'', 'relaxed')