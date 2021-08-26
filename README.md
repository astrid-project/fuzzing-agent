
# ASTRID Fuzzing Agent

A python service which provides a fuzzer for runtime inspection. The agent primarily uses AFL for coverage guided fuzzing. 
# Usage
```
python3 agent.py --help
usage: agent.py [-h] --fuzzer FUZZER [--input INPUT] [--output OUTPUT]
                [--binary BINARY] [--config CONFIG] --profile PROFILE

Fuzzing agent for ASTRID

optional arguments:
  -h, --help            show this help message and exit
  --fuzzer FUZZER, -f FUZZER
                        Fuzzer to be used for fuzzing (AFL/driller)
  --input INPUT, -i INPUT
                        Testcases directory for input
  --output OUTPUT, -o OUTPUT
                        Working output directory for input
  --binary BINARY, -b BINARY
                        The binary to be used for fuzzing
  --config CONFIG, -c CONFIG
                        Path to the configuration file
  --profile PROFILE, -p PROFILE
                        Execution profile for the agent
```

To have AFL working, the following must be enabled on the host system for functionality
```
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
```

The agent can be run on docker as well. To pull the latest image, 
```
docker pull spockuto/astrid-fuzzing-agent
```

To start the fuzzer, 
```
docker run --network host --name runtime_fuzzer \
			-dit -e BINARY_PATH='./pcap/afldemo' \
			-e KAFKA_ENDPOINT='127.0.0.1:9092' -e FLASK_PORT='5000' \
			-e SERVICE_TIMEOUT='10' -e FUZZING_AGENT_DEBUG='true' \
			spockuto/astrid-fuzzing-agent:latest
		
docker exec -it runtime_fuzzer python3 agent.py
```
### Environment variables
```
BINARY_PATH - path to the binary on the outer container.
KAFKA_ENDPOINT - endpoint for the kafka bus
FLASK_PORT - port to run the API service of the agent on (default 5000)
SERVICE_TIMEOUT - the agent will produce the series of reports every n seconds
FUZZING_AGENT_DEBUG - boolean value for which on debug mode, the agent will print \
											the report to STDOUT instead of kafka
```

### Kafka topics
They can be updated in the **config/agent.cfg**
```
"topics" : {
	"report" : "data_fuzzing_report",
	"comp_report" : "data_fuzzing_comp_report",
	"queue" : "data_fuzzing_queue" ,
	"crash" : "data_fuzzing_crash" ,
	"testcase" : "data_fuzzing_testcase"
}
```

  
 
## Demo environment setup

### Sysbox requirements
* The node's OS must be Ubuntu Focal or Bionic (with a 5.0+ kernel).
* We recommend a minimum of 4 CPUs (e.g., 2 cores with 2 hyperthreads) and 4GB of RAM in each worker node. Though this is not a hard requirement, smaller configurations may slow down Sysbox.
* The Kubernetes cluster should use the CRIO runtime.
### Setting up the k8s cluster
> Assuming kubernetes, kubectl, kubeadm are already installed

  ```
  sudo swapoff -a
systemctl start crio
sudo kubeadm init --pod-network-cidr=10.244.0.0/16 --cri-socket /var/run/crio/crio.sock
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.3.1/aio/deploy/recommended.yaml
 ```

> To setup a admin login for the dashboard
```
git clone https://github.com/astrid-project/fuzzing-agent.git
cd fuzzing-agent
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/clusterole.yaml
kubectl -n kubernetes-dashboard get secret $(kubectl -n kubernetes-dashboard get sa/admin-user -o jsonpath="{.secrets[0].name}") -o go-template="{{.data.token | base64decode}}"
kubectl proxy &
kubectl taint nodes --all node-role.kubernetes.io/master-
kubectl taint nodes --all node.kubernetes.io/disk-pressure-
```
### Installing Sysbox on the cluster
```
kubectl label nodes vm sysbox-install=yes
kubectl apply -f https://raw.githubusercontent.com/nestybox/sysbox/master/sysbox-k8s-manifests/rbac/sysbox-deploy-rbac.yaml
kubectl apply -f https://raw.githubusercontent.com/nestybox/sysbox/master/sysbox-k8s-manifests/daemonset/sysbox-deploy-k8s.yaml
kubectl apply -f https://raw.githubusercontent.com/nestybox/sysbox/master/sysbox-k8s-manifests/runtime-class/sysbox-runtimeclass.yaml
```
### Persistent Volume
We need to setup a Persistent volume for communication between the packetcapture pod and fuzzing-agent pod. They can't run on the same pod since sysbox runtime doesn't allow priveleged pods which is polycubed requirement.
```
mkdir -p /home/sekar/k8spv
kubectl apply -f k8s/pv-storage.yaml
kubectl apply -f k8s/pv-claim.yaml
```

### Bring up the pods
The fuzzing pod will automatically bring up the nested containers. Currently we are using a dummy container as the upper container. But for the demo, it will be replaced by the container who's service needs to be fuzzed. 
```
kubectl apply -f k8s/fuzzing-pod.yaml
kubectl apply -f k8s/packetcapture.yaml
```

### Finding the virtual interface
To attach the virtual interface of the fuzzing pod for packet capture, we need to use a bit of manual networking. This is because Flannel is used to setup the CNI.
However, in the demo environment, pcn-k8s will be used (I guess?) which allows cubes to be attached easily.

To figure out the virtual interface,
```
kubectl exec astrid-fuzzing-demo-pod -- ip link list | awk -F': ' '{print $2}'
```

> lo
eth0@if**27**
docker0
```
ip link list | awk -F': ' '{print $1 $2}'
```
> 25veth542502ba@if3
    link/ether 96:1f:4b:60:02:16 brd ff:ff:ff:ff:ff:ff link-netns 89c697a3-fde4-4449-a670-f06f6fb0d492
26vethdecfae9e@if3
    link/ether 0e:b7:67:39:9d:52 brd ff:ff:ff:ff:ff:ff link-netns c12d4715-5dc2-4b84-b10f-d1f50ca12f5a
27**veth2c0a4ed8**@if3
    link/ether 1a:24:6a:17:d3:04 brd ff:ff:ff:ff:ff:ff link-netns e7b0a157-ae30-4719-be73-0b9dd3335ec0

### Setting up the packetcapture service
```
polycubectl packetcapture add mysniffer capture=bidirectional
polycubectl attach mysniffer veth2c0a4ed8
polycubectl mysniffer set dump="/packetcapture/dump"
polycubectl mysniffer set filter=all
polycubectl detach mysniffer veth2c0a4ed8
```
The service will automatically create pcap in the shared persistent volume, which will periodically be parsed and deleted by the fuzzing agent.
### Running the agent
The agent needs to be executed through the LCP, for which the agent registration and instantiation files are present in **config/** directory
