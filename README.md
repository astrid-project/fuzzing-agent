Fuzzing Agents
==============

* Local agent monitors the Service VF fuzzing.
* Master agent monitors the workers and provides endpoint for management and control actions

Remember
========
* Open socket between master and worker or use message bus?
* initial registration + handshake?
* need to enable some server parameters
* Fast file monitoring suitable for continous inspection (need to check)
* subroutine to enable core pattern


echo core > /proc/sys/kernel/core_pattern


Working with Sysbox
===================
We already have working k8s kluster with Ubuntu 

The node's OS must be Ubuntu Focal or Bionic (with a 5.0+ kernel).

We recommend a minimum of 4 CPUs (e.g., 2 cores with 2 hyperthreads) and 4GB of RAM in each worker node. Though this is not a hard requirement, smaller configurations may slow down Sysbox.
