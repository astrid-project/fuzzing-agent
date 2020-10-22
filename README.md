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