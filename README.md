# P4-TLS
This project parses TLS SNI extension using P4 language on Tofino architecture. This repository contains:

    - P4/: P4 code that runs on Tofino. The program compiles on BF SDE 9.6.0.  
        Use "make compile" to compile the P4 program.
        Use "make run" to the run the P4 program.

    - CP/: Control plane programs. These programs contain python scripts that interact with the P4 data plane via bfrt_python. You will also find scripts that install rules in the data plane. For example, a rule that matches on the hostname "facebook.com".
        # CP.py generates the CRC 32 hashes of the domains to be blocked.
        # setup.py configures the ports of the P4 PDP switch basid on the ucli_cmds file. 
        Use "make start_control_plane" to lunch P4_runtime using setup.py script.