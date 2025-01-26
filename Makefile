
compile:
	cd /root/bf-sde-9.6.0/ ; sh . ../tools/./set_sde.bash
	~/tools/p4_build.sh --with-p4c=bf-p4c /home/TLS_parser/P4/basic.p4

run:
	pkill switchd 2> /dev/null ; cd /root/bf-sde-9.6.0/ ;./run_switchd.sh -p basic

start_control_plane:
	/root/bf-sde-9.6.0/./run_bfshell.sh --no-status-srv -i -b /home/TLS_parser/CP/setup.py
