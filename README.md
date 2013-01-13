mac_watcher
===========

A basic python script using scapy to monitor for new mac addresses on
the network. I wrote this as I was tired of arpwatch emailing me 
when a device that had already been detected re-appeared on the
network with a different ip address. 

========
Using: 
1. install the requirements: pip install requirements.txt (or apt-get install python-scapy python-netaddr)
2. run sudo python watcher.py
