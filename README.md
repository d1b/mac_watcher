## mac_watcher
This is a basic python script using scapy to monitor for new mac addresses on
a network. I wrote this as I was tired of arpwatch emailing me 
when a device that had already been detected re-appeared on the
network with a different ip address. 

### Requirements
This script requires scapy and netaddr in order to work.  
These dependencies can be installed by running the following command  

	pip install -r requirements.txt  
or on debian/ubuntu by the following command  

	apt-get install python-scapy python-netaddr  

## Usage 
After installing the required dependencies launch the watcher through

	sudo python watcher.py

To output the stored mac address information run

	sudo python watcher.py -s

It is possible to run the script as a non-root user on linux through 'setcap' (granting CAP_NET_RAW and CAP_NET_ADMIN).
