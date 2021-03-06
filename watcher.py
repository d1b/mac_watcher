#!/usr/bin/python
from __future__ import print_function
import argparse
import csv
import json
from multiprocessing import Process
import os
import socket
import time

import netaddr
from netaddr import EUI
from scapy.all import sniff, ARP


def get_hostname(ip):
    try:
        ret = socket.gethostbyaddr(ip)
        if ret:
            return ret[0]
    except socket.error:
        return ""


def persistent_pkt_info(filename, ** kwargs):
    with open(filename, 'a+') as csvfile:
        csv_w = csv.writer(csvfile)
        csv_w.writerow([kwargs['hwsrc'], json.dumps(kwargs)])


def handle_new_pkt(pkt, ** kwargs):
    hwsrc = kwargs['hwsrc']
    src_ip = pkt[ARP].psrc
    hostname = get_hostname(src_ip)
    try:
        org = EUI(hwsrc).oui.registration().org
    except netaddr.core.NotRegisteredError:
        org = 'NA'
    print(src_ip, hwsrc, hostname, org)
    filename = kwargs.get('filename', None)
    if filename:
        cur_time = time.time()
        persistent_pkt_info(filename, hwsrc=hwsrc, src_ip=src_ip,
                            time=cur_time, org=org, hostname=hostname)


class SimpleNetworkMonitor(object):

    def __init__(self, filename, ** kwargs):
        self.filename = filename
        self.csv_file = self._get_csv_file()
        self.load_known_from_persist()

    def _get_csv_file(self):
        return open(self.filename, 'a+')

    def __get_csv_writer(self):
        return csv.writer(self.csv_file)

    def __get_csv_reader(self):
        """ re-open the file so it can be read from the start """
        return csv.reader(self._get_csv_file())

    def load_known_from_persist(self):
        self.known_mac = set([row[0] for row in self.__get_csv_reader()
                              if row])

    def arp_monitor_callback(self, pkt):
        if ARP not in pkt:
            return
        hwsrc = pkt[ARP].hwsrc
        if self.is_mac_known(hwsrc):
            return
        self.known_mac.add(hwsrc)
        p = Process(target=handle_new_pkt, args=(pkt),
                    kwargs={'hwsrc': hwsrc, 'filename': self.filename})
        p.start()

    def is_mac_known(self, hwsrc):
        if hwsrc in self.known_mac:
            return True
        return False

    def show_known(self):
        for row in self.__get_csv_reader():
            if not row:
                continue
            print(row[0], json.loads(row[1]))


def parse_args():
    parser = argparse.ArgumentParser(description="SimpleNetworkMonitor")
    parser.add_argument("-f", "--file", dest="filename", default=os.path.expanduser("~/.simple_arp_watcher"),
                        help="Filename to load and store arp and ip entries into."
                        "\nDefaults to ~/.simple_arp_watcher")
    parser.add_argument("-s", "--show-known-entries", dest="show_known",
                        help="Show known mac address network information.",
                        action="store_true")
    parser.add_argument("-if", "--interface", dest="interface",
                        help="The interface to listen on.", default="eth0")
    parser.add_argument('-mi', "--monitor-ip", dest="ip_monitor",
                        action="store_true", help="Alert on mac & ip address change."
                        "\nCurrently This option does nothing.")
    parser.add_argument("-e", "--email", dest="email",
                        help="Email address to notify on network changes."
                        "\n This is not required and it currently does nothing.")
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    simpNetMon = SimpleNetworkMonitor(args.filename)
    if args.show_known:
        simpNetMon.show_known()
        return
    sniff(prn=simpNetMon.arp_monitor_callback, filter='arp',
          store=0, iface=args.interface)

if __name__ == "__main__":
    main()
