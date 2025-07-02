
import sys
import time
from scapy.all import send, fragment, IP, ICMP, ARP, sr1


def arp_scan(network):
    arp_request = ARP(pdst=network)
    print(f"ARP Scan for {network}")



def portfiltercheck(target, ports):
    try:
        port_list = [int(p) for p in ports.split(',')]


        ans, unans = sr(
            IP(dst=target)/TCP(dport=port_list, flags="A"),
            timeout=2,
            verbose=0
        )

        print(f"\nPort Filter Report for {target}:")


        for sent, received in ans:
            if received.haslayer(TCP):

                if sent[TCP].dport == received[TCP].sport:
                    print(f"Port {sent[TCP].dport}: UNFILTERED (RST received)")
                else:
                    print(f"Port {sent[TCP].dport}: FILTERED (unexpected response)")
            else:
                print(f"Port {sent[TCP].dport}: FILTERED (non-TCP response)")

        for sent in unans:
            print(f"Port {sent[TCP].dport}: FILTERED (no response)")

    except Exception as e:
        print(f"Port scan error: {e}")
