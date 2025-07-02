import sys
import time
from scapy.all import send, fragment, IP, ICMP, ARP, sr1
from netmon import portfiltercheck, arp_scan
from pod import pod
from help import help

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: <script> [pod|asc|pfc] [target] [options]")
        print("  pod: ping of death - requires [count]")
        print("  asc: ARP scan")
        print("  pfc: port filter check - requires [ports]")
        sys.exit(1)

    command = sys.argv[1]
    target = sys.argv[2]

    if command == "pod":
        count = int(sys.argv[3]) if len(sys.argv) > 3 else 100
        pod(target, count)
    elif command in ["asc", "ARPScan"]:
        arp_scan(target)
    elif command in ["pfc", "portfil"]:
        if len(sys.argv) < 4:
            print("Error: Specify ports as comma-separated list (e.g., '80,443,666')")
            sys.exit(1)
        ports = sys.argv[3]
        portfiltercheck(target, ports)
    elif command == 'help':
        help()
    else:
        print("Invalid command")




