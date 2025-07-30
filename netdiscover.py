#!/usr/bin/env python3
"""
py_nettool.py

- Default: ARP-scan your local /24 LAN, resolve hostnames.
- --ports host:port[,port…] → simple TCP connect scan.
"""

import argparse
import ipaddress
import socket
import struct
import sys

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
except ImportError:
    print("Error: scapy is required (pip install scapy)")
    sys.exit(1)

def get_local_network() -> str:
    # Find your primary IPv4 + netmask via a UDP socket trick → assume /24
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return f"{ip.rsplit('.',1)[0]}.0/24"

def arp_scan(network: str, timeout: float = 2.0):
    nw = ipaddress.ip_network(network, strict=False)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=str(nw))
    answers, _ = srp(pkt, timeout=timeout)
    return [(resp.psrc, resp.hwsrc) for _, resp in answers]

def resolve_name(ip: str, timeout: float = 1.0) -> str:
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(None)

def tcp_scan(host: str, ports: list, timeout: float = 1.0):
    open_ports = []
    for p in ports:
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((host, p))
        except:
            pass
        else:
            open_ports.append(p)
            sock.close()
    return open_ports

def parse_ports(spec: str):
    host, rest = spec.split(":",1)
    ports = []
    for part in rest.split(","):
        if "-" in part:
            a,b = part.split("-",1)
            ports += range(int(a), int(b)+1)
        else:
            ports.append(int(part))
    return host, sorted(set(ports))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("-n", "--network", help="CIDR (default=auto)", default=None)
    p.add_argument("-t", "--timeout", type=float, default=1.0)
    p.add_argument("-p", "--ports",
                   help="TCP scan: host:port or host:port1,port2 or host:1000-1010")
    args = p.parse_args()

    if args.ports:
        host, ports = parse_ports(args.ports)
        print(f"Scanning {host} ports {ports} …")
        open_p = tcp_scan(host, ports, timeout=args.timeout)
        print("Open ports:", open_p or "None")
        return

    net = args.network or get_local_network()
    print(f"ARP-scanning {net} …\n")
    print(f"{'IP Address':<15} {'MAC Address':<18} {'Hostname'}")
    print("-" * 60)

    for ip, mac in arp_scan(net, timeout=args.timeout):
        name = resolve_name(ip, timeout=args.timeout)
        print(f"{ip:<15} {mac:<18} {name}")


if __name__ == "__main__":
    main()
