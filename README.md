# network-scanner

A fast and simple Python tool for local network discovery and TCP port scanning.

## Features

- ARP scan of local or specified IPv4 networks
- Hostname resolution via reverse DNS
- TCP port scanning for specific hosts and port ranges
- Defaults to scanning your local /24 subnet automatically
- Single-file, no dependencies beyond `scapy` (for ARP)
- Works on Windows, Linux, and macOS

## Requirements

- Python 3.7+
- scapy (`pip install scapy`)

## Usage

### ARP scan (default behavior)

```bash
python netdiscover.py
```

Scans your local network (auto-detected subnet) and prints IP, MAC, and hostname.

### ARP scan a specific subnet

```bash
python netdiscover.py -n 10.0.1.0/24
```

### TCP port scan

```bash
python netdiscover.py -p 192.168.1.10:22,80,443
python netdiscover.py -p 192.168.1.10:1-1000
```

### Set a custom timeout (in seconds)

```bash
python netdiscover.py -t 2.0
```

## Example Output

```
ARP-scanning 192.168.1.0/24 …

IP Address       MAC Address        Hostname
------------------------------------------------------------
192.168.1.1      aa:bb:cc:dd:ee:ff  router.local
192.168.1.10     00:11:22:33:44:55  desktop.lan
```

## License

MIT License
