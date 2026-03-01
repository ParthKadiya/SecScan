import argparse
import socket
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from modules import http_scanner

common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
    }

def scan_port(target,port,timeout=0.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target,port))
    sock.close()
    return result == 0

def scan_common_ports(target):
    open_ports=[]
    print("[*] Scanning common ports (Threaded) ...")

    def check(port, service):
        if scan_port(target,port):
            print(f"[+] {port}/tcp OPEN ({service})")
            open_ports.append((port,service))

    with ThreadPoolExecutor(max_workers=50) as executor:
        for port,service in common_ports.items():
            executor.submit(check, port, service)  

    return open_ports 

def scan_custome_range_ports(target, port_range):
    start, end = map(int, port_range.split("-"))
    open_ports = []
    print(f"[*] Scanning Ports {start}-{end}...")

    def check(port):
        if scan_port(target, port):
            print(f"[+] {port}/tcp OPEN")
            open_ports.append(port)

    with ThreadPoolExecutor(max_workers=200) as executor:
        for port in range(start, end+1):
            executor.submit(check, port)
        
    return open_ports

def main():
    parser=argparse.ArgumentParser(
        description="SecScan - Security Scanning CLI Tool"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target domain ot IP Address for scanning"
    )

    parser.add_argument(
        "--scan",
        choices=["port","web","full"],
        default="full",
        help="Scan Type: port, web, full"
    )

    parser.add_argument(
        "--ports",
        help="Define Custome ports range. Example: 1-1000"
    )

    args = parser.parse_args()

    target = args.target
    scan_type = args.scan

    print(f"[+] Target: {target}")
    print(f"[+] Scan type: {scan_type}")

    if scan_type=="port":
        if args.ports:
            open_ports = scan_custome_range_ports(target, args.ports)
        else:
            open_ports = scan_common_ports(target)
    elif scan_type=="web":
        web_output = http_scanner.web_scan(target)
    else:
        open_ports = scan_common_ports(target)
        web_output = http_scanner.web_scan(target)

if __name__=="__main__":
    main()