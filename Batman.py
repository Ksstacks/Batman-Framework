#!/usr/bin/python3
import os
import nmap
import socket
from rich.console import Console
import sys
import requests
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

console = Console()

crack = """                   
               ,---.   ,--.--------.        ___    ,---.      .-._         
    _..---.  .--.'  \ /==/,  -   , -\.-._ .'=.'\ .--.'  \    /==/ \  .-._  
  .' .'.-. \ \==\-/\ \\==\.-.  - ,-./==/ \|==|  |\==\-/\ \   |==|, \/ /, / 
 /==/- '=' / /==/-|_\ |`--`\==\- \  |==|,|  / - |/==/-|_\ |  |==|-  \|  |  
 |==|-,   '  \==\,   - \    \==\_ \ |==|  \/  , |\==\,   - \ |==| ,  | -|  
 |==|  .=. \ /==/ -   ,|    |==|- | |==|- ,   _ |/==/ -   ,| |==| -   _ |  
 /==/- '=' ,/==/-  /\ - \   |==|, | |==| _ /\   /==/-  /\ - \|==|  /\ , |  
|==|   -   /\==\ _.\=\.-'   /==/ -/ /==/  / / , |==\ _.\=\.-'/==/, | |- |  
`-._`.___,'  `--`           `--`--` `--`./  `--` `--`        `--`./  `--`  
  
+Batman Framework
+by kstacks
+telegram @ksstacks             
"""

helph = """
Commands:
- scan|nmap port scanning
- reverse-ip|reverse IP and MAC lookup
- ip-lookup|IP lookup and location
- exit|exit framework
"""

scanh = """
Usage:
scan [options]
scan -sn | scan the network for IP adresses.
"""

reverseh = """
Usage:
reverse-ip [options]
reverse-ip -l | Do a reverse IP lookup displaying the hostname.
"""

iplookuph = """
Usage:
ip-lookup [options]
ip-lookup -l | Do a IP lookup to discover the Geo location of the ip address along with a traceroute.
"""

helpcmd = ["help"]
scancmd = ["scan", "scan -h", "scan --help", "scan -sn"]
reversecmd = ["reverse-ip", "reverse-ip -h", "reverse-ip --help", "reverse-ip -l"]
iplookupcmd = ["ip-lookup", "ip-lookup -h", "ip-lookup --help", "ip-lookup -l"]

# Replace 'your_ipinfo_api_key' with your actual API key from ipinfo.io
IPINFO_API_KEY = '0b1aed3506a288'

def check_sudo():
    if os.geteuid() != 0:
        console.print("This script must be run as root. Please use sudo.", style="bold red")
        sys.exit(1)

def get_local_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.error:
        console.print("IP not found")
        sys.exit()

def print_help():
    console.print(helph)

def save_output(output):
    while True:
        save = input("Do you want to save the output? (y/n): ").strip().lower()
        if save == 'y':
            filename = input("Enter the filename to save the output: ").strip()
            with open(filename, 'w') as f:
                f.write(output)
            console.print(f"Output saved to {filename}", style="bold green")
            break
        elif save == 'n':
            console.print("Output not saved", style="bold red")
            break
        else:
            console.print("Invalid input, please enter 'y' or 'n'.")

def scan_network(host):
    nm = nmap.PortScanner()
    nm.scan(hosts=host + '/24', arguments='-sn -Pn')
    hosts_list = [(x, nm[x]['status']['state'], nm[x].hostname(), nm[x]['addresses'].get('mac', 'N/A')) for x in nm.all_hosts()]
    
    output = "\nScan Results:\n\n"
    for host, status, hostname, mac in hosts_list:
        if status == 'up':
            host_display = f'{host} ({hostname})' if hostname else host
            output += f'Host: {host_display}, MAC: {mac}, Status: {status}\n'
        else:
            host_display = f'{host} ({hostname})' if hostname else host
            output += f'Host: {host_display}, MAC: {mac}, Status: {status}\n'

    console.print(output, style="bold underline")
    save_output(output)

def reverse_ip_lookup(ip):
    try:
        hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
        output = f"IP: {ip}\nHostname: {hostname}\nAliases: {', '.join(aliaslist)}\nIP Addresses: {', '.join(ipaddrlist)}"
        console.print(output)
        save_output(output)
    except socket.herror as e:
        console.print(f"Error: {e}")

def ip_lookup(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}')
        data = response.json()
        loc = data.get('loc', 'N/A')
        latitude, longitude = loc.split(',') if loc != 'N/A' else ('N/A', 'N/A')
        
        output = (f"IP: {data.get('ip')}\nHostname: {data.get('hostname')}\nCity: {data.get('city')}\nRegion: {data.get('region')}\nCountry: {data.get('country')}\n"
                  f"Location: {loc}\nLatitude: {latitude}\nLongitude: {longitude}\nOrg: {data.get('org')}\nCarrier: {data.get('carrier', 'N/A')}")
        
        console.print(output)
        save_output(output)
    except Exception as e:
        console.print(f"Error: {e}")

def traceroute(ip):
    output = "Traceroute results:\n"
    ttl = 1
    while True:
        pkt = IP(dst=ip, ttl=ttl) / ICMP()
        reply = sr1(pkt, verbose=0, timeout=1)
        if reply is None:
            output += f"{ttl}\t*\n"
        else:
            output += f"{ttl}\t{reply.src}\n"
            if reply.src == ip:
                break
        ttl += 1
    
    console.print(output, style="bold underline")
    save_output(output)

def main():
    check_sudo()
    print(crack)
    while True:
        command = input("~$ ").strip()
        if command in helpcmd:
            print_help()
        elif command in scancmd[:3]:
            console.print(scanh)
        elif command == scancmd[3]:
            host = input("Host: ").strip()
            if not host:
                console.print("No host specified")
            else:
                console.print("Scanning...")
                scan_network(host)
        elif command in reversecmd[:3]:
            console.print(reverseh)
        elif command == reversecmd[3]:
            ip = input("IP Address: ").strip()
            if not ip:
                console.print("No IP address specified")
            else:
                console.print("Performing reverse IP lookup...")
                reverse_ip_lookup(ip)
        elif command in iplookupcmd[:3]:
            console.print(iplookuph)
        elif command == iplookupcmd[3]:
            ip = input("IP Address: ").strip()
            if not ip:
                console.print("No IP address specified")
            else:
                console.print("Performing IP lookup...")
                ip_lookup(ip)
                console.print("Performing traceroute...")
                traceroute(ip)
        elif command == "exit":
            break
        else:
            console.print("Invalid command, type 'help' for options")

if __name__ == "__main__":
    main()
