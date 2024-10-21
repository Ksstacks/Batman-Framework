#!/usr/bin/python3
import os
import nmap
import socket
from rich.console import Console
import sys
import requests
from colorama import Fore, Style, init
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1

console = Console()

crack = f"""
               \033[34m,---.   ,--.--------.         \033[33m___    ,---.      .-.\033[37m_       
    \033[34m_..---.  .--.'  \ /==/,  -   , -\ \033[33m.-._ .'=.'\ .--.'  \    /==/ \  .-._\033[37m  
  \033[34m.' .'.-. \ \==\-/\ \\==\.-.  - ,-./  \033[33m==/ \|==|  |\==\-/\ \   |==|, \/ /, /\033[37m 
 \033[34m/==/- '=' / /==/-|_\ |`--`\==\- \   \033[33m|==|,|  / - |/==/-|_\ |  |==|-  \|  |\033[37m  
 \033[34m|==|-,   '  \==\,   - \    \==\_ \  \033[33m|==|  \/  , |\==\,   - \ |==| ,  | -|\033[37m  
 \033[34m|==|  .=. \ /==/ -   ,|    |==|- |  \033[33m|==|- ,   _ |/==/ -   ,| |==| -   _ |\033[37m  
 \033[34m/==/- '=' ,/==/-  /\ - \   |==|, |  \033[33m|==| _ /\   /==/-  /\ - \|==|  /\ , |\033[37m  
\033[34m|==|   -   /\==\ _.\=\.-'   /==/ -/  \033[33m/==/  / / , |==\ _.\=\.-'/==/, | |- |\033[37m  
\033[34m`-._`.___,'  `--`           `--`--`  \033[33m`--`./  `--` `--`        `--`./  `--`\033[37m  
  
+\033[34mBatman\033[33m Framework\033[37m
+by \033[31mkstacks\033[37m
+telegram @ksstacks\033[37m    
"""

helph = """
Commands:
- help               | Show help menu
- scan               | Nmap port scanning
- reverse-ip         | Reverse IP and MAC lookup
- ip-lookup          | IP lookup and location
- traceroute         | IP traceroute
- clear              | Clear the screen
- exit               | Exit framework
"""

scanh = """
Usage:
scan [options]
scan -sn             | Scan the network for IP addresses.
scan -s              | Perform a stealth scan on a specified host.
scan -v              | Perform a version scan on a specified host.
scan -f              | Perform a fragment scan on a specified host.
scan -m              | Spoof mac address.
scan -a              | Perform an agressive IP scan.
"""

reverseh = """
Usage:
reverse-ip [options]
reverse-ip -l        | Do a reverse IP lookup displaying the hostname.
"""

iplookuph = """
Usage:
ip-lookup [options]
ip-lookup -l         | Perform an IP lookup to discover the Geo location of the IP address along with a traceroute.
"""

traceroute = """
Usage:
traceroute           | Perform a traceroute (default 30 hops).
"""
helpcmd = ["help"]
scancmd = ["scan", "scan -h", "scan --help", "scan -sn", "scan -s", "scan -v", "scan -f", "scan -m", "scan -a"]
reversecmd = ["reverse-ip", "reverse-ip -h", "reverse-ip --help", "reverse-ip -l"]
iplookupcmd = ["ip-lookup", "ip-lookup -h", "ip-lookup --help", "ip-lookup -l"]
traceroutecmd = ["traceroute -h", "traceroute --help", "traceroute"]

# Replace 'your_ipinfo_api_key' with your actual API key from ipinfo.io
IPINFO_API_KEY = 'API'


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

def clear_screen():
    # Clear the screen based on the user's operating system
    os.system('cls' if os.name == 'nt' else 'clear')

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

def stealth_scan(host, ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, ports=ports, arguments='-sS -Pn')
        if host in nm.all_hosts():
            output = f"\nStealth Scan Results for {host}:\n\n"
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    output += f"Port: {port}, State: {state}\n"
            console.print(output, style="bold underline")
            save_output(output)  # Call save_output when output is defined
        else:
            console.print(f"No results found for {host}", style="bold red")
            output = f"No results found for {host}"
            save_output(output)  # Save a message when no results are found
    except Exception as e:
        console.print(f"An error occurred: {e}", style="bold red")
        output = f"An error occurred: {e}"
        save_output(output)  # Save the error message when an exception occurs

def version_scan(host, ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, ports=ports, arguments='-sV -Pn')
        if host in nm.all_hosts():
            output = f"\nVersion Scan Results for {host}:\n\n"
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    version_info = nm[host][proto][port].get('version', 'N/A')
                    name = nm[host][proto][port].get('name', 'N/A')
                    output += f"Port: {port}, State: {state}, Service: {name}, Version: {version_info}\n"
            console.print(output, style="bold underline")
            save_output(output)  # Call save_output when output is defined
        else:
            console.print(f"No results found for {host}", style="bold red")
            output = f"No results found for {host}"
            save_output(output)  # Save a message when no results are found
    except Exception as e:
        console.print(f"An error occurred: {e}", style="bold red")
        output = f"An error occurred: {e}"
        save_output(output)  # Save the error message when an exception occurs

def frag_scan(host, ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, ports=ports, arguments='-sS -f -Pn')
        if host in nm.all_hosts():
            output = f"Fragment Scan Results for {host}:\n\n"
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    output += f"Port: {port}, State: {state}\n"
            console.print(output, style="bold underline")
            save_output(output)  # Call save_output when output is defined
        else:
            console.print(f"No results found for {host}", style="bold red")
            output = f"No results found for {host}"
            save_output(output)  # Save a message when no results are found
    except Exception as e:
        console.print(f"An error occurred: {e}", style="bold red")
        output = f"An error occurred: {e}"
        save_output(output)  # Save the error message when an exception occurs

def mac_scan(mac, host, vendor, ports):
    nm = nmap.PortScanner()
    try:
        if not mac:
            nm.scan(hosts=host, ports=ports, arguments=f'--spoof-mac {vendor} {host}')
        else:
            nm.scan(hosts=host, ports=ports, arguments=f'--spoof-mac {mac} {host}')
        if host in nm.all_hosts():
            output = f"Mac Spoof Results for {host}:\n\n"
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for prefix in lport:
                    state = nm[mac][host][proto][vendor]['state']
                    output += f"Port: {port}, State: {state}\n"
            console.print(output, style="bold underline")
            save_output(output)  # Call save_output when output is defined
        else:
            console.print(f"No results found for {host}", style="bold red")
            output = f"No results found for {host}"
            save_output(output)  # Save a message when no results are found
    except Exception as e:
        console.print(f"An error occurred: {e}", style="bold red")
        output = f"An error occurred: {e}"
        save_output(output)  # Save the error message when an exception occurs

def agressive_scan(host, ports):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=host, ports=ports, arguments='-A -Pn')
        if host in nm.all_hosts():
            output = f"\nAgressive Scan Results for {host}:\n\n"
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    state = nm[host][proto][port]['state']
                    version_info = nm[host][proto][port].get('version', 'N/A')
                    name = nm[host][proto][port].get('name', 'N/A')
                    output += f"Port: {port}, State: {state}, Service: {name}, Version: {version_info}\n"
            console.print(output, style="bold underline")
            save_output(output)  # Call save_output when output is defined
        else:
            console.print(f"No results found for {host}", style="bold red")
            output = f"No results found for {host}"
            save_output(output)  # Save a message when no results are found
    except Exception as e:
        console.print(f"An error occurred: {e}", style="bold red")
        output = f"An error occurred: {e}"
        save_output(output)  # Save the error message when an exception occurs

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

def traceroute_run(ip, hops):
    output = "Traceroute results:\n"
    ttl = 1
    i = 0
    for i in range(hops):
        i = i + 1
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
        elif command == scancmd[4]:
            host = input("Host: ").strip()
            ports = input("Ports: ").strip()
            if not ports:
                ports = "1-1000"
            if not host:
                console.print("No host specified")
            else:
                console.print("Performing stealth scan...")
                stealth_scan(host, ports)
        elif command == scancmd[5]:
            host = input("Host: ").strip()
            ports = input("Ports: ").strip()
            if not ports:
                ports = "1-1000"
            if not host:
                console.print("No host specified")
            else:
                console.print("Performing version scan...")
                version_scan(host, ports)
        elif command == scancmd[6]:
            host = input("Host: ").strip()
            ports = input("Ports: ").strip()
            if not ports:
                ports = "1-1000"
            if not host:
                console.print("No host specified")
            else:
                console.print("Performing fragment scan...")
                frag_scan(host, ports)
        elif command == scancmd[7]:
            mac = input("Mac (optional): ").strip()
            host = input("Host: ").strip()
            if not mac:
                vendor = input("vendor: ").strip()
            ports = input("Ports: ").strip()
            if not ports:
                ports = "1-1000"
            if not host:
                console.print("No host specified")
            if not mac and not vendor:
                console.print("Mac or vendor must be specified")
            else:
                console.print("Performing Mac spoof...")
                mac_scan(mac, host, vendor, ports)
        elif command == scancmd[8]:
            ip = input("Host: ").strip()
            ports = input("Ports: ").strip()
            if not ports:
                ports = "1-60000"
            if not ip:
                console.print("No host specified")
            else:
                console.print("Performing agressive scan...")
                agressive_scan(ip, ports)
                console.print("Performing traceroute...")
                hops = 31
                traceroute_run(ip, hops)
        elif command in reversecmd[:3]:
            console.print(reverseh)
        elif command == reversecmd[3]:
            ip = input("Host: ").strip()
            if not ports:
                ports = "1-1000"
            if not ip:
                console.print("No IP address specified")
            else:
                console.print("Performing reverse IP lookup...")
                reverse_ip_lookup(ip)
        elif command in iplookupcmd[:3]:
            console.print(iplookuph)
        elif command == iplookupcmd[3]:
            ip = input("Host: ").strip()
            if not ip:
                console.print("No IP address specified")
            else:
                console.print("Performing IP lookup...")
                ip_lookup(ip)
                trace = input("Do you want to perform a traceroute? (y/n)")
                if trace == "y":
                    console.print("Performing traceroute...")
                    hops = 31
                    traceroute_run(ip, hops)
                else:
                    console.print("~$ ")
        elif command == traceroutecmd[:2]:
            console.print(traceroute)
        elif command == traceroutecmd[2]:
            ip = input("Host: ").strip()
            hops = input("Hops(default 30): ").strip()
            if not ip:
                console.print("No IP address specified")
            else:
                console.print("Performing IP traceroute...")
                if not hops:
                    hops = 31
                    hops = int(hops)
                    traceroute_run(ip, hops)
                else:
                    hops = hops + 1
                    hoped = int(hops)
                    traceroute_run(ip, hops)
        elif command == "clear":
            clear_screen()
            print(crack)
        elif command == "exit":
            break
        else:
            console.print("Invalid command, type 'help' for options")

if __name__ == "__main__":
    main()
