#!/usr/bin/env python3
import os
import sys
import subprocess
from time import sleep

# Color codes for terminal
RED = "\033[1;31m"
GREEN = "\033[1;32m"
YELLOW = "\033[1;33m"
BLUE = "\033[1;34m"
MAGENTA = "\033[1;35m"
CYAN = "\033[1;36m"
RESET = "\033[0m"

def clear_screen():
    os.system('clear')

def print_banner():
    clear_screen()
    banner = f"""{RED}
  ___ _   _ _   _ _____ _____ ____ _____  _    ____ _____ _____ ____  
 |_ _| | | | | | |_   _| ____/ ___|_   _|/ \  / ___|_   _| ____|  _ \ 
  | || | | | |_| | | | |  _| \___ \ | | / _ \ \___ \ | | |  _| | | | |
  | || |_| |  _  | | | | |___ ___) || |/ ___ \ ___) || | | |___| |_| |
 |___|\___/|_| |_| |_| |_____|____/ |_/_/   \_\____/ |_| |_____|____/ 
                                                                      
    {RESET}{GREEN}Ethical Hacker & Bug Hunter Toolkit{RESET}
    {YELLOW}Created for Ubuntu Penetration Testing{RESET}
    """
    print(banner)

def install_tool(tool_name):
    print(f"\n{YELLOW}[*] Installing {tool_name} if not already installed...{RESET}")
    if tool_name == "nmap":
        os.system('sudo apt-get install nmap -y')
    elif tool_name == "nikto":
        os.system('sudo apt-get install nikto -y')
    elif tool_name == "sqlmap":
        os.system('sudo apt-get install sqlmap -y')
    elif tool_name == "metasploit":
        os.system('sudo apt-get install metasploit-framework -y')
    elif tool_name == "dirb":
        os.system('sudo apt-get install dirb -y')
    elif tool_name == "hydra":
        os.system('sudo apt-get install hydra -y')
    elif tool_name == "wpscan":
        os.system('sudo apt-get install wpscan -y')
    elif tool_name == "gobuster":
        os.system('sudo apt-get install gobuster -y')
    elif tool_name == "john":
        os.system('sudo apt-get install john -y')
    elif tool_name == "aircrack-ng":
        os.system('sudo apt-get install aircrack-ng -y')

def run_nmap():
    print(f"\n{CYAN}[*] Nmap - Network Mapper{RESET}")
    target = input("Enter target IP or domain: ")
    print(f"\n{YELLOW}Common Nmap commands:{RESET}")
    print("1. Quick scan")
    print("2. Full scan (all ports)")
    print("3. Service version detection")
    print("4. OS detection")
    print("5. Aggressive scan")
    print("6. Vulnerability scan")
    choice = input("\nChoose scan type (1-6): ")
    
    if choice == "1":
        cmd = f"nmap {target}"
    elif choice == "2":
        cmd = f"nmap -p- {target}"
    elif choice == "3":
        cmd = f"nmap -sV {target}"
    elif choice == "4":
        cmd = f"nmap -O {target}"
    elif choice == "5":
        cmd = f"nmap -A {target}"
    elif choice == "6":
        cmd = f"nmap --script vuln {target}"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_nikto():
    print(f"\n{CYAN}[*] Nikto - Web Server Scanner{RESET}")
    target = input("Enter target URL (e.g., http://example.com): ")
    cmd = f"nikto -h {target}"
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_sqlmap():
    print(f"\n{CYAN}[*] sqlmap - SQL Injection Tool{RESET}")
    target = input("Enter target URL with parameter (e.g., http://example.com/page.php?id=1): ")
    print(f"\n{YELLOW}Common sqlmap commands:{RESET}")
    print("1. Test for SQLi vulnerabilities")
    print("2. Dump database names")
    print("3. Dump tables from specific database")
    print("4. Dump data from specific table")
    print("5. Get OS shell")
    choice = input("\nChoose action (1-5): ")
    
    if choice == "1":
        cmd = f"sqlmap -u {target} --batch"
    elif choice == "2":
        cmd = f"sqlmap -u {target} --dbs --batch"
    elif choice == "3":
        db = input("Enter database name: ")
        cmd = f"sqlmap -u {target} -D {db} --tables --batch"
    elif choice == "4":
        db = input("Enter database name: ")
        table = input("Enter table name: ")
        cmd = f"sqlmap -u {target} -D {db} -T {table} --dump --batch"
    elif choice == "5":
        cmd = f"sqlmap -u {target} --os-shell --batch"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_dirb():
    print(f"\n{CYAN}[*] DIRB - Web Content Scanner{RESET}")
    target = input("Enter target URL (e.g., http://example.com): ")
    wordlist = input("Enter path to wordlist (or press Enter for default): ")
    if not wordlist:
        wordlist = "/usr/share/dirb/wordlists/common.txt"
    cmd = f"dirb {target} {wordlist}"
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_hydra():
    print(f"\n{CYAN}[*] Hydra - Password Cracker{RESET}")
    print(f"\n{YELLOW}Common Hydra commands:{RESET}")
    print("1. HTTP form login")
    print("2. SSH login")
    print("3. FTP login")
    print("4. RDP login")
    choice = input("\nChoose attack type (1-4): ")
    
    if choice == "1":
        target = input("Enter target URL (e.g., http://example.com/login): ")
        username = input("Enter username or path to userlist: ")
        password = input("Enter password or path to passlist: ")
        form_params = input("Enter form parameters (e.g., 'user=^USER^&pass=^PASS^'): ")
        cmd = f"hydra -l {username} -p {password} {target} http-post-form \"{form_params}:Invalid credentials\""
    elif choice == "2":
        target = input("Enter target IP or hostname: ")
        username = input("Enter username or path to userlist: ")
        password = input("Enter password or path to passlist: ")
        cmd = f"hydra -l {username} -p {password} {target} ssh"
    elif choice == "3":
        target = input("Enter target IP or hostname: ")
        username = input("Enter username or path to userlist: ")
        password = input("Enter password or path to passlist: ")
        cmd = f"hydra -l {username} -p {password} {target} ftp"
    elif choice == "4":
        target = input("Enter target IP or hostname: ")
        username = input("Enter username or path to userlist: ")
        password = input("Enter password or path to passlist: ")
        cmd = f"hydra -l {username} -p {password} {target} rdp"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_wpscan():
    print(f"\n{CYAN}[*] WPScan - WordPress Vulnerability Scanner{RESET}")
    target = input("Enter WordPress site URL (e.g., http://example.com): ")
    print(f"\n{YELLOW}Common WPScan commands:{RESET}")
    print("1. Basic scan")
    print("2. Enumerate users")
    print("3. Enumerate plugins")
    print("4. Enumerate themes")
    print("5. Aggressive scan")
    choice = input("\nChoose scan type (1-5): ")
    
    if choice == "1":
        cmd = f"wpscan --url {target}"
    elif choice == "2":
        cmd = f"wpscan --url {target} --enumerate u"
    elif choice == "3":
        cmd = f"wpscan --url {target} --enumerate p"
    elif choice == "4":
        cmd = f"wpscan --url {target} --enumerate t"
    elif choice == "5":
        cmd = f"wpscan --url {target} --enumerate --plugins-detection aggressive"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_gobuster():
    print(f"\n{CYAN}[*] Gobuster - Directory/File/DNS Bruteforcer{RESET}")
    target = input("Enter target URL or domain: ")
    print(f"\n{YELLOW}Common Gobuster commands:{RESET}")
    print("1. Directory bruteforce")
    print("2. DNS subdomain bruteforce")
    choice = input("\nChoose mode (1-2): ")
    
    if choice == "1":
        wordlist = input("Enter path to wordlist (or press Enter for default): ")
        if not wordlist:
            wordlist = "/usr/share/wordlists/dirb/common.txt"
        cmd = f"gobuster dir -u {target} -w {wordlist}"
    elif choice == "2":
        wordlist = input("Enter path to wordlist (or press Enter for default): ")
        if not wordlist:
            wordlist = "/usr/share/wordlists/dns/subdomains-top1million-5000.txt"
        cmd = f"gobuster dns -d {target} -w {wordlist}"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_metasploit():
    print(f"\n{CYAN}[*] Metasploit Framework{RESET}")
    print(f"\n{YELLOW}Starting Metasploit console...{RESET}")
    print(f"{YELLOW}Common commands after starting:{RESET}")
    print("- search [exploit_name]")
    print("- use [exploit_path]")
    print("- show options")
    print("- set RHOSTS [target_ip]")
    print("- exploit")
    input("\nPress Enter to continue to Metasploit console...")
    os.system("msfconsole")

def run_john():
    print(f"\n{CYAN}[*] John the Ripper - Password Cracker{RESET}")
    hash_file = input("Enter path to file containing hashes: ")
    print(f"\n{YELLOW}Common John commands:{RESET}")
    print("1. Default cracking (auto-detect hash type)")
    print("2. Wordlist attack")
    print("3. Incremental mode (all chars)")
    choice = input("\nChoose mode (1-3): ")
    
    if choice == "1":
        cmd = f"john {hash_file}"
    elif choice == "2":
        wordlist = input("Enter path to wordlist: ")
        cmd = f"john --wordlist={wordlist} {hash_file}"
    elif choice == "3":
        cmd = f"john --incremental {hash_file}"
    else:
        print(f"{RED}Invalid choice!{RESET}")
        return
    
    print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
    os.system(cmd)

def run_aircrack():
    print(f"\n{CYAN}[*] Aircrack-ng - WiFi Security Tool{RESET}")
    print(f"\n{YELLOW}Common Aircrack-ng commands:{RESET}")
    print("1. Capture WiFi handshake")
    print("2. Crack WPA/WPA2 handshake")
    choice = input("\nChoose action (1-2): ")
    
    if choice == "1":
        print("\n1. Put your WiFi adapter in monitor mode first:")
        print("   airmon-ng start wlan0")
        print("2. Then capture packets:")
        print("   airodump-ng wlan0mon")
        print("3. When you see target AP, capture its traffic:")
        print("   airodump-ng -c [channel] --bssid [AP_MAC] -w capture wlan0mon")
        print("4. Wait for handshake (shown as WPA handshake)")
    elif choice == "2":
        cap_file = input("Enter path to .cap file containing handshake: ")
        wordlist = input("Enter path to wordlist: ")
        cmd = f"aircrack-ng -w {wordlist} {cap_file}"
        print(f"\n{GREEN}[+] Running: {cmd}{RESET}")
        os.system(cmd)
    else:
        print(f"{RED}Invalid choice!{RESET}")

def show_help():
    print(f"\n{YELLOW}Available Tools:{RESET}")
    print("1. Nmap - Network scanner")
    print("2. Nikto - Web server scanner")
    print("3. sqlmap - SQL injection tool")
    print("4. DIRB - Web content scanner")
    print("5. Hydra - Password cracker")
    print("6. WPScan - WordPress scanner")
    print("7. Gobuster - Directory/DNS bruteforcer")
    print("8. Metasploit - Exploitation framework")
    print("9. John the Ripper - Password cracker")
    print("10. Aircrack-ng - WiFi security tool")
    print("0. Exit")

def main():
    while True:
        print_banner()
        show_help()
        choice = input("\nSelect tool to run (0-10): ")
        
        if choice == "0":
            print(f"\n{RED}Exiting... Goodbye!{RESET}\n")
            break
        elif choice == "1":
            install_tool("nmap")
            run_nmap()
        elif choice == "2":
            install_tool("nikto")
            run_nikto()
        elif choice == "3":
            install_tool("sqlmap")
            run_sqlmap()
        elif choice == "4":
            install_tool("dirb")
            run_dirb()
        elif choice == "5":
            install_tool("hydra")
            run_hydra()
        elif choice == "6":
            install_tool("wpscan")
            run_wpscan()
        elif choice == "7":
            install_tool("gobuster")
            run_gobuster()
        elif choice == "8":
            install_tool("metasploit")
            run_metasploit()
        elif choice == "9":
            install_tool("john")
            run_john()
        elif choice == "10":
            install_tool("aircrack-ng")
            run_aircrack()
        else:
            print(f"\n{RED}Invalid choice! Please select 0-10.{RESET}")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{RED}Exiting... Goodbye!{RESET}\n")
        sys.exit(0)