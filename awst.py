#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Web Security Toolkit (AWST) - Auto-Installer & Multi-Tool
Features:
- Auto-installs missing dependencies
- Checks for updates
- Multiple web security testing modules
- Colorized output
- Logging system
"""

import os
import sys
import platform
import subprocess
import requests
import time
import socket
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from datetime import datetime
import argparse
import json
import hashlib
from colorama import init, Fore, Style

# Initialize colorama
init()
GREEN = Fore.GREEN
RED = Fore.RED
BLUE = Fore.BLUE
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

# Global variables
VERSION = "2.0"
TOOL_NAME = "AWST"
LOG_FILE = "awst_log.txt"

# Required dependencies
REQUIRED_PACKAGES = {
    "requests": "requests",
    "bs4": "beautifulsoup4",
    "colorama": "colorama",
    "argparse": "argparse"
}

# Banner
def show_banner():
    print(f"""{CYAN}
    █████╗ ██╗    ██╗███████╗████████╗
   ██╔══██╗██║    ██║██╔════╝╚══██╔══╝
   ███████║██║ █╗ ██║███████╗   ██║   
   ██╔══██║██║███╗██║╚════██║   ██║   
   ██║  ██║╚███╔███╔╝███████║   ██║   
   ╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝   ╚═╝   
   {YELLOW}Advanced Web Security Toolkit {RESET}(v{VERSION})
   {RED}USE ONLY FOR AUTHORIZED PENETRATION TESTING{RESET}
    """)

# Check and install dependencies
def check_dependencies():
    print(f"\n{YELLOW}[*] Checking dependencies...{RESET}")
    missing_pkgs = []
    
    for pkg in REQUIRED_PACKAGES:
        try:
            __import__(pkg)
        except ImportError:
            missing_pkgs.append(REQUIRED_PACKAGES[pkg])
    
    if missing_pkgs:
        print(f"{RED}[!] Missing packages: {', '.join(missing_pkgs)}{RESET}")
        install = input(f"{YELLOW}[?] Install missing packages? (Y/n): {RESET}").strip().lower()
        
        if install == 'y' or install == '':
            try:
                print(f"{BLUE}[*] Installing dependencies...{RESET}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade"] + missing_pkgs)
                print(f"{GREEN}[+] Dependencies installed successfully!{RESET}")
                time.sleep(1)
            except Exception as e:
                print(f"{RED}[!] Failed to install dependencies: {e}{RESET}")
                sys.exit(1)
        else:
            print(f"{RED}[!] Required packages not installed. Exiting.{RESET}")
            sys.exit(1)
    else:
        print(f"{GREEN}[+] All dependencies are installed.{RESET}")

# Check for updates
def check_updates():
    try:
        print(f"\n{YELLOW}[*] Checking for updates...{RESET}")
        response = requests.get(f"{REPO_URL}/raw/main/version.json", timeout=5)
        
        if response.status_code == 200:
            latest_version = response.json().get("version")
            
            if latest_version != VERSION:
                print(f"{RED}[!] New version available: {latest_version}{RESET}")
                update = input(f"{YELLOW}[?] Update now? (Y/n): {RESET}").strip().lower()
                
                if update == 'y' or update == '':
                    print(f"{BLUE}[*] Updating tool...{RESET}")
                    try:
                        subprocess.check_call(["git", "pull", "origin", "main"])
                        print(f"{GREEN}[+] Update successful! Please restart the tool.{RESET}")
                        sys.exit(0)
                    except Exception as e:
                        print(f"{RED}[!] Update failed: {e}{RESET}")
            else:
                print(f"{GREEN}[+] You are using the latest version.{RESET}")
    except Exception as e:
        print(f"{RED}[!] Could not check for updates: {e}{RESET}")

# Logging system
def log_action(action, target=""):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {action} {target}\n"
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)

# Main menu
def main_menu():
    while True:
        clear_screen()
        show_banner()
        
        print(f"\n{YELLOW}Main Menu:{RESET}")
        print(f"1. Website Reconnaissance")
        print(f"2. Vulnerability Scanner")
        print(f"3. SQL Injection Tester")
        print(f"4. XSS Vulnerability Scanner")
        print(f"5. Directory Bruteforcer")
        print(f"6. Subdomain Scanner")
        print(f"7. Port Scanner")
        print(f"8. Admin Panel Finder")
        print(f"9. Check for Updates")
        print(f"0. Exit")
        
        choice = input(f"\n{YELLOW}[?] Select an option (0-9): {RESET}").strip()
        
        if choice == "1":
            website_recon()
        elif choice == "2":
            vulnerability_scanner()
        elif choice == "3":
            sql_injection_tester()
        elif choice == "4":
            xss_scanner()
        elif choice == "5":
            directory_bruteforcer()
        elif choice == "6":
            subdomain_scanner()
        elif choice == "7":
            port_scanner()
        elif choice == "8":
            admin_panel_finder()
        elif choice == "9":
            check_updates()
            input("\nPress Enter to continue...")
        elif choice == "0":
            print(f"\n{YELLOW}[+] Exiting...{RESET}")
            sys.exit(0)
        else:
            print(f"{RED}[!] Invalid choice!{RESET}")
            time.sleep(1)

# Clear screen function
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

# Website reconnaissance module
def website_recon():
    clear_screen()
    print(f"{CYAN}[+] Website Reconnaissance{RESET}\n")
    url = input(f"{YELLOW}[?] Enter target URL (e.g., http://example.com): {RESET}").strip()
    
    try:
        log_action("Website Recon", url)
        response = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0"})
        
        # Server info
        print(f"\n{GREEN}[+] Server Information:{RESET}")
        for header in ["Server", "X-Powered-By", "X-AspNet-Version"]:
            if header in response.headers:
                print(f"{header}: {YELLOW}{response.headers[header]}{RESET}")
        
        # Extract links
        print(f"\n{GREEN}[+] Extracted Links:{RESET}")
        soup = BeautifulSoup(response.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.startswith(("http://", "https://")):
                print(href)
            else:
                print(urljoin(url, href))
        
        # Check robots.txt
        print(f"\n{GREEN}[+] Checking robots.txt:{RESET}")
        robots_url = urljoin(url, "/robots.txt")
        robots_resp = requests.get(robots_url, timeout=5)
        if robots_resp.status_code == 200:
            print(robots_resp.text)
        else:
            print(f"{RED}[-] robots.txt not found{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    input("\nPress Enter to continue...")

# Vulnerability scanner module
def vulnerability_scanner():
    clear_screen()
    print(f"{CYAN}[+] Vulnerability Scanner{RESET}\n")
    url = input(f"{YELLOW}[?] Enter target URL (e.g., http://example.com): {RESET}").strip()
    
    try:
        log_action("Vulnerability Scan", url)
        print(f"\n{YELLOW}[*] Scanning for common vulnerabilities...{RESET}")
        
        # SQLi test
        test_url = f"{url}?id=1'"
        response = requests.get(test_url, timeout=8)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            print(f"{RED}[!] Possible SQL Injection vulnerability{RESET}")
        
        # XSS test
        test_url = f"{url}?q=<script>alert(1)</script>"
        response = requests.get(test_url, timeout=8)
        if "<script>alert(1)</script>" in response.text:
            print(f"{RED}[!] Possible XSS vulnerability{RESET}")
        
        # LFI test
        test_url = urljoin(url, "/../../../../etc/passwd")
        response = requests.get(test_url, timeout=8)
        if "root:" in response.text:
            print(f"{RED}[!] Possible LFI vulnerability{RESET}")
        
        print(f"\n{GREEN}[+] Scan completed{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error: {e}{RESET}")
    
    input("\nPress Enter to continue...")

# (Other functions like SQLi, XSS, Bruteforce, etc. can be added similarly)

# Main execution
if __name__ == "__main__":
    try:
        check_dependencies()
        check_updates()
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Exiting...{RESET}")
        sys.exit(0)