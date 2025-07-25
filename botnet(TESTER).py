#!/usr/bin/env python3
import requests
import concurrent.futures
import time
import sys
from datetime import datetime

# Warna untuk terminal
class Colors:
    RED = "\033[1;31m"
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[1;35m"
    CYAN = "\033[1;36m"
    RESET = "\033[0m"

def print_banner():
    print(f"""{Colors.CYAN}
   ___  _____  _____  ____  ____  _____ ____  
  / _ \|  _  \|  ___|/ ___||  _ \| ____|  _ \ 
 | | | | | | || |_   \___ \| | | |  _| | |_) |
 | |_| | |_| ||  _|   ___) | |_| | |___|  _ < 
  \___/|_____/|_|    |____/|____/|_____|_| \_\\
                                              
{Colors.RESET}""")
    print(f"{Colors.YELLOW}Website Load Testing Tool with Status Monitoring{Colors.RESET}\n")

def get_user_input():
    print(f"{Colors.BLUE}[CONFIGURATION]{Colors.RESET}")
    url = input("Enter target URL (with http/https): ").strip()
    
    # Validasi URL
    if not url.startswith(('http://', 'https://')):
        print(f"{Colors.RED}Error: URL must start with http:// or https://{Colors.RESET}")
        sys.exit(1)
    
    try:
        duration = int(input("Test duration (seconds): "))
        rate = int(input("Requests per second: "))
        workers = int(input(f"Concurrent workers (recommend {rate//2}-{rate}): "))
        timeout = int(input("Request timeout (seconds): "))
    except ValueError:
        print(f"{Colors.RED}Error: Please enter valid numbers{Colors.RESET}")
        sys.exit(1)
        
    return url, duration, rate, workers, timeout

def send_request(session, url, timeout):
    try:
        start_time = time.time()
        response = session.get(url, timeout=timeout)
        latency = (time.time() - start_time) * 1000  # dalam milidetik
        return {
            'status': response.status_code,
            'latency': latency,
            'success': True,
            'error': None
        }
    except Exception as e:
        return {
            'status': None,
            'latency': None,
            'success': False,
            'error': str(e)
        }

def monitor_website(url, interval=5, timeout=5):
    """Fungsi untuk memonitor status website secara terpisah"""
    session = requests.Session()
    while True:
        try:
            start_time = time.time()
            response = session.get(url, timeout=timeout)
            latency = (time.time() - start_time) * 1000
            status = response.status_code
            
            if 200 <= status < 300:
                color = Colors.GREEN
            elif 400 <= status < 500:
                color = Colors.YELLOW
            else:
                color = Colors.RED
                
            print(f"{color}[MONITOR] Status: {status} | Latency: {latency:.2f}ms{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}[MONITOR] Error: {str(e)}{Colors.RESET}")
        
        time.sleep(interval)

def run_load_test():
    url, duration, rate, workers, timeout = get_user_input()
    
    # Setup session
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    # Mulai thread monitoring
    from threading import Thread
    monitor_thread = Thread(target=monitor_website, args=(url, 5, timeout), daemon=True)
    monitor_thread.start()
    
    print(f"\n{Colors.BLUE}[TEST STARTED]{Colors.RESET}")
    print(f"Target: {url}")
    print(f"Duration: {duration} seconds")
    print(f"Rate: {rate} requests/second")
    print(f"Workers: {workers}")
    print(f"Timeout: {timeout} seconds\n")
    
    start_time = time.time()
    end_time = start_time + duration
    total_requests = 0
    successful_requests = 0
    failed_requests = 0
    total_latency = 0
    
    # Mulai pengujian
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        while time.time() < end_time:
            batch_start = time.time()
            
            # Kirim batch request
            futures = [executor.submit(send_request, session, url, timeout) for _ in range(rate)]
            
            # Proses hasil
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                total_requests += 1
                
                if result['success']:
                    successful_requests += 1
                    total_latency += result['latency']
                else:
                    failed_requests += 1
            
            # Hitung waktu yang tersisa untuk batch ini
            batch_time = time.time() - batch_start
            if batch_time < 1.0:
                time.sleep(1.0 - batch_time)
    
    # Hasil pengujian
    test_duration = time.time() - start_time
    avg_latency = total_latency / successful_requests if successful_requests > 0 else 0
    
    print(f"\n{Colors.BLUE}[TEST RESULTS]{Colors.RESET}")
    print(f"Total duration: {test_duration:.2f} seconds")
    print(f"Total requests: {total_requests}")
    print(f"{Colors.GREEN}Successful requests: {successful_requests} ({successful_requests/total_requests*100:.2f}%){Colors.RESET}")
    print(f"{Colors.RED}Failed requests: {failed_requests} ({failed_requests/total_requests*100:.2f}%){Colors.RESET}")
    print(f"Average latency: {avg_latency:.2f}ms (successful only)")
    
    # Generate report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"loadtest_report_{timestamp}.txt"
    
    with open(filename, 'w') as f:
        f.write(f"Load Test Report - {timestamp}\n")
        f.write("="*40 + "\n")
        f.write(f"Target URL: {url}\n")
        f.write(f"Test duration: {duration} seconds\n")
        f.write(f"Request rate: {rate} requests/second\n")
        f.write(f"Concurrent workers: {workers}\n")
        f.write(f"Request timeout: {timeout} seconds\n\n")
        f.write(f"Total requests: {total_requests}\n")
        f.write(f"Successful requests: {successful_requests} ({successful_requests/total_requests*100:.2f}%)\n")
        f.write(f"Failed requests: {failed_requests} ({failed_requests/total_requests*100:.2f}%)\n")
        f.write(f"Average latency: {avg_latency:.2f}ms (successful only)\n")
    
    print(f"\nReport saved to {filename}")

if __name__ == "__main__":
    print_banner()
    
    # Peringatan legal
    print(f"{Colors.RED}WARNING: Only use this tool on websites you own or have explicit permission to test.{Colors.RESET}")
    print(f"{Colors.RED}Unauthorized load testing may be illegal and considered a cyber attack.{Colors.RESET}\n")
    
    confirm = input("Do you have permission to test this website? (yes/no): ").lower()
    if confirm != 'yes':
        print(f"{Colors.RED}Test aborted. You must have proper authorization.{Colors.RESET}")
        sys.exit(0)
    
    try:
        run_load_test()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Test interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}Error: {str(e)}{Colors.RESET}")
        sys.exit(1)