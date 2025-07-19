COMPANY : CODTECH IT SOLUTIONS

NAME : PAVITR KAUSHIK

INTERN ID : CT08DF354

DOMAIN : CYBER SECURITY & ETHICAL HACKING

DURATIONS : 8 WEEKS

MENTOR : NEELA SANTOSH

**TASK 1:** **FILE-INTEGRITY-CHECKER**

**DESCRIPTION**

🛡️ Folder Integrity Checker (with GUI)

Detect. Alert. Protect. A lightweight Python tool that monitors any folder for file modifications, additions, and deletions using cryptographic hashing and a GUI interface—ideal for cybersecurity, forensics, and data integrity monitoring.

🧰 Tools & Technologies Used Component Description 🐍 Python 3.x Core programming language used to build the application. 📦 Hashlib Python's built-in library to compute secure SHA-256 file hashes. 📁 os & json For directory traversal and data storage (hash records). 🖼️ Tkinter Standard Python library for creating a user-friendly Graphical User Interface (GUI). 📄 ScrolledText Allows viewing long output logs in the GUI cleanly.

🚀 Features

✅ Real-time integrity checks of folders using cryptographic hashes.

🧠 Intelligent detection of:

    🆕 New files

    ⚠️ Modified files

    ❌ Deleted files
  
    🧪 First-time scan saves a secure snapshot as hash_store.json.
    
    📜 Outputs changes in a clean, scrollable GUI window.
    
    🖱️ Easy-to-use buttons to browse folders and start scanning.


🛠️ How to Use

    Install Python if not already installed:
    https://www.python.org/downloads/

    Run the script:

    python folder_gui_checker.py

    Use the GUI:

    Click "Browse Folder" to select the directory.

    Click "Check Folder Integrity" to scan and detect changes.

    Changes will appear in the window (first-time scan will save hash records).
📂 Output

GUI shows:

    🆕 New files added

    ⚠️ Modified files (content changed)

    ❌ Deleted files
💡 Ideal Use Cases

    🔒 Cybersecurity monitoring and digital forensics

    🗂️ Academic or legal document change detection

    🧪 Detecting unauthorized changes in software/code projects
📌 Future Improvements

    🕒 Scheduled automatic integrity checks

    📨 Email or system notifications on detection

**OUTPUT**

<img width="744" height="540" alt="Screenshot 2025-06-20 155155" src="https://github.com/user-attachments/assets/de4dfb45-16f9-4aff-9922-63c8096fc4fa" />



**TASK 2: WEB-APPLICATION-VULNERABILITY-SCANNER**

**DESCRIPTION**
  
  🛡️ Web Application Vulnerability Scanner 🔍

Secure your web apps before attackers do. This Python-based CLI tool scans websites for common vulnerabilities like Cross-Site Scripting (XSS) and SQL Injection, helping ethical hackers, developers, and security testers identify weak spots in web applications.

🚀 Features

🌐 Scans any URL for vulnerable HTML forms.

💉 Automatically tests each form for XSS using an injection script (<script>alert('XSS')</script>).

🧬 Detects basic SQL Injection via payloads like ' OR '1'='1.

🧠 Intelligently identifies responses that indicate a vulnerability.

🧾 Displays detailed output in the terminal for fast debugging.

🧰 Tools & Libraries Used Tool Purpose requests Sending HTTP GET and POST requests BeautifulSoup Parsing and scraping web forms from HTML urllib.parse Handling form action URLs Python 3.x Core programming language

🛠️ How to Use

  Install dependencies (if not already):
  
      pip install requests beautifulsoup4

  Run the script:

      python Web_Application_Vulnerability_Scanner.py

  Enter the target URL when prompted, e.g.,

      Enter the URL to scan: http://example.com
✅ The scanner will:

Detect all forms on the page

Attempt XSS injections

Try SQLi payloads and look for error patterns

⚠️ Disclaimer

This tool is designed for educational and ethical testing purposes only. ⚠️ Do NOT use it on websites you do not own or have explicit permission to test.

**OUTPUT**

<img width="1011" height="191" alt="Screenshot 2025-06-20 160849" src="https://github.com/user-attachments/assets/ab4033e2-5dac-493f-a7e8-3d6fd0232875" />

**TASK 3: PENETRATION TESTING TOOLKIT**

**DESCRIPTION**
  
  🧰 Penetration Testing Toolkit – Python CLI

All-in-One Offensive Security Toolkit A powerful command-line Python script that brings together essential penetration testing modules—from port scanning and brute-forcing to HTTP analysis—into a single, beginner-friendly yet effective tool for ethical hackers and cybersecurity learners.

🔍 Modules Included

🔓 Port Scanner

    Efficiently scans a range of ports on a target IP to detect open services.
📂 FTP Brute Force (Demo)

    Performs a basic dictionary-based brute force attack on FTP services to test login credentials.
🧾 HTTP Header Analyzer

    Fetches and displays all HTTP headers from a target URL to identify potential misconfigurations or useful reconnaissance data.
⚙️ Technologies Used

Library Purpose socket Low-level TCP/IP port scanning ftplib FTP connection and login attempts requests HTTP GET requests for headers argparse Clean command-line interface datetime Logging the start time of a scan

🚀 How to Use

Make sure you have Python 3 installed.

Run the script from your terminal with any of the following options:

🔍 Port Scanner

     python Penetration_Testing_Toolkit.py --scan 192.168.1.1:20:100

Scans ports 20 to 100 on 192.168.1.1.

💥 FTP Brute Force (Demo)

     python Penetration_Testing_Toolkit.py --ftp 192.168.1.1:admin:wordlist.txt

Tries passwords from wordlist.txt on FTP service at 192.168.1.1 with username admin.

🌐 HTTP Header Analysis

     python Penetration_Testing_Toolkit.py --headers http://example.com

Displays all HTTP response headers from the given URL.

    💡 Use Cases

    🔐 Pentesting lab exercises

    🎓 Cybersecurity learning projects

    🔎 Quick on-the-go recon and enumeration

    📂 Testing basic security posture of small servers

⚠️ Disclaimer

This toolkit is intended for educational and ethical testing only. ⚠️ Do NOT scan or attack systems without proper authorization.

**OUTPUT**

<img width="1033" height="228" alt="Screenshot 2025-06-20 162704" src="https://github.com/user-attachments/assets/c85802b5-a37e-46e1-a19e-764f828b3dcf" />

**TASK 4: ADVANCED-ENCRYPTION-TOOL**

**DESCRIPTION**
  
  🔐 Advanced AES-256 File Encryption Tool (GUI Powered)

Protect what matters. Encrypt with confidence. This Python-based desktop application allows you to securely encrypt and decrypt files using military-grade AES-256 encryption—all wrapped in a simple and intuitive Tkinter GUI. Whether you're a privacy enthusiast or a cybersecurity student, this tool keeps your sensitive data safe and easy to handle.

🧰 Key Features

    🔐 AES-256 Encryption: Uses CBC mode with PKCS7 padding for strong symmetric encryption.

    🧬 Secure Key Derivation: Implements PBKDF2HMAC with SHA-256 and salting to protect passwords.

    🧠 Automatic Salt & IV Handling: Randomly generates salt and IV for each encryption session.

    💻 User-Friendly Interface: Clean, minimal GUI built with tkinter—no command-line needed.

    📁 File-Based Workflow: Encrypt and decrypt any file on your system with just a few clicks.
  
🛠️ Built With Library Purpose cryptography AES encryption, key derivation, padding tkinter Desktop GUI interface base64 For safe encoding/decoding if needed os Secure random salt/IV generation

🚀 How to Use

Install dependencies:

    pip install cryptography
Run the script:

    python Advanced_encryption_tool.py
In the GUI:

    🔒 Click "Encrypt File" → Choose a file → Set a password → Encrypted .enc file is saved.

    🔓 Click "Decrypt File" → Choose a .enc file → Enter the correct password → Decrypted .dec file is saved.
📂 File Output Format

    file.txt → encrypted → file.txt.enc

    file.txt.enc → decrypted → file.txt.dec

⚠️ Security Disclaimer

This tool is intended for educational and secure local use only. Do not share passwords, and always backup your original files. Incorrect passwords will result in decryption failure or data loss.

**OUTPUT**

<img width="857" height="493" alt="Screenshot 2025-06-20 161512" src="https://github.com/user-attachments/assets/c6a14bf6-5fc5-4e6f-8eef-5e63e33c6ce2" />
