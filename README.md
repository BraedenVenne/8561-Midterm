# 8561-Midterm

Client-server security assessment tool suite featuring an authenticated TCP control channel, multi-factor authentication (TOTP), an automated port scanner, an HTTP security checker, a message application, and an offline PCAP analysis module.

---

## Prerequisites

* Python 3.x installed on your system.
* Nmap installed (required for the `python-nmap` port scanning module).

---

## Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/BraedenVenne/8561-Midterm.git
   cd 8561-Midterm
   ```

2. **Create and Activate a Virtual Environment:**
   * **Windows (PowerShell):**
     ```powershell
     python -m venv .venv
     .venv\Scripts\Activate.ps1
     ```
   * **macOS / Linux:**
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```

3. **Install Dependencies:**
   Install all required packages using the requirements file:
   ```bash
   pip install -r requirments.txt
   ```

---

## Running the Application

To run the full suite, open **three separate terminal windows/tabs** (with your virtual environment activated in each) and follow these steps in order:

### Step 1: Start the Test Web Server (Optional - for HTTP Security Checker)
Runs the target test website locally on `http://127.0.0.1:8765`:
```bash
python test_website.py
```

### Step 2: Start the Main TCP Security Server
Binds the central security server to `127.0.0.1:12345` (ensure `FSCT8561_Operation_Sentinel_Traffic.pcap` is in the root directory for the PCAP module):
```bash
python server.py
```
*Note: Upon entering the username and password for `alice` the TOTP secret will be displayed on the server.py terminal console.* 

### Step 3: Run the TCP Client Interface
Launches the client-side terminal interface to connect to the server:
```bash
python client.py
```

---

## Default Login Credentials

* **Username:** `alice`
* **Password:** `Cyber123!`
* **TOTP Code:** Enter the current 6-digit code generated from your authenticator app (linked using the URI displayed in the server console) you can use a website such as https://totp.danhersam.com/ to generate a code as well.

### Security Menu Options

There are five options to choose from on the menu:

* **[1] Run Local TCP Port Scanner:** Prompts for a target IP/hostname and port range (1-65535), executing an Nmap scan to output open and closed service tables.

* **[2] Run HTTP Website Security Checker:** Audits endpoints on the local test web server (`http://127.0.0.1:8765`), checking response headers and cookies, and exporting findings to CSV files.

* **[3] Run Offline PCAP Analysis:** Instructs the server to parse `FSCT8561_Operation_Sentinel_Traffic.pcap` via Scapy, reporting packet counts and flagging suspicious IPs exceeding traffic thresholds.

* **[4] Run Message Application:** Opens an active terminal chat loop to send messages to the server using the `MSG|` protocol format (with a 200-character length limit).

* **[5] Exit Application:** Sends an `EXIT|` command to gracefully terminate the connection and close the client.
