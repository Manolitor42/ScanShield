# ScanShield

**ScanShield** is an advanced vulnerability scanner built to identify common web security flaws such as SQL Injection, XSS, LFI, RFI, directory listing issues, and security header misconfigurations.

## Features

- **SQL Injection**: Detects SQL injection vulnerabilities with a variety of payloads.
- **Cross-Site Scripting (XSS)**: Scans for XSS vulnerabilities using multiple payloads.
- **Local File Inclusion (LFI)**: Tests for LFI vulnerabilities with payloads for system files.
- **Remote File Inclusion (RFI)**: Identifies potential RFI vulnerabilities with external payloads.
- **Directory Listing**: Checks for directory listing vulnerabilities across common directories.
- **Security Headers**: Ensures HTTP security headers like X-Frame-Options, Strict-Transport-Security, and more are configured properly.


## Installation

### Linux

1. Clone this repository:
   ```bash
   git clone https://github.com/Fear2o/ScanShield.git
   cd ScanShield
   ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the scanner:
   ```bash
   python scanshield.py
   ```

### Windows

1. Clone this repository:
   - Use [Git for Windows](https://git-scm.com/) to clone the repo or download the ZIP file and extract it.

2. Install Python and required packages:
   - Make sure Python is installed from [python.org](https://www.python.org/downloads/).
   - Open Command Prompt (`cmd`) and navigate to the ScanShield directory:
     ```bash
     cd C:\path\to\ScanShield
     ```

3. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the scanner:
   ```bash
   python scanshield.py
   ```

### Termux (Android)

1. Install Termux from the [Google Play Store](https://play.google.com/store/apps/details?id=com.termux) or [F-Droid](https://f-droid.org/packages/com.termux/).

2. Update packages:
   ```bash
   pkg update
   ```

3. Install Git and Python:
   ```bash
   pkg install git python
   ```

4. Clone the repository:
   ```bash
   git clone https://github.com/Fear2o/ScanShield.git
   cd ScanShield
   ```

5. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

6. Run the scanner:
   ```bash
   python scanshield.py
   ```

### macOS

1. Clone this repository:
   ```bash
   git clone https://github.com/Fear2o/ScanShield.git
   cd ScanShield
   ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the scanner:
   ```bash
   python scanshield.py
   ```


## Payloads

ScanShield uses a variety of payloads for SQL injection, XSS, LFI, and RFI testing. It will automatically detect and attempt to exploit these vulnerabilities.

## Contributing

Feel free to fork this repo and submit pull requests for new features or improvements. Contributions are welcome!

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

