# Information Stealer - Educational Project

## ⚠️ DISCLAIMER

**This project is for EDUCATIONAL PURPOSES ONLY.** It is designed to help students and security researchers understand:
- How attackers extract sensitive information from systems
- Common vulnerabilities in password storage
- The importance of cybersecurity best practices
- How to defend against such attacks

**DO NOT use this tool on systems you do not own or have explicit permission to test.** Unauthorized access to computer systems is illegal and unethical.

---

## Project Overview

This Python script demonstrates how malicious actors extract sensitive information from Windows systems. It performs three main operations:

1. **Extracts Saved Browser Passwords** - Retrieves and decrypts stored credentials from Google Chrome
2. **Captures Clipboard Data** - Reads the current clipboard content (may contain passwords, credit card numbers, etc.)
3. **Steals System Information** - Gathers OS details, IP addresses, MAC address, hostname, and processor information

## Features

### 1. Chrome Password Extraction
- Locates Chrome's encrypted password database (`Login Data`)
- Extracts the encryption key from Chrome's `Local State` file
- Decrypts passwords using Windows DPAPI (Data Protection API) and AES-256-GCM
- Supports both old (DPAPI) and new (AES) Chrome encryption methods

### 2. Clipboard Data Capture
- Reads current clipboard content using `pyperclip`
- Can capture sensitive data like:
  - Passwords
  - Credit card numbers
  - Personal information
  - API keys and tokens

### 3. System Information Gathering
- **Operating System**: System name, version, architecture, processor
- **Network Information**: 
  - Local IP address
  - Public IP address (via external API)
  - MAC address
  - Hostname
- **Network Interfaces**: Lists all available network interfaces

## How It Works

### Decrypting Saved Passwords

1. **Locate Chrome Database**: The script finds Chrome's `Login Data` SQLite database in:
   - Windows: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
   - macOS: `~/Library/Application Support/Google/Chrome/Default/Login Data`
   - Linux: `~/.config/google-chrome/Default/Login Data`

2. **Extract Encryption Key**: 
   - Reads Chrome's `Local State` file (JSON format)
   - Extracts the base64-encoded encrypted key
   - Decrypts it using Windows DPAPI (`CryptUnprotectData`)

3. **Decrypt Passwords**:
   - For Chrome 80+: Uses AES-256-GCM encryption
   - For older versions: Uses Windows DPAPI
   - Queries the SQLite database for saved credentials
   - Decrypts each password using the extracted key

### Clipboard Hijacking

- Uses the `pyperclip` library to read clipboard content
- Captures any text currently stored in the clipboard
- This is a common attack vector as users often copy sensitive data

### System Reconnaissance

- Uses Python's standard libraries (`platform`, `socket`, `uuid`) to gather system details
- Queries external API (`ipify.org`) to determine public IP address
- Collects network interface information

## Installation

### Prerequisites

- Python 3.7 or higher
- Windows operating system (for password extraction - uses Windows-specific APIs)
- Google Chrome installed (for password extraction)

### Setup

1. **Clone or download this repository**

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

   Required packages:
   - `pywin32` - Windows API access for password decryption
   - `pycryptodome` - AES encryption/decryption
   - `pyperclip` - Clipboard access
   - `requests` - HTTP requests for public IP

3. **Run the script**:
   ```bash
   python information_stealer.py
   ```

## Usage

Simply run the script:

```bash
python information_stealer.py
```

The script will:
1. Extract Chrome passwords (if available)
2. Capture clipboard content
3. Gather system information
4. Display results in the console
5. Save all data to `stolen_data.json`

### Output

The script generates:
- **Console output**: Real-time progress and summary
- **JSON file**: `stolen_data.json` containing all extracted information

Example output structure:
```json
{
    "passwords": [
        {
            "url": "https://example.com",
            "username": "user@example.com",
            "password": "decrypted_password"
        }
    ],
    "clipboard": "Copied text content...",
    "system_info": {
        "os": {
            "system": "Windows",
            "release": "10",
            "version": "10.0.26200",
            "architecture": "AMD64",
            "processor": "Intel64 Family 6 Model..."
        },
        "hostname": "DESKTOP-XXXXX",
        "mac_address": "xx:xx:xx:xx:xx:xx",
        "local_ip": "192.168.x.x",
        "public_ip": "xxx.xxx.xxx.xxx"
    }
}
```

## Key Concepts Covered

### Browser Forensics
- Understanding how browsers store credentials
- SQLite database structure and querying
- Encryption key management

### Cryptography
- Windows DPAPI (Data Protection API)
- AES-256-GCM encryption/decryption
- Key derivation and management

### System Reconnaissance
- Network information gathering
- System fingerprinting
- IP address enumeration

### Ethical Hacking & Cybersecurity
- Understanding attack vectors
- Importance of secure password storage
- Defense strategies against information theft

## Security Implications

This project demonstrates several security vulnerabilities:

1. **Browser Password Storage**: 
   - Passwords are encrypted but can be decrypted by any user logged into the system
   - No additional authentication required to access saved passwords

2. **Clipboard Security**:
   - Clipboard data is accessible to any running process
   - Sensitive data should never be stored in clipboard

3. **System Information Leakage**:
   - System details can be used for fingerprinting and targeted attacks
   - Network information aids in reconnaissance

## Defense Strategies

To protect against such attacks:

1. **Use a Password Manager**:
   - Use dedicated password managers with master passwords
   - Avoid browser password storage for sensitive accounts

2. **Enable Full Disk Encryption**:
   - Encrypt your hard drive to protect data at rest
   - Use BitLocker (Windows) or FileVault (macOS)

3. **Limit Clipboard Usage**:
   - Avoid copying sensitive data to clipboard
   - Use secure copy methods when necessary

4. **Network Security**:
   - Use VPNs to mask public IP
   - Implement network segmentation
   - Monitor network traffic

5. **System Hardening**:
   - Keep systems updated
   - Use antivirus/anti-malware software
   - Implement least privilege access

## Educational Value

This project helps students understand:

- **How attacks work**: Understanding the mechanics of information theft
- **Vulnerability assessment**: Identifying security weaknesses
- **Defense mechanisms**: Learning how to protect against such attacks
- **Ethical hacking**: Responsible security research practices

## Legal and Ethical Considerations

- ✅ **DO**: Use on your own systems for learning
- ✅ **DO**: Use with explicit written permission on test systems
- ✅ **DO**: Study the code to understand security concepts
- ❌ **DON'T**: Use on systems without permission
- ❌ **DON'T**: Use for malicious purposes
- ❌ **DON'T**: Distribute stolen information

## Troubleshooting

### Password Extraction Not Working

- **Issue**: "Windows-specific modules not available"
  - **Solution**: Ensure `pywin32` is installed: `pip install pywin32`

- **Issue**: "Chrome Login Data not found"
  - **Solution**: Ensure Chrome is installed and has saved passwords

- **Issue**: "Failed to decrypt password"
  - **Solution**: May occur if Chrome database is locked (close Chrome) or encryption method changed

### Clipboard Capture Issues

- **Issue**: "Error capturing clipboard"
  - **Solution**: Ensure `pyperclip` is installed and clipboard is accessible

### System Info Issues

- **Issue**: "Unable to determine public IP"
  - **Solution**: Check internet connection and firewall settings

## Project Structure

```
Information-Stealer/
│
├── information_stealer.py    # Main script
├── requirements.txt          # Python dependencies
├── README.md                 # This file
└── stolen_data.json         # Output file (generated)
```

## Contributing

This is an educational project. Contributions that improve:
- Code clarity and documentation
- Educational value
- Security awareness
- Cross-platform compatibility

are welcome.

## License

This project is provided for educational purposes. Use responsibly and ethically.

## References

- [Chrome Password Storage](https://chromium.googlesource.com/chromium/src/+/master/docs/security/faq.md)
- [Windows DPAPI](https://docs.microsoft.com/en-us/windows/win32/api/dpapi/)
- [AES-GCM Encryption](https://en.wikipedia.org/wiki/Galois/Counter_Mode)

## Author Notes

This project was created to help students understand cybersecurity vulnerabilities and defense mechanisms. Always use such tools responsibly and with proper authorization.

---

**Remember**: With great power comes great responsibility. Use this knowledge to improve security, not to exploit vulnerabilities.
