import os
import sqlite3
import json
import base64
import shutil
import re
import threading
import time
import psutil
from Crypto.Cipher import AES
import win32crypt
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk

class ChromePasswordExtractor:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("900x700")
        self.configure_dark_theme()
        
        # Authorization flag
        self.authorized = False
        self.usb_detected = False
        
        # Dark theme colors
        self.bg_color = "#2d2d2d"
        self.fg_color = "#ffffff"
        self.entry_bg = "#3d3d3d"
        self.button_bg = "#3d3d3d"
        self.button_active = "#4d4d4d"
        self.border_color = "#4d4d4d"
        
        # Timer variables
        self.hide_timer = None
        self.clipboard_clear_timer = None
        
        # Add Ctrl+C binding
        self.root.bind('<Control-c>', self.copy_selected_text)
        self.root.bind('<Control-C>', self.copy_selected_text)
        
        # Show authorization screen first
        self.show_auth_screen()
        
    def configure_dark_theme(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure('.', background="#2d2d2d", foreground="#ffffff")
        style.configure('TEntry', fieldbackground="#3d3d3d", foreground="#ffffff")
        style.configure('TButton', background="#3d3d3d", foreground="#ffffff")
        style.map('TButton', 
                 background=[('active', '#4d4d4d')],
                 foreground=[('active', '#ffffff')])
        
        self.root.configure(bg="#2d2d2d")
    
    def show_auth_screen(self):
        """Show authorization screen (USB or password)"""
        self.clear_window()
        
        auth_frame = tk.Frame(self.root, bg=self.bg_color)
        auth_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        tk.Label(
            auth_frame,
            text="Please insert USB drive or enter admin password",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 12)
        ).pack(pady=20)
        
        # Password entry
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            auth_frame,
            textvariable=self.password_var,
            show="*",
            width=30,
            style='TEntry'
        )
        password_entry.pack(pady=10)
        password_entry.bind("<Return>", lambda e: self.check_auth())
        
        # Login button
        login_btn = ttk.Button(
            auth_frame,
            text="Login",
            command=self.check_auth,
            style='TButton'
        )
        login_btn.pack(pady=10)
        
        # Start USB monitoring
        self.usb_monitor_thread = threading.Thread(target=self.monitor_usb, daemon=True)
        self.usb_monitor_thread.start()
        
        # Focus on password field
        password_entry.focus_set()
    
    def check_auth(self):
        """Check password or USB authorization"""
        password = self.password_var.get()
        if password == "admin" or self.usb_detected:
            self.authorized = True
            self.show_main_interface()
        else:
            messagebox.showerror("Error", "Incorrect password or no USB detected")
    
    def monitor_usb(self):
        """Monitor USB ports in background"""
        initial_drives = set(psutil.disk_partitions(all=True))
        
        while not self.authorized:
            time.sleep(1)
            current_drives = set(psutil.disk_partitions(all=True))
            new_drives = current_drives - initial_drives
            
            for drive in new_drives:
                if 'removable' in drive.opts:
                    self.usb_detected = True
                    if not self.authorized:
                        self.root.after(0, self.check_auth)
                    break
            
            initial_drives = current_drives
    
    def show_main_interface(self):
        """Show main password extraction interface"""
        self.clear_window()
        
        # Main frames
        main_frame = tk.Frame(self.root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Search bar
        search_frame = tk.Frame(main_frame, bg=self.bg_color)
        search_frame.pack(pady=10)
        
        search_label = tk.Label(
            search_frame,
            text="Search (URL or Login):",
            bg=self.bg_color,
            fg=self.fg_color,
            font=("Arial", 12)
        )
        search_label.pack(side=tk.LEFT, padx=5)
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(
            search_frame,
            textvariable=self.search_var,
            width=30,
            style='TEntry'
        )
        search_entry.pack(side=tk.LEFT)
        search_entry.bind("<KeyRelease>", self.filter_results)
        
        # Button frame
        button_frame = tk.Frame(main_frame, bg=self.bg_color)
        button_frame.pack(pady=10)
        
        # Buttons with border
        button_style = {
            'bg': self.button_bg,
            'fg': self.fg_color,
            'activebackground': self.button_active,
            'font': ('Arial', 12),
            'width': 15,
            'relief': 'ridge',
            'borderwidth': 2,
            'highlightthickness': 0
        }
        
        self.extract_btn = tk.Button(
            button_frame,
            text="Get Passwords",
            command=self.start_extraction,
            **button_style
        )
        self.extract_btn.pack(side=tk.LEFT, padx=5)
        
        self.toggle_btn = tk.Button(
            button_frame,
            text="Show Passwords",
            command=self.toggle_passwords,
            **button_style,
            state=tk.DISABLED
        )
        self.toggle_btn.pack(side=tk.LEFT, padx=5)
        
        # Results area
        self.result_area = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            font=("Consolas", 10),
            state=tk.DISABLED,
            bg=self.entry_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            padx=10,
            pady=10,
            relief='flat',
            borderwidth=2
        )
        self.result_area.pack(fill=tk.BOTH, expand=True)
        self.result_area.bind("<Double-Button-1>", self.copy_selected_text)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(
            self.root,
            textvariable=self.status_var,
            bd=1,
            relief=tk.SUNKEN,
            anchor=tk.W,
            bg=self.bg_color,
            fg=self.fg_color
        )
        status_bar.pack(fill=tk.X, padx=5, pady=5)
        
        # Initialize variables
        self.passwords = []
        self.filtered_passwords = []
        self.show_passwords = False
        self.scroll_position = 0.0
        
        # Start clipboard cleaner
        self.start_clipboard_cleaner()
    
    def filter_results(self, event=None):
        """Filter passwords based on search"""
        search_text = self.search_var.get().lower()
        self.filtered_passwords = [
            p for p in self.passwords 
            if search_text in p['url'].lower() or search_text in p['login'].lower()
        ]
        self.display_results()
    
    def start_clipboard_cleaner(self):
        """Start the periodic clipboard cleaning"""
        self.clear_clipboard()
        self.clipboard_clear_timer = threading.Timer(10.0, self.start_clipboard_cleaner)
        self.clipboard_clear_timer.daemon = True
        self.clipboard_clear_timer.start()
    
    def clear_clipboard(self):
        """Clear clipboard and remove any passwords"""
        try:
            clipboard_content = self.root.clipboard_get()
            if clipboard_content:
                # List of patterns to look for in clipboard
                password_patterns = [
                    r'Password:\s*\S+',
                    r'password:\s*\S+',
                    r'pwd:\s*\S+',
                    r'pass:\s*\S+',
                    r'Пароль:\s*\S+',
                    r'пароль:\s*\S+'
                ]
                
                # Check if clipboard contains any password-like content
                contains_password = any(
                    re.search(pattern, clipboard_content, re.IGNORECASE) 
                    for pattern in password_patterns
                )
                
                if contains_password:
                    self.root.clipboard_clear()
                    self.status_var.set("Clipboard cleared (password detected)")
        except tk.TclError:
            pass  # Clipboard is empty or contains non-text data

    def clear_window(self):
        """Clear all widgets from window"""
        for widget in self.root.winfo_children():
            widget.destroy()
    
    def start_extraction(self):
        self.extract_btn.config(state=tk.DISABLED)
        self.toggle_btn.config(state=tk.DISABLED)
        self.result_area.config(state=tk.NORMAL)
        self.result_area.delete(1.0, tk.END)
        self.result_area.config(state=tk.DISABLED)
        self.status_var.set("Working...")
        
        threading.Thread(target=self.extract_passwords, daemon=True).start()

    def extract_passwords(self):
        try:
            key = self.get_encryption_key()
            login_data_path = os.path.join(
                os.environ['LOCALAPPDATA'],
                'Google', 'Chrome', 'User Data', 'Default', 'Login Data'
            )
            
            if not os.path.exists(login_data_path):
                self.show_error("Password file not found! Close Chrome and try again.")
                return
            
            temp_db = "temp_login.db"
            shutil.copy2(login_data_path, temp_db)
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT origin_url, username_value, password_value 
                FROM logins
                WHERE password_value IS NOT NULL
                ORDER BY origin_url
            """)
            
            self.passwords = []
            for row in cursor.fetchall():
                url, username, encrypted_password = row
                if self.is_junk_url(url):
                    continue
                
                password = self.decrypt_password(encrypted_password, key)
                if password:
                    self.passwords.append({
                        'url': url,
                        'login': username,
                        'password': password
                    })
            
            cursor.close()
            conn.close()
            os.remove(temp_db)
            
            self.filtered_passwords = self.passwords  # Show all passwords initially
            self.display_results()
            self.status_var.set(f"Found {len(self.passwords)} passwords")
            self.toggle_btn.config(state=tk.NORMAL)
            
        except Exception as e:
            self.show_error(f"Error: {str(e)}")
        finally:
            self.extract_btn.config(state=tk.NORMAL)

    def toggle_passwords(self):
        # Save exact scroll position
        self.scroll_position = self.result_area.yview()[0]
        
        self.show_passwords = not self.show_passwords
        
        if self.show_passwords:
            self.toggle_btn.config(text="Hide Passwords")
            # Start timer to auto-hide passwords after 15 seconds
            if self.hide_timer:
                self.hide_timer.cancel()
            self.hide_timer = threading.Timer(15.0, self.auto_hide_passwords)
            self.hide_timer.daemon = True
            self.hide_timer.start()
        else:
            self.toggle_btn.config(text="Show Passwords")
            if self.hide_timer:
                self.hide_timer.cancel()
                self.hide_timer = None
        
        self.display_results()
        
        # Restore scroll position
        self.result_area.yview_moveto(self.scroll_position)
    
    def auto_hide_passwords(self):
        """Automatically hide passwords after timeout"""
        if self.show_passwords:
            self.root.after(0, self.toggle_passwords)
            self.status_var.set("Passwords automatically hidden")

    def display_results(self):
        self.result_area.config(state=tk.NORMAL)
        self.result_area.delete(1.0, tk.END)
        
        # Use filtered passwords for display
        passwords_to_display = self.filtered_passwords if self.filtered_passwords else self.passwords

        for i, item in enumerate(passwords_to_display, 1):
            password = item['password'] if self.show_passwords else "********"
            
            self.result_area.insert(tk.END, 
                f"{i}. Site: {item['url']}\n"
                f"   Login: {item['login']}\n"
                f"   Password: {password}\n\n"
            )
        
        self.result_area.config(state=tk.DISABLED)

    def is_junk_url(self, url):
        patterns = [
            r'^android://',
            r'^chrome://',
            r'^about:',
            r'^file://',
            r'@com\.'
        ]
        return any(re.search(pattern, url, re.IGNORECASE) for pattern in patterns)

    def get_encryption_key(self):
        local_state_path = os.path.join(
            os.environ['LOCALAPPDATA'],
            'Google', 'Chrome', 'User Data', 'Local State'
        )
        
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        
            encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            encrypted_key = encrypted_key[5:]  # Remove DPAPI prefix
            
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

    def decrypt_password(self, encrypted_password, key):
        try:
            iv = encrypted_password[3:15]
            ciphertext = encrypted_password[15:-16]
            auth_tag = encrypted_password[-16:]
            
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt_and_verify(ciphertext, auth_tag).decode('utf-8')
        except:
            return None

    def copy_selected_text(self, event=None):
        """Copy selected text to clipboard (works with Ctrl+C and double-click)"""
        try:
            if not self.result_area.tag_ranges(tk.SEL):  # If nothing selected
                return
                
            selected = self.result_area.selection_get()
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
            
            if re.search(r'Password:\s*\S+', selected, re.IGNORECASE):
                self.status_var.set("Password copied (will be cleared)")
            else:
                self.status_var.set("Text copied to clipboard")
                
        except tk.TclError:
            self.status_var.set("Copy error - nothing selected")

    def show_error(self, message):
        messagebox.showerror("Error", message)
        self.status_var.set("Error")
        self.extract_btn.config(state=tk.NORMAL)
        self.toggle_btn.config(state=tk.DISABLED)
    
    def __del__(self):
        """Clean up timers when closing"""
        if hasattr(self, 'hide_timer') and self.hide_timer:
            self.hide_timer.cancel()
        if hasattr(self, 'clipboard_clear_timer') and self.clipboard_clear_timer:
            self.clipboard_clear_timer.cancel()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChromePasswordExtractor(root)
    root.mainloop()