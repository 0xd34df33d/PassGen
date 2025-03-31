import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any
from ..core.vault_manager import VaultManager
from ..utils.password_generator import PasswordGenerator
import logging
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QMessageBox
)

logger = logging.getLogger(__name__)

class MasterPasswordDialog(tk.Toplevel):
    def __init__(self, parent: tk.Tk, vault_manager: VaultManager):
        super().__init__(parent)
        
        self.vault_manager = vault_manager
        self.result = False
        
        # Configure dialog
        self.title("Master Password")
        self.geometry("300x150")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        
        # Create main container
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Password entry
        ttk.Label(main_frame, text="Master Password:").pack(pady=(0, 5))
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 10))
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(
            main_frame,
            text="Show Password",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        ).pack(pady=(0, 10))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(
            button_frame,
            text="Unlock",
            command=self._unlock
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=self._cancel
        ).pack(side=tk.RIGHT, padx=5)
        
        # Bind events
        self.password_entry.bind('<Return>', lambda e: self._unlock())
        self.password_entry.bind('<Escape>', lambda e: self._cancel())
        
        # Focus password entry
        self.password_entry.focus_set()
        
        # Center dialog
        self._center_dialog()
    
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="•")
    
    def _unlock(self):
        """Attempt to unlock the vault."""
        password = self.password_var.get()
        if self.vault_manager.unlock_vault(password):
            self.result = True
            self.destroy()
        else:
            self.password_var.set("")
            self.password_entry.focus_set()
    
    def _cancel(self):
        """Cancel the dialog."""
        self.result = False
        self.destroy()
    
    def _center_dialog(self):
        """Center the dialog on the screen."""
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

class UnlockDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        logger.info("Initializing unlock dialog")
        self.setWindowTitle("Unlock Vault")
        self.setModal(True)
        self._setup_ui()
        logger.info("Unlock dialog initialized successfully")
    
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        
        # Password input
        password_layout = QHBoxLayout()
        password_label = QLabel("Master Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.unlock_btn = QPushButton("Unlock")
        self.unlock_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.unlock_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
    
    def get_password(self) -> str:
        """Get the entered password."""
        return self.password_input.text()

class EntryDialog(QDialog):
    def __init__(self, parent=None, entry=None):
        super().__init__(parent)
        self.entry = entry
        self.setWindowTitle("Add Entry" if not entry else "Edit Entry")
        self.setModal(True)
        self._setup_ui()
    
    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)
        
        # Title
        title_layout = QHBoxLayout()
        title_label = QLabel("Title:")
        self.title_input = QLineEdit()
        if self.entry:
            self.title_input.setText(self.entry['title'])
        title_layout.addWidget(title_label)
        title_layout.addWidget(self.title_input)
        layout.addLayout(title_layout)
        
        # Username
        username_layout = QHBoxLayout()
        username_label = QLabel("Username:")
        self.username_input = QLineEdit()
        if self.entry:
            self.username_input.setText(self.entry['username'])
        username_layout.addWidget(username_label)
        username_layout.addWidget(self.username_input)
        layout.addLayout(username_layout)
        
        # Password
        password_layout = QHBoxLayout()
        password_label = QLabel("Password:")
        self.password_input = QLineEdit()
        if self.entry:
            self.password_input.setText(self.entry['password'])
        password_layout.addWidget(password_label)
        password_layout.addWidget(self.password_input)
        layout.addLayout(password_layout)
        
        # URL
        url_layout = QHBoxLayout()
        url_label = QLabel("URL:")
        self.url_input = QLineEdit()
        if self.entry:
            self.url_input.setText(self.entry['url'])
        url_layout.addWidget(url_label)
        url_layout.addWidget(self.url_input)
        layout.addLayout(url_layout)
        
        # Notes
        notes_layout = QHBoxLayout()
        notes_label = QLabel("Notes:")
        self.notes_input = QLineEdit()
        if self.entry:
            self.notes_input.setText(self.entry['notes'])
        notes_layout.addWidget(notes_label)
        notes_layout.addWidget(self.notes_input)
        layout.addLayout(notes_layout)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.save_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.save_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
    
    def get_entry_data(self) -> dict:
        """Get the entry data from the form."""
        return {
            'title': self.title_input.text(),
            'username': self.username_input.text(),
            'password': self.password_input.text(),
            'url': self.url_input.text(),
            'notes': self.notes_input.text()
        } 