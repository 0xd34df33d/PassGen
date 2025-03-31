import tkinter as tk
from tkinter import ttk, messagebox
import asyncio
from typing import Optional
from ..core.vault_manager import VaultManager
from ..utils.config import Config
from ..utils.password_generator import PasswordGenerator
from .dialogs import MasterPasswordDialog, EntryDialog
from .tabs import GeneratorTab, VaultTab, SettingsTab

class PasswordManagerApp:
    def __init__(self, root: tk.Tk, vault_manager: VaultManager, config: Config):
        self.root = root
        self.vault_manager = vault_manager
        self.config = config
        self.password_generator = PasswordGenerator()
        
        # Configure root window
        self.root.title("Secure Password Manager")
        self.root.geometry("800x600")
        
        # Create main container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.generator_tab = GeneratorTab(self.notebook, self.password_generator)
        self.vault_tab = VaultTab(self.notebook, self.vault_manager)
        self.settings_tab = SettingsTab(self.notebook, self.vault_manager, self.config)
        
        # Add tabs to notebook
        self.notebook.add(self.generator_tab, text="Generator")
        self.notebook.add(self.vault_tab, text="Vault")
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Initialize state
        self._locked = True
        self._last_activity = 0
        self._clipboard_tasks = {}
        
        # Bind events
        self.root.bind('<Key>', self._on_activity)
        self.root.bind('<Button-1>', self._on_activity)
        self.root.bind('<Button-2>', self._on_activity)
        self.root.bind('<Button-3>', self._on_activity)
        
        # Start auto-lock timer
        self._schedule_auto_lock()
        
        # Show master password dialog
        self._show_master_password_dialog()
    
    def _on_activity(self, event):
        """Handle user activity to reset auto-lock timer."""
        self._last_activity = asyncio.get_event_loop().time()
        if self._locked:
            self._show_master_password_dialog()
    
    def _schedule_auto_lock(self):
        """Schedule the next auto-lock check."""
        if not self._locked:
            current_time = asyncio.get_event_loop().time()
            timeout = self.config.get('auto_lock_timeout', 300)
            if current_time - self._last_activity >= timeout:
                self._lock_vault()
        
        # Schedule next check in 1 second
        self.root.after(1000, self._schedule_auto_lock)
    
    def _show_master_password_dialog(self):
        """Show the master password dialog."""
        dialog = MasterPasswordDialog(self.root, self.vault_manager)
        self.root.wait_window(dialog)
        
        if dialog.result:
            self._unlock_vault()
        else:
            self._lock_vault()
    
    def _unlock_vault(self):
        """Unlock the vault and update UI state."""
        self._locked = False
        self._last_activity = asyncio.get_event_loop().time()
        self.vault_tab.refresh_entries()
        self.settings_tab.update_state()
    
    def _lock_vault(self):
        """Lock the vault and update UI state."""
        self._locked = True
        self.vault_manager.lock_vault()
        self.vault_tab.clear_entries()
        self.settings_tab.update_state()
    
    def schedule_clipboard_clear(self, text: str):
        """Schedule clearing of clipboard after timeout."""
        timeout = self.config.get('clipboard_timeout', 30) * 1000  # Convert to milliseconds
        
        # Cancel existing task if any
        if text in self._clipboard_tasks:
            self.root.after_cancel(self._clipboard_tasks[text])
        
        # Schedule new task
        task_id = self.root.after(timeout, lambda: self._clear_clipboard(text))
        self._clipboard_tasks[text] = task_id
    
    def _clear_clipboard(self, text: str):
        """Clear the clipboard if it still contains the specified text."""
        try:
            current = self.root.clipboard_get()
            if current == text:
                self.root.clipboard_clear()
        except:
            pass
        finally:
            if text in self._clipboard_tasks:
                del self._clipboard_tasks[text]
    
    def show_error(self, message: str):
        """Show an error message to the user."""
        messagebox.showerror("Error", message)
    
    def show_info(self, message: str):
        """Show an info message to the user."""
        messagebox.showinfo("Information", message)
    
    def show_warning(self, message: str):
        """Show a warning message to the user."""
        messagebox.showwarning("Warning", message) 