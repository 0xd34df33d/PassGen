import logging
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QSlider, QCheckBox, QLineEdit,
    QTreeWidget, QTreeWidgetItem, QMessageBox,
    QInputDialog, QSpinBox, QComboBox, QMenu,
    QGroupBox, QTabWidget, QDialog, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, QPoint, QTimer
from PyQt5.QtGui import QPalette, QColor
from src.core.vault_manager import VaultManager
from src.core.password_generator import PasswordGenerator
from src.utils.config import Config
from .dialogs import EntryDialog

logger = logging.getLogger(__name__)

class GeneratorTab(QWidget):
    def __init__(self, password_generator: PasswordGenerator):
        """Initialize the password generator tab."""
        super().__init__()
        logger.info("Initializing password generator tab")
        self.password_generator = password_generator
        self.config = Config()
        self._setup_ui()
        logger.info("Password generator tab initialized successfully")
    
    def _setup_ui(self):
        """Setup the user interface."""
        logger.debug("Setting up generator tab UI")
        layout = QVBoxLayout(self)
        
        # Password length slider
        length_layout = QHBoxLayout()
        self.length_label = QLabel("Password Length:")
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setMinimum(8)
        self.length_slider.setMaximum(64)
        self.length_slider.setValue(16)
        self.length_value = QLabel("16")
        self.length_slider.valueChanged.connect(
            lambda v: self.length_value.setText(str(v))
        )
        length_layout.addWidget(self.length_label)
        length_layout.addWidget(self.length_slider)
        length_layout.addWidget(self.length_value)
        layout.addLayout(length_layout)
        
        # Character set options
        self.use_uppercase = QCheckBox("Use Uppercase Letters")
        self.use_uppercase.setChecked(True)
        self.use_digits = QCheckBox("Use Digits")
        self.use_digits.setChecked(True)
        self.use_symbols = QCheckBox("Use Special Characters")
        self.use_symbols.setChecked(True)
        self.avoid_ambiguous = QCheckBox("Avoid Ambiguous Characters")
        self.avoid_ambiguous.setChecked(True)
        
        layout.addWidget(self.use_uppercase)
        layout.addWidget(self.use_digits)
        layout.addWidget(self.use_symbols)
        layout.addWidget(self.avoid_ambiguous)
        
        # Generate button
        self.generate_btn = QPushButton("Generate Password")
        self.generate_btn.clicked.connect(self._generate_password)
        layout.addWidget(self.generate_btn)
        
        # Password preview
        self.password_preview = QLineEdit()
        self.password_preview.setReadOnly(True)
        layout.addWidget(self.password_preview)
        
        # Entropy display
        self.entropy_label = QLabel("Entropy: 0 bits")
        layout.addWidget(self.entropy_label)
        
        # Passphrase options
        passphrase_layout = QHBoxLayout()
        self.word_count = QSpinBox()
        self.word_count.setMinimum(3)
        self.word_count.setMaximum(10)
        self.word_count.setValue(4)
        self.separator = QComboBox()
        self.separator.addItems(["-", "_", " ", "."])
        self.capitalize = QCheckBox("Capitalize Words")
        self.capitalize.setChecked(True)
        
        self.word_count_label = QLabel("Word Count:")
        self.separator_label = QLabel("Separator:")
        
        passphrase_layout.addWidget(self.word_count_label)
        passphrase_layout.addWidget(self.word_count)
        passphrase_layout.addWidget(self.separator_label)
        passphrase_layout.addWidget(self.separator)
        passphrase_layout.addWidget(self.capitalize)
        
        layout.addLayout(passphrase_layout)
        
        # Generate passphrase button
        self.generate_passphrase_btn = QPushButton("Generate Passphrase")
        self.generate_passphrase_btn.clicked.connect(self._generate_passphrase)
        layout.addWidget(self.generate_passphrase_btn)
        
        # Passphrase preview
        self.passphrase_preview = QLineEdit()
        self.passphrase_preview.setReadOnly(True)
        layout.addWidget(self.passphrase_preview)
        
        # Status label
        self.status_label = QLabel()
        layout.addWidget(self.status_label)
        
        logger.debug("Generator tab UI setup complete")
    
    def _generate_password(self):
        """Generate and display a password based on current settings."""
        try:
            password = self.password_generator.generate_password(
                length=self.length_slider.value(),
                use_uppercase=self.use_uppercase.isChecked(),
                use_lowercase=True,
                use_digits=self.use_digits.isChecked(),
                use_symbols=self.use_symbols.isChecked(),
                avoid_ambiguous=self.avoid_ambiguous.isChecked()
            )
            self.password_preview.setText(password)
            QApplication.clipboard().setText(password)
            timeout = self.config.get('clear_clipboard_timeout', 30) * 1000
            self.status_label.setText(f"Password copied to clipboard! Will be cleared in {timeout//1000} seconds.")
            QTimer.singleShot(timeout, lambda: self._clear_clipboard(password))
        except Exception as e:
            self.password_preview.setText(f"Error: {str(e)}")
    
    def _generate_passphrase(self):
        """Generate and display a passphrase based on current settings."""
        try:
            passphrase = self.password_generator.generate_passphrase(
                word_count=self.word_count.value(),
                separator=self.separator.currentText(),
                capitalize=self.capitalize.isChecked()
            )
            self.passphrase_preview.setText(passphrase)
            QApplication.clipboard().setText(passphrase)
            timeout = self.config.get('clear_clipboard_timeout', 30) * 1000
            self.status_label.setText(f"Passphrase copied to clipboard! Will be cleared in {timeout//1000} seconds.")
            QTimer.singleShot(timeout, lambda: self._clear_clipboard(passphrase))
        except Exception as e:
            self.passphrase_preview.setText(f"Error: {str(e)}")

    def _clear_clipboard(self, text):
        """Clear the clipboard if it still contains the specified text."""
        if QApplication.clipboard().text() == text:
            QApplication.clipboard().clear()
            self.status_label.setText("Clipboard cleared for security.")

    def update_language(self, translations):
        """Update the language of all UI elements."""
        try:
            # Update labels
            self.length_label.setText(translations.get("Password Length:", "Password Length:"))
            self.word_count_label.setText(translations.get("Word Count:", "Word Count:"))
            self.separator_label.setText(translations.get("Separator:", "Separator:"))
            self.entropy_label.setText(translations.get("Entropy:", "Entropy:") + " 0 " + translations.get("bits", "bits"))
            
            # Update checkboxes
            self.use_uppercase.setText(translations.get("Use Uppercase Letters", "Use Uppercase Letters"))
            self.use_digits.setText(translations.get("Use Digits", "Use Digits"))
            self.use_symbols.setText(translations.get("Use Special Characters", "Use Special Characters"))
            self.avoid_ambiguous.setText(translations.get("Avoid Ambiguous Characters", "Avoid Ambiguous Characters"))
            self.capitalize.setText(translations.get("Capitalize Words", "Capitalize Words"))
            
            # Update buttons
            self.generate_btn.setText(translations.get("Generate Password", "Generate Password"))
            self.generate_passphrase_btn.setText(translations.get("Generate Passphrase", "Generate Passphrase"))
        except Exception as e:
            logger.error(f"Failed to update generator tab language: {str(e)}")

class VaultTab(QWidget):
    vault_locked = pyqtSignal()
    vault_unlocked = pyqtSignal()
    
    def __init__(self, vault_manager: VaultManager):
        """Initialize the vault tab."""
        super().__init__()
        logger.info("Initializing vault tab")
        self.vault_manager = vault_manager
        self.config = Config()
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.timeout.connect(self._lock_vault)
        self._setup_ui()
        logger.info("Vault tab initialized successfully")
    
    def _setup_ui(self):
        """Setup the user interface."""
        logger.debug("Setting up vault tab UI")
        layout = QVBoxLayout(self)
        
        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search entries...")
        self.search_input.textChanged.connect(self._search_entries)
        search_layout.addWidget(self.search_input)
        layout.addLayout(search_layout)
        
        # Entries tree
        self.entries_tree = QTreeWidget()
        self.entries_tree.setHeaderLabels(["Title", "Username", "URL"])
        self.entries_tree.itemDoubleClicked.connect(self._edit_entry)
        layout.addWidget(self.entries_tree)
        
        # Buttons
        button_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add Entry")
        self.add_btn.clicked.connect(self._add_entry)
        self.edit_btn = QPushButton("Edit Entry")
        self.edit_btn.clicked.connect(self._edit_entry)
        self.delete_btn = QPushButton("Delete Entry")
        self.delete_btn.clicked.connect(self._delete_entry)
        self.lock_btn = QPushButton("Lock Vault")
        self.lock_btn.clicked.connect(self._lock_vault)
        self.unlock_btn = QPushButton("Unlock Vault")
        self.unlock_btn.clicked.connect(self._unlock_vault)
        
        button_layout.addWidget(self.add_btn)
        button_layout.addWidget(self.edit_btn)
        button_layout.addWidget(self.delete_btn)
        button_layout.addWidget(self.lock_btn)
        button_layout.addWidget(self.unlock_btn)
        layout.addLayout(button_layout)
        
        # Initial state
        self._update_entries()
        self._set_buttons_enabled(False)
        
        logger.debug("Vault tab UI setup complete")
    
    def _unlock_vault(self):
        """Unlock the vault."""
        logger.info("Attempting to unlock vault")
        from .dialogs import UnlockDialog
        dialog = UnlockDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            password = dialog.get_password()
            if self.vault_manager.unlock_vault(password):
                logger.info("Vault unlocked successfully")
                self._set_buttons_enabled(True)
                self._update_entries()
                self.vault_unlocked.emit()
                timeout = self.config.get_auto_lock_timeout()  # Already in seconds from Config
                self.auto_lock_timer.start(timeout)
                logger.debug(f"Auto-lock timer started with {timeout//60} minutes timeout")
            else:
                logger.warning("Failed to unlock vault")
                QMessageBox.warning(
                    self,
                    "Error",
                    "Failed to unlock vault. Please check your master password."
                )
    
    def _update_entries(self):
        """Update the entries tree with current vault contents."""
        logger.debug("Updating entries display")
        self.entries_tree.clear()
        
        try:
            entries = self.vault_manager.get_entries()
            for entry in entries:
                item = QTreeWidgetItem([
                    entry['title'],
                    entry['username'],
                    entry['url']
                ])
                item.setData(0, Qt.UserRole, entry['id'])
                self.entries_tree.addTopLevelItem(item)
            logger.debug(f"Displayed {len(entries)} entries")
        except Exception as e:
            logger.error(f"Failed to update entries: {e}")
            QMessageBox.critical(
                self,
                "Error",
                "Failed to update entries. Please try unlocking the vault again."
            )
    
    def _search_entries(self, query: str):
        """Search entries in the vault."""
        logger.debug(f"Searching entries for: {query}")
        self.entries_tree.clear()
        
        try:
            entries = self.vault_manager.search_entries(query)
            for entry in entries:
                item = QTreeWidgetItem([
                    entry['title'],
                    entry['username'],
                    entry['url']
                ])
                item.setData(0, Qt.UserRole, entry['id'])
                self.entries_tree.addTopLevelItem(item)
            logger.debug(f"Found {len(entries)} matching entries")
        except Exception as e:
            logger.error(f"Failed to search entries: {e}", exc_info=True)
    
    def _add_entry(self):
        """Add a new entry to the vault."""
        logger.info("Adding new entry")
        try:
            from .dialogs import EntryDialog
            dialog = EntryDialog(self)
            if dialog.exec_() == QDialog.Accepted:
                entry_data = dialog.get_entry_data()
                if self.vault_manager.add_entry(**entry_data):
                    self._update_entries()
                    logger.info("Entry added successfully")
                else:
                    logger.error("Failed to add entry")
                    QMessageBox.critical(
                        self,
                        "Error",
                        "Failed to add entry. Please try again."
                    )
        except Exception as e:
            logger.error(f"Failed to add entry: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "Error",
                "An error occurred while adding the entry."
            )
    
    def _edit_entry(self):
        """Edit the selected entry."""
        logger.info("Editing entry")
        selected_items = self.entries_tree.selectedItems()
        if not selected_items:
            return
            
        try:
            entry_id = selected_items[0].data(0, Qt.UserRole)
            entries = self.vault_manager.get_entries()
            entry = next(e for e in entries if e['id'] == entry_id)
            
            from .dialogs import EntryDialog
            dialog = EntryDialog(self, entry)
            if dialog.exec_() == QDialog.Accepted:
                entry_data = dialog.get_entry_data()
                if self.vault_manager.update_entry(entry_id, **entry_data):
                    self._update_entries()
                    logger.info("Entry updated successfully")
                else:
                    logger.error("Failed to update entry")
                    QMessageBox.critical(
                        self,
                        "Error",
                        "Failed to update entry. Please try again."
                    )
        except Exception as e:
            logger.error(f"Failed to edit entry: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "Error",
                "An error occurred while editing the entry."
            )
    
    def _delete_entry(self):
        """Delete the selected entry."""
        logger.info("Deleting entry")
        selected_items = self.entries_tree.selectedItems()
        if not selected_items:
            return
            
        try:
            entry_id = selected_items[0].data(0, Qt.UserRole)
            reply = QMessageBox.question(
                self,
                "Confirm Delete",
                "Are you sure you want to delete this entry?",
                QMessageBox.Yes | QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                if self.vault_manager.delete_entry(entry_id):
                    self._update_entries()
                    logger.info("Entry deleted successfully")
                else:
                    logger.error("Failed to delete entry")
                    QMessageBox.critical(
                        self,
                        "Error",
                        "Failed to delete entry. Please try again."
                    )
        except Exception as e:
            logger.error(f"Failed to delete entry: {e}", exc_info=True)
            QMessageBox.critical(
                self,
                "Error",
                "An error occurred while deleting the entry."
            )
    
    def _lock_vault(self):
        """Lock the vault."""
        logger.info("Locking vault")
        self.vault_manager.lock_vault()
        self._set_buttons_enabled(False)
        self.entries_tree.clear()
        self.auto_lock_timer.stop()
        self.vault_locked.emit()
    
    def _set_buttons_enabled(self, enabled: bool):
        """Enable or disable buttons based on vault state."""
        logger.debug(f"Setting buttons enabled: {enabled}")
        self.add_btn.setEnabled(enabled)
        self.edit_btn.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)
        self.lock_btn.setEnabled(enabled)
        self.unlock_btn.setEnabled(not enabled)
    
    def on_vault_locked(self):
        """Handle vault locked event."""
        logger.info("Vault locked")
        self._set_buttons_enabled(False)
        self.entries_tree.clear()
    
    def on_vault_unlocked(self):
        """Handle vault unlocked event."""
        logger.info("Vault unlocked")
        self._set_buttons_enabled(True)
        self._update_entries()
        self.vault_unlocked.emit()
        timeout = self.config.get_auto_lock_timeout()  # Already in seconds from Config
        self.auto_lock_timer.start(timeout)
        logger.debug(f"Auto-lock timer started with {timeout//60} minutes timeout")

    def update_language(self, translations):
        """Update the language of all UI elements."""
        try:
            # Update search placeholder
            self.search_input.setPlaceholderText(translations.get("Search entries...", "Search entries..."))
            
            # Update buttons
            self.add_btn.setText(translations.get("Add Entry", "Add Entry"))
            self.edit_btn.setText(translations.get("Edit Entry", "Edit Entry"))
            self.delete_btn.setText(translations.get("Delete Entry", "Delete Entry"))
            self.lock_btn.setText(translations.get("Lock Vault", "Lock Vault"))
            self.unlock_btn.setText(translations.get("Unlock Vault", "Unlock Vault"))
        except Exception as e:
            logger.error(f"Failed to update vault tab language: {str(e)}")

    def mousePressEvent(self, event):
        """Reset auto-lock timer on user activity."""
        super().mousePressEvent(event)
        if self.vault_manager.is_unlocked():
            timeout = self.config.get_auto_lock_timeout()  # Already in seconds from Config
            self.auto_lock_timer.start(timeout)
            logger.debug(f"Auto-lock timer reset to {timeout//60} minutes due to user activity")

    def keyPressEvent(self, event):
        """Reset auto-lock timer on user activity."""
        super().keyPressEvent(event)
        if self.vault_manager.is_unlocked():
            timeout = self.config.get_auto_lock_timeout()  # Already in seconds from Config
            self.auto_lock_timer.start(timeout)
            logger.debug(f"Auto-lock timer reset to {timeout//60} minutes due to user activity")

class SettingsTab(QWidget):
    def __init__(self, vault_manager, config):
        super().__init__()
        self.vault_manager = vault_manager
        self.config = config
        logger.info("Initializing settings tab")
        
        # Create layout
        layout = QVBoxLayout()
        
        # Master Password Section
        self.master_pass_group = QGroupBox("Master Password")
        master_pass_layout = QVBoxLayout()
        
        # Old password (only show if vault exists)
        self.old_pass_layout = QHBoxLayout()
        self.old_pass_label = QLabel("Current Password:")
        self.old_password = QLineEdit()
        self.old_password.setEchoMode(QLineEdit.Password)
        self.old_pass_layout.addWidget(self.old_pass_label)
        self.old_pass_layout.addWidget(self.old_password)
        
        # New password
        new_pass_layout = QHBoxLayout()
        new_pass_label = QLabel("New Password:")
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        new_pass_layout.addWidget(new_pass_label)
        new_pass_layout.addWidget(self.new_password)
        
        # Confirm password
        confirm_pass_layout = QHBoxLayout()
        confirm_pass_label = QLabel("Confirm Password:")
        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        confirm_pass_layout.addWidget(confirm_pass_label)
        confirm_pass_layout.addWidget(self.confirm_password)
        
        # Change password button
        self.change_pass_btn = QPushButton("Set Password")
        self.change_pass_btn.clicked.connect(self._change_master_password)
        
        # Add layouts to master password group
        master_pass_layout.addLayout(new_pass_layout)
        master_pass_layout.addLayout(confirm_pass_layout)
        master_pass_layout.addWidget(self.change_pass_btn)
        self.master_pass_group.setLayout(master_pass_layout)
        
        # Update UI based on vault existence
        if self.vault_manager.vault_path.exists():
            master_pass_layout.insertLayout(0, self.old_pass_layout)
            self.change_pass_btn.setText("Change Password")
        
        # Security Settings Section
        security_group = QGroupBox("Security")
        security_layout = QVBoxLayout()
        
        # Auto-lock timeout
        timeout_layout = QHBoxLayout()
        timeout_label = QLabel("Auto-lock timeout (minutes):")
        self.timeout_spinbox = QSpinBox()
        self.timeout_spinbox.setRange(1, 60)
        self.timeout_spinbox.setValue(self.config.get('auto_lock_timeout', 15))
        self.timeout_spinbox.valueChanged.connect(self._update_timeout)
        timeout_layout.addWidget(timeout_label)
        timeout_layout.addWidget(self.timeout_spinbox)
        
        # Clear clipboard
        clear_clip_layout = QHBoxLayout()
        clear_clip_label = QLabel("Clear clipboard after (seconds):")
        self.clear_clip_spinbox = QSpinBox()
        self.clear_clip_spinbox.setRange(0, 300)
        self.clear_clip_spinbox.setValue(self.config.get('clear_clipboard_timeout', 30))
        self.clear_clip_spinbox.valueChanged.connect(self._update_clipboard_timeout)
        clear_clip_layout.addWidget(clear_clip_label)
        clear_clip_layout.addWidget(self.clear_clip_spinbox)
        
        security_layout.addLayout(timeout_layout)
        security_layout.addLayout(clear_clip_layout)
        security_group.setLayout(security_layout)
        
        # Theme Settings Section
        theme_group = QGroupBox("Theme")
        theme_layout = QVBoxLayout()
        
        # Theme selector
        theme_selector_layout = QHBoxLayout()
        theme_label = QLabel("Theme:")
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Light", "Dark", "System"])
        self.theme_combo.setCurrentText(self.config.get('theme', 'System'))
        self.theme_combo.currentTextChanged.connect(self._update_theme)
        theme_selector_layout.addWidget(theme_label)
        theme_selector_layout.addWidget(self.theme_combo)
        
        theme_layout.addLayout(theme_selector_layout)
        theme_group.setLayout(theme_layout)
        
        # Add all sections to main layout
        layout.addWidget(self.master_pass_group)
        layout.addWidget(security_group)
        layout.addWidget(theme_group)
        layout.addStretch()
        
        self.setLayout(layout)
        
        # Apply current theme
        self._apply_theme(self.config.get('theme', 'System'))
        
        logger.info("Settings tab initialized successfully")
    
    def _update_theme(self, theme):
        """Update theme setting."""
        try:
            self.config.set('theme', theme)
            logger.info(f"Theme updated to {theme}")
            self._apply_theme(theme)
        except Exception as e:
            logger.error(f"Failed to update theme: {str(e)}")
    
    def _apply_theme(self, theme):
        """Apply theme to the application."""
        try:
            app = QApplication.instance()
            
            if theme == "Dark":
                app.setStyle("Fusion")
                dark_palette = QPalette()
                dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
                dark_palette.setColor(QPalette.Base, QColor(35, 35, 35))
                dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
                dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
                dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
                dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
                dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
                dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
                dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
                dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
                dark_palette.setColor(QPalette.HighlightedText, QColor(35, 35, 35))
                app.setPalette(dark_palette)
            elif theme == "Light":
                app.setStyle("Fusion")
                light_palette = QPalette()
                light_palette.setColor(QPalette.Window, QColor(240, 240, 240))
                light_palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
                light_palette.setColor(QPalette.Base, QColor(255, 255, 255))
                light_palette.setColor(QPalette.AlternateBase, QColor(245, 245, 245))
                light_palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
                light_palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
                light_palette.setColor(QPalette.Text, QColor(0, 0, 0))
                light_palette.setColor(QPalette.Button, QColor(240, 240, 240))
                light_palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
                light_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
                light_palette.setColor(QPalette.Link, QColor(0, 0, 255))
                light_palette.setColor(QPalette.Highlight, QColor(0, 120, 215))
                light_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
                app.setPalette(light_palette)
            else:  # System
                app.setStyle("")
                app.setPalette(app.style().standardPalette())
            logger.info(f"Theme applied successfully: {theme}")
        except Exception as e:
            logger.error(f"Failed to apply theme: {str(e)}")
            # Fallback to system theme
            app.setStyle("")
            app.setPalette(app.style().standardPalette())
    
    def _update_timeout(self, value):
        """Update auto-lock timeout setting."""
        try:
            self.config.set('auto_lock_timeout', value)
            logger.info(f"Auto-lock timeout updated to {value} minutes")
        except Exception as e:
            logger.error(f"Failed to update auto-lock timeout: {str(e)}")
    
    def _update_clipboard_timeout(self, value):
        """Update clipboard clear timeout setting."""
        try:
            self.config.set('clear_clipboard_timeout', value)
            logger.info(f"Clipboard clear timeout updated to {value} seconds")
        except Exception as e:
            logger.error(f"Failed to update clipboard timeout: {str(e)}")
    
    def _change_master_password(self):
        """Handle master password change."""
        try:
            logger.info("Changing master password")
            new_password = self.new_password.text()
            confirm_password = self.confirm_password.text()
            
            # Basic validation
            if not new_password or not confirm_password:
                QMessageBox.warning(self, "Error", "Please enter and confirm your new password")
                return
            
            if new_password != confirm_password:
                logger.warning("New passwords do not match")
                QMessageBox.warning(self, "Error", "New passwords do not match")
                return
            
            if len(new_password) < 12:
                logger.warning("Password too short")
                QMessageBox.warning(self, "Error", "Password must be at least 12 characters long")
                return
            
            # Check if vault exists
            if self.vault_manager.vault_path.exists():
                # Changing existing password
                old_password = self.old_password.text()
                if not old_password:
                    QMessageBox.warning(self, "Error", "Please enter your current password")
                    return
                
                if self.vault_manager.change_master_password(old_password, new_password):
                    logger.info("Master password changed successfully")
                    QMessageBox.information(self, "Success", "Master password changed successfully")
                    self.old_password.clear()
                    self.new_password.clear()
                    self.confirm_password.clear()
                else:
                    logger.error("Failed to change master password")
                    QMessageBox.critical(self, "Error", "Failed to change master password. Please check your current password.")
            else:
                # Setting initial password
                if self.vault_manager.set_initial_password(new_password):
                    logger.info("Initial master password set successfully")
                    QMessageBox.information(self, "Success", "Master password set successfully")
                    self.new_password.clear()
                    self.confirm_password.clear()
                    
                    # Update UI to show old password field
                    master_pass_layout = self.master_pass_group.layout()
                    master_pass_layout.insertLayout(0, self.old_pass_layout)
                    self.change_pass_btn.setText("Change Password")
                else:
                    logger.error("Failed to set initial master password")
                    QMessageBox.critical(self, "Error", "Failed to set master password")
        except Exception as e:
            logger.error(f"Failed to change master password: {e}", exc_info=True)
            QMessageBox.critical(self, "Error", "An error occurred while changing the master password") 