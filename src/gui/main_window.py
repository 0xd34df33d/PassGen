import logging
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QTabWidget,
    QMessageBox, QInputDialog, QAction
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QIcon
from src.gui.tabs import GeneratorTab, VaultTab, SettingsTab
from src.core.vault_manager import VaultManager
from src.core.password_generator import PasswordGenerator
from src.utils.config import Config
import os

logger = logging.getLogger(__name__)

class MainWindow(QMainWindow):
    def __init__(self, vault_manager: VaultManager, password_generator: PasswordGenerator, config: Config):
        """Initialize the main window."""
        super().__init__()
        logger.info("Initializing main window")
        
        self.vault_manager = vault_manager
        self.password_generator = password_generator
        self.config = config
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        self.setCentralWidget(self.tab_widget)
        
        # Create tabs
        self.generator_tab = GeneratorTab(password_generator)
        self.vault_tab = VaultTab(vault_manager)
        self.settings_tab = SettingsTab(vault_manager, config)
        
        # Add tabs to widget
        self.tab_widget.addTab(self.generator_tab, "Password Generator")
        self.tab_widget.addTab(self.vault_tab, "Vault")
        self.tab_widget.addTab(self.settings_tab, "Settings")
        
        # Connect vault signals
        self.vault_tab.vault_locked.connect(self._on_vault_locked)
        self.vault_tab.vault_unlocked.connect(self._on_vault_unlocked)
        
        # Create menu bar
        self._create_menu_bar()
        
        # Create status bar
        self.statusBar().showMessage("Ready")
        
        # Set window properties
        self.setWindowTitle("PassGen Password Manager")
        self.setMinimumSize(800, 600)
        
        # Set window icon
        icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'passgen.ico')
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
            logger.info(f"Window icon set from {icon_path}")
        else:
            logger.warning(f"Window icon not found at {icon_path}")
        
        # Setup auto-lock timer
        logger.debug("Setting up auto-lock timer")
        self.auto_lock_timer = QTimer()
        self.auto_lock_timer.timeout.connect(self.auto_lock)
        self.auto_lock_timer.start(self.config.get_auto_lock_timeout() * 1000)
        
        logger.info("Main window initialized successfully")
    
    def _create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)
    
    def _show_about(self):
        """Show the about dialog."""
        QMessageBox.about(
            self,
            "About PassGen",
            "PassGen Password Manager\n\n"
            "A secure password manager for storing and generating passwords.\n"
            "Created by Cody Python\n"
            "Version 1.0.0"
        )
    
    def auto_lock(self):
        """Lock the vault after timeout."""
        logger.info("Auto-locking vault due to inactivity")
        if not self.vault_manager._locked:
            self.vault_manager.lock_vault()
            self.vault_tab.on_vault_locked()
            QMessageBox.information(
                self,
                "Vault Locked",
                "The vault has been automatically locked due to inactivity."
            )
    
    def _on_vault_locked(self):
        """Handle vault locked event."""
        logger.info("Vault locked")
        self.auto_lock_timer.stop()
    
    def _on_vault_unlocked(self):
        """Handle vault unlocked event."""
        logger.info("Vault unlocked")
        # Reset and start auto-lock timer
        timeout = self.config.get_auto_lock_timeout()  # Already in seconds from Config
        self.auto_lock_timer.start(timeout)
        logger.debug(f"Auto-lock timer started with {timeout//60} minutes timeout")
    
    def closeEvent(self, event):
        """Handle window close event."""
        logger.info("Application closing")
        self.vault_manager.lock_vault()
        event.accept() 