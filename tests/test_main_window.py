import pytest
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QPushButton, QSpinBox, QLineEdit, QListWidget, QMessageBox
from PyQt5.QtTest import QTest
from passgen.gui.main_window import MainWindow
from passgen.core.vault_manager import VaultManager
from passgen.core.password_generator import PasswordGenerator
from passgen.utils.config import Config

@pytest.fixture
def app(qtbot):
    """Create the QApplication instance."""
    config = Config()
    vault_manager = VaultManager(config)
    password_generator = PasswordGenerator()
    window = MainWindow(vault_manager, password_generator, config)
    qtbot.addWidget(window)
    return window

def test_window_title(app):
    """Test that the window title is set correctly."""
    assert "PassGen Password Manager" in app.windowTitle()

def test_password_generation(app, qtbot):
    """Test password generation through the GUI."""
    # Find the generate password button and length input
    generate_button = app.findChild(QPushButton, "generate_button")
    length_input = app.findChild(QSpinBox, "length_input")
    password_display = app.findChild(QLineEdit, "password_display")
    
    # Set password length
    qtbot.setValue(length_input, 16)
    
    # Click generate button
    qtbot.mouseClick(generate_button, Qt.LeftButton)
    
    # Verify password was generated
    assert len(password_display.text()) == 16

def test_vault_creation(app, qtbot):
    """Test vault creation through the GUI."""
    # Find the create vault button and password input
    create_button = app.findChild(QPushButton, "create_vault_button")
    password_input = app.findChild(QLineEdit, "master_password_input")
    
    # Enter master password
    qtbot.keyClicks(password_input, "test_master_password")
    
    # Click create button
    qtbot.mouseClick(create_button, Qt.LeftButton)
    
    # Verify vault was created
    assert app.vault_manager.vault_exists()

def test_add_password_entry(app, qtbot):
    """Test adding a new password entry through the GUI."""
    # First create a vault
    test_vault_creation(app, qtbot)
    
    # Find input fields
    site_input = app.findChild(QLineEdit, "site_input")
    username_input = app.findChild(QLineEdit, "username_input")
    password_input = app.findChild(QLineEdit, "entry_password_input")
    add_button = app.findChild(QPushButton, "add_entry_button")
    
    # Enter entry details
    qtbot.keyClicks(site_input, "test_site")
    qtbot.keyClicks(username_input, "test_user")
    qtbot.keyClicks(password_input, "test_password")
    
    # Add entry
    qtbot.mouseClick(add_button, Qt.LeftButton)
    
    # Verify entry was added
    entries = app.vault_manager.get_entries("test_master_password")
    assert any(e["site"] == "test_site" for e in entries)

def test_search_functionality(app, qtbot):
    """Test the search functionality."""
    # First add some entries
    test_add_password_entry(app, qtbot)
    
    # Find search input
    search_input = app.findChild(QLineEdit, "search_input")
    
    # Perform search
    qtbot.keyClicks(search_input, "test_site")
    
    # Verify search results
    results_list = app.findChild(QListWidget, "entries_list")
    assert results_list.count() == 1
    assert "test_site" in results_list.item(0).text()

def test_copy_password_to_clipboard(app, qtbot):
    """Test copying password to clipboard."""
    # First add an entry
    test_add_password_entry(app, qtbot)
    
    # Find and click the copy button for the entry
    copy_button = app.findChild(QPushButton, "copy_password_button")
    qtbot.mouseClick(copy_button, Qt.LeftButton)
    
    # Get clipboard content
    clipboard = app.clipboard()
    assert clipboard.text() == "test_password"
    
    # Verify clipboard is cleared after timeout
    QTest.qWait(31000)  # Wait 31 seconds (30 second timeout + 1 second buffer)
    assert clipboard.text() == ""

def test_error_handling_invalid_master_password(app, qtbot, monkeypatch):
    """Test error handling when invalid master password is entered."""
    def mock_error_dialog(*args, **kwargs):
        return QMessageBox.Ok
    
    monkeypatch.setattr(QMessageBox, "critical", mock_error_dialog)
    
    # Create vault first
    test_vault_creation(app, qtbot)
    
    # Try to unlock with wrong password
    password_input = app.findChild(QLineEdit, "master_password_input")
    unlock_button = app.findChild(QPushButton, "unlock_button")
    
    qtbot.keyClicks(password_input, "wrong_password")
    qtbot.mouseClick(unlock_button, Qt.LeftButton)
    
    # Verify error handling
    assert not app.vault_manager.is_unlocked()
    assert password_input.text() == ""  # Password field should be cleared

def test_password_strength_indicator(app, qtbot):
    """Test the password strength indicator."""
    # Find password input and strength indicator
    password_input = app.findChild(QLineEdit, "new_password_input")
    strength_label = app.findChild(QLabel, "strength_indicator")
    
    # Test weak password
    qtbot.keyClicks(password_input, "weak")
    assert "Weak" in strength_label.text()
    assert "red" in strength_label.styleSheet()
    
    # Clear and test strong password
    password_input.clear()
    qtbot.keyClicks(password_input, "StrongP@ssw0rd123!")
    assert "Strong" in strength_label.text()
    assert "green" in strength_label.styleSheet()

def test_auto_lock_timeout(app, qtbot):
    """Test that vault auto-locks after timeout."""
    # First unlock the vault
    test_vault_creation(app, qtbot)
    
    # Verify vault is unlocked
    assert app.vault_manager.is_unlocked()
    
    # Wait for auto-lock timeout
    QTest.qWait(301000)  # 5 minutes + 1 second buffer
    
    # Verify vault is locked
    assert not app.vault_manager.is_unlocked()
    assert not app.findChild(QWidget, "entries_list").isVisible()

def test_password_generator_options(app, qtbot):
    """Test password generator option toggles."""
    # Find option checkboxes
    uppercase_check = app.findChild(QCheckBox, "use_uppercase")
    lowercase_check = app.findChild(QCheckBox, "use_lowercase")
    numbers_check = app.findChild(QCheckBox, "use_numbers")
    special_check = app.findChild(QCheckBox, "use_special")
    generate_button = app.findChild(QPushButton, "generate_button")
    password_display = app.findChild(QLineEdit, "password_display")
    
    # Test with only numbers
    uppercase_check.setChecked(False)
    lowercase_check.setChecked(False)
    special_check.setChecked(False)
    numbers_check.setChecked(True)
    
    qtbot.mouseClick(generate_button, Qt.LeftButton)
    generated = password_display.text()
    assert all(c.isdigit() for c in generated)
    
    # Test with custom special characters
    special_chars_input = app.findChild(QLineEdit, "special_chars_input")
    qtbot.keyClicks(special_chars_input, "#@!")
    special_check.setChecked(True)
    
    qtbot.mouseClick(generate_button, Qt.LeftButton)
    generated = password_display.text()
    special_chars = [c for c in generated if not c.isalnum()]
    assert all(c in "#@!" for c in special_chars)

def test_search_with_filters(app, qtbot):
    """Test search functionality with different filters."""
    # Add multiple test entries
    test_vault_creation(app, qtbot)
    add_test_entries(app, qtbot)
    
    search_input = app.findChild(QLineEdit, "search_input")
    results_list = app.findChild(QListWidget, "entries_list")
    
    # Test site filter
    site_filter = app.findChild(QRadioButton, "filter_site")
    site_filter.setChecked(True)
    qtbot.keyClicks(search_input, "test")
    assert results_list.count() == 1
    
    # Test username filter
    username_filter = app.findChild(QRadioButton, "filter_username")
    username_filter.setChecked(True)
    search_input.clear()
    qtbot.keyClicks(search_input, "user")
    assert results_list.count() > 1

def add_test_entries(app, qtbot):
    """Helper function to add multiple test entries."""
    entries = [
        ("test_site", "test_user", "test_pass"),
        ("example.com", "user123", "pass123"),
        ("github.com", "devuser", "devpass")
    ]
    
    for site, username, password in entries:
        site_input = app.findChild(QLineEdit, "site_input")
        username_input = app.findChild(QLineEdit, "username_input")
        password_input = app.findChild(QLineEdit, "entry_password_input")
        add_button = app.findChild(QPushButton, "add_entry_button")
        
        qtbot.keyClicks(site_input, site)
        qtbot.keyClicks(username_input, username)
        qtbot.keyClicks(password_input, password)
        qtbot.mouseClick(add_button, Qt.LeftButton) 