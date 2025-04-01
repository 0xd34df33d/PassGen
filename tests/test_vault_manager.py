import unittest
import tempfile
import os
from pathlib import Path
import json
from passgen.core.vault_manager import VaultManager
from passgen.utils.config import Config

class TestVaultManager(unittest.TestCase):
    def setUp(self):
        """Set up a temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.config = Config()
        self.config.vault_path = Path(self.temp_dir) / "test_vault.enc"
        self.vault_manager = VaultManager(self.config)

    def tearDown(self):
        """Clean up temporary files after tests."""
        if os.path.exists(self.config.vault_path):
            os.remove(self.config.vault_path)
        os.rmdir(self.temp_dir)

    def test_create_vault(self):
        """Test creating a new vault."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        self.assertTrue(self.config.vault_path.exists(), "Vault file should be created")

    def test_add_and_retrieve_entry(self):
        """Test adding and retrieving a password entry."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add a test entry
        self.vault_manager.add_entry(
            master_password,
            "test_site",
            "test_username",
            "test_password"
        )
        
        # Retrieve the entry
        entry = self.vault_manager.get_entry(master_password, "test_site")
        self.assertIsNotNone(entry, "Entry should be retrievable")
        self.assertEqual(entry["username"], "test_username")
        self.assertEqual(entry["password"], "test_password")

    def test_invalid_master_password(self):
        """Test that invalid master password is rejected."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        with self.assertRaises(ValueError):
            self.vault_manager.get_entry("wrong_password", "test_site")

    def test_update_entry(self):
        """Test updating an existing password entry."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add initial entry
        self.vault_manager.add_entry(
            master_password,
            "test_site",
            "test_username",
            "test_password"
        )
        
        # Update the entry
        self.vault_manager.update_entry(
            master_password,
            "test_site",
            "new_username",
            "new_password"
        )
        
        # Verify update
        entry = self.vault_manager.get_entry(master_password, "test_site")
        self.assertEqual(entry["username"], "new_username")
        self.assertEqual(entry["password"], "new_password")

    def test_delete_entry(self):
        """Test deleting a password entry."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add an entry
        self.vault_manager.add_entry(
            master_password,
            "test_site",
            "test_username",
            "test_password"
        )
        
        # Delete the entry
        self.vault_manager.delete_entry(master_password, "test_site")
        
        # Verify deletion
        with self.assertRaises(KeyError):
            self.vault_manager.get_entry(master_password, "test_site")

    def test_list_entries(self):
        """Test listing all entries in the vault."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add multiple entries
        test_entries = [
            ("site1", "user1", "pass1"),
            ("site2", "user2", "pass2"),
            ("site3", "user3", "pass3")
        ]
        
        for site, username, password in test_entries:
            self.vault_manager.add_entry(
                master_password,
                site,
                username,
                password
            )
        
        # Get all entries
        entries = self.vault_manager.get_entries(master_password)
        self.assertEqual(len(entries), len(test_entries))
        
        # Verify each entry exists
        for site, username, password in test_entries:
            entry = self.vault_manager.get_entry(master_password, site)
            self.assertEqual(entry["username"], username)
            self.assertEqual(entry["password"], password)

    def test_change_master_password(self):
        """Test changing the master password."""
        old_password = "old_master_password"
        new_password = "new_master_password"
        
        self.vault_manager.create_vault(old_password)
        
        # Add some entries
        self.vault_manager.add_entry(old_password, "test_site", "test_user", "test_pass")
        
        # Change master password
        self.vault_manager.change_master_password(old_password, new_password)
        
        # Verify old password no longer works
        with self.assertRaises(ValueError):
            self.vault_manager.get_entries(old_password)
        
        # Verify new password works
        entries = self.vault_manager.get_entries(new_password)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["site"], "test_site")

    def test_vault_encryption(self):
        """Test that vault contents are properly encrypted."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add test entry
        self.vault_manager.add_entry(
            master_password,
            "test_site",
            "test_username",
            "test_password"
        )
        
        # Read raw vault file contents
        with open(self.config.vault_path, 'rb') as f:
            encrypted_data = f.read()
        
        # Verify data is encrypted (not plaintext)
        try:
            decoded = json.loads(encrypted_data.decode())
            # If we can decode as JSON, data is not encrypted
            self.fail("Vault data is not encrypted")
        except:
            pass  # Expected - data should be encrypted

    def test_vault_backup(self):
        """Test vault backup functionality."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add test entries
        self.vault_manager.add_entry(master_password, "site1", "user1", "pass1")
        
        # Create backup
        backup_path = self.vault_manager.create_backup()
        self.assertTrue(backup_path.exists())
        
        # Modify original vault
        self.vault_manager.add_entry(master_password, "site2", "user2", "pass2")
        
        # Restore from backup
        self.vault_manager.restore_backup(backup_path, master_password)
        
        # Verify restored state
        entries = self.vault_manager.get_entries(master_password)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["site"], "site1")

    def test_vault_corruption_detection(self):
        """Test detection of corrupted vault files."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Corrupt the vault file
        with open(self.config.vault_path, 'ab') as f:
            f.write(b'corrupt')
        
        # Attempt to read vault
        with self.assertRaises(ValueError):
            self.vault_manager.get_entries(master_password)

    def test_concurrent_access(self):
        """Test handling of concurrent vault access."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Create second vault manager instance
        vault_manager2 = VaultManager(self.config)
        
        # Modify vault with first instance
        self.vault_manager.add_entry(master_password, "site1", "user1", "pass1")
        
        # Verify second instance sees changes
        entries = vault_manager2.get_entries(master_password)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["site"], "site1")

    def test_password_history(self):
        """Test password history tracking."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Add entry and update password multiple times
        self.vault_manager.add_entry(master_password, "test_site", "user", "pass1")
        self.vault_manager.update_entry(master_password, "test_site", "user", "pass2")
        self.vault_manager.update_entry(master_password, "test_site", "user", "pass3")
        
        # Get password history
        history = self.vault_manager.get_password_history(master_password, "test_site")
        self.assertEqual(len(history), 3)
        self.assertEqual(history[0], "pass3")  # Most recent first
        self.assertEqual(history[-1], "pass1")  # Oldest last

    def test_vault_version_compatibility(self):
        """Test vault version compatibility handling."""
        master_password = "test_master_password"
        self.vault_manager.create_vault(master_password)
        
        # Modify vault version in metadata
        vault_data = self.vault_manager.get_vault_data(master_password)
        vault_data["version"] = "0.1.0"  # Old version
        
        # Write modified data
        self.vault_manager.save_vault_data(vault_data, master_password)
        
        # Attempt to read vault with version check
        with self.assertRaises(ValueError) as cm:
            self.vault_manager.get_entries(master_password)
        self.assertIn("version", str(cm.exception))

if __name__ == '__main__':
    unittest.main() 