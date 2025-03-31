import json
import hashlib
import secrets
import time
import logging
from typing import Dict, List, Optional
from pathlib import Path
from src.crypto.aes import AES
from src.utils.config import Config

logger = logging.getLogger(__name__)

class VaultManager:
    def __init__(self, config: Config):
        """Initialize the vault manager."""
        logger.info("Initializing VaultManager")
        self.config = config
        self.vault_path = Path(config.get_vault_path())
        self.audit_log_path = Path(config.get_audit_log_path())
        self._vault_data: Optional[Dict] = None
        self._aes: Optional[AES] = None
        self._failed_attempts = 0
        self._last_attempt_time = 0
        self._locked = True
        logger.debug(f"Vault path: {self.vault_path}")
        logger.debug(f"Audit log path: {self.audit_log_path}")
        logger.debug("VaultManager initialized successfully")
    
    def is_unlocked(self) -> bool:
        """Check if the vault is unlocked."""
        return not self._locked
    
    def is_locked(self) -> bool:
        """Check if the vault is locked."""
        return self._locked
    
    def _derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive encryption key from master password using PBKDF2."""
        logger.debug("Deriving key from master password")
        iterations = self.config.get('pbkdf2_iterations', 600000)
        # Use SHA-256 to ensure we get exactly 32 bytes for AES-256
        key = hashlib.pbkdf2_hmac(
            'sha256',  # Changed from sha512 to sha256
            master_password.encode(),
            salt,
            iterations,
            dklen=32  # Explicitly request 32 bytes
        )
        logger.debug(f"Key derivation complete with {iterations} iterations")
        return key
    
    def _constant_time_compare(self, a: bytes, b: bytes) -> bool:
        """Compare two bytes objects in constant time."""
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0
    
    def _log_audit(self, event: str, success: bool):
        """Log security events to audit log."""
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        message = f"{timestamp} | {event} | {'SUCCESS' if success else 'FAILURE'}"
        logger.info(f"Audit log: {message}")
        with open(self.audit_log_path, 'a') as f:
            f.write(message + "\n")
    
    def create_vault(self, master_password: str) -> bool:
        """Create a new vault with the given master password."""
        logger.info("Creating new vault")
        if len(master_password) < self.config.get('min_password_length', 12):
            logger.warning("Master password too short")
            return False
            
        # Generate salt and derive key
        salt = secrets.token_bytes(32)
        key = self._derive_key(master_password, salt)
        
        # Initialize empty vault
        vault_data = {
            'entries': [],
            'version': '1.0'
        }
        
        # Convert vault data to JSON and encrypt
        logger.debug("Encrypting vault data")
        aes = AES(key)
        json_data = json.dumps(vault_data).encode('utf-8')
        encrypted_data, iv = aes.encrypt(json_data)
        
        # Save encrypted vault with salt and IV
        try:
            with open(self.vault_path, 'wb') as f:
                # Format: [32 bytes salt][16 bytes IV][encrypted data]
                f.write(salt)
                f.write(iv)
                f.write(encrypted_data)
            logger.info("Vault created successfully")
            self._log_audit('VAULT_CREATION', True)
            return True
        except Exception as e:
            logger.error(f"Failed to create vault: {e}", exc_info=True)
            self._log_audit('VAULT_CREATION', False)
            return False
    
    def unlock_vault(self, master_password: str) -> bool:
        """Unlock the vault with the given master password."""
        logger.info("Attempting to unlock vault")
        # Check for lockout
        current_time = time.time()
        if self._failed_attempts >= self.config.get('max_failed_attempts', 3):
            if current_time - self._last_attempt_time < self.config.get('lockout_duration', 2):
                logger.warning("Vault is locked due to too many failed attempts")
                self._log_audit('UNLOCK_ATTEMPT_LOCKED', False)
                return False
            self._failed_attempts = 0
            logger.info("Lockout period expired, resetting failed attempts")
        
        if not self.vault_path.exists():
            logger.warning("Vault file does not exist")
            return False
            
        # Read encrypted vault
        try:
            with open(self.vault_path, 'rb') as f:
                data = f.read()
                
            if len(data) < 48:  # 32 bytes salt + 16 bytes IV
                logger.error("Invalid vault file format")
                return False
                
            # Extract salt, IV and encrypted data
            salt = data[:32]  # First 32 bytes are salt
            iv = data[32:48]  # Next 16 bytes are IV
            encrypted_data = data[48:]  # Rest is encrypted data
            
            # Derive key from password and salt
            key = self._derive_key(master_password, salt)
            aes = AES(key)
            
            # Decrypt data
            try:
                decrypted_data = aes.decrypt(encrypted_data, iv)
                vault_data = json.loads(decrypted_data.decode('utf-8'))
                
                # Verify vault data structure
                if not isinstance(vault_data, dict) or 'entries' not in vault_data:
                    logger.error("Invalid vault data structure")
                    return False
                    
                self._vault_data = vault_data
                self._aes = aes
                self._salt = salt
                self._locked = False
                self._failed_attempts = 0
                logger.info("Vault unlocked successfully")
                self._log_audit('VAULT_UNLOCK', True)
                return True
            except ValueError as e:
                logger.error(f"Failed to decrypt vault: {e}")
                self._failed_attempts += 1
                self._last_attempt_time = current_time
                self._log_audit('VAULT_UNLOCK', False)
                return False
        except Exception as e:
            self._failed_attempts += 1
            self._last_attempt_time = current_time
            logger.error(f"Failed to unlock vault: {e}", exc_info=True)
            self._log_audit('VAULT_UNLOCK', False)
            return False
    
    def lock_vault(self):
        """Lock the vault and clear sensitive data from memory."""
        logger.info("Locking vault")
        self._vault_data = None
        self._aes = None
        self._locked = True
        logger.debug("Sensitive data cleared from memory")
    
    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = "") -> bool:
        """Add a new entry to the vault."""
        if self._locked:
            logger.warning("Cannot add entry: vault is locked")
            return False
            
        logger.info(f"Adding new entry: {title}")
        entry = {
            'id': secrets.token_hex(8),
            'title': title,
            'username': username,
            'password': password,
            'url': url,
            'notes': notes,
            'created_at': time.time(),
            'updated_at': time.time()
        }
        
        self._vault_data['entries'].append(entry)
        success = self._save_vault()
        if success:
            logger.info(f"Entry added successfully: {title}")
        else:
            logger.error(f"Failed to add entry: {title}")
        return success
    
    def update_entry(self, entry_id: str, **kwargs) -> bool:
        """Update an existing entry in the vault."""
        if self._locked:
            logger.warning("Cannot update entry: vault is locked")
            return False
            
        logger.info(f"Updating entry: {entry_id}")
        for entry in self._vault_data['entries']:
            if entry['id'] == entry_id:
                entry.update(kwargs)
                entry['updated_at'] = time.time()
                success = self._save_vault()
                if success:
                    logger.info(f"Entry updated successfully: {entry_id}")
                else:
                    logger.error(f"Failed to update entry: {entry_id}")
                return success
        logger.warning(f"Entry not found: {entry_id}")
        return False
    
    def delete_entry(self, entry_id: str) -> bool:
        """Delete an entry from the vault."""
        if self._locked:
            logger.warning("Cannot delete entry: vault is locked")
            return False
            
        logger.info(f"Deleting entry: {entry_id}")
        self._vault_data['entries'] = [
            entry for entry in self._vault_data['entries']
            if entry['id'] != entry_id
        ]
        success = self._save_vault()
        if success:
            logger.info(f"Entry deleted successfully: {entry_id}")
        else:
            logger.error(f"Failed to delete entry: {entry_id}")
        return success
    
    def get_entries(self) -> List[Dict]:
        """Get all entries from the vault."""
        if self._locked:
            logger.warning("Cannot get entries: vault is locked")
            return []
        logger.debug(f"Retrieving {len(self._vault_data['entries'])} entries")
        return self._vault_data['entries']
    
    def search_entries(self, query: str) -> List[Dict]:
        """Search entries in the vault."""
        if self._locked:
            logger.warning("Cannot search entries: vault is locked")
            return []
            
        logger.debug(f"Searching entries for: {query}")
        query = query.lower()
        results = [
            entry for entry in self._vault_data['entries']
            if query in entry['title'].lower() or
               query in entry['username'].lower() or
               query in entry['url'].lower() or
               query in entry['notes'].lower()
        ]
        logger.debug(f"Found {len(results)} matching entries")
        return results
    
    def _save_vault(self) -> bool:
        """Save the current vault state to disk."""
        if self._locked or not self._aes:
            logger.warning("Cannot save vault: vault is locked or not initialized")
            return False
            
        try:
            logger.debug("Encrypting vault data for saving")
            # Encrypt vault data
            encrypted_data, iv = self._aes.encrypt(
                json.dumps(self._vault_data).encode()
            )
            
            # Save encrypted vault
            with open(self.vault_path, 'wb') as f:
                f.write(self._salt)
                f.write(iv)
                f.write(encrypted_data)
            logger.debug("Vault saved successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to save vault: {e}", exc_info=True)
            return False
    
    def change_master_password(self, old_password: str, new_password: str) -> bool:
        """Change the master password of the vault."""
        logger.info("Attempting to change master password")
        
        # Verify old password by trying to unlock the vault
        if not self.unlock_vault(old_password):
            logger.warning("Failed to verify old master password")
            return False
        
        # Create new vault with new password
        try:
            # Generate new salt and key
            new_salt = secrets.token_bytes(32)
            new_key = self._derive_key(new_password, new_salt)
            
            # Create new AES instance with new key
            new_aes = AES(new_key)
            
            # Encrypt vault data with new key
            json_data = json.dumps(self._vault_data).encode('utf-8')
            encrypted_data, iv = new_aes.encrypt(json_data)
            
            # Save encrypted vault with new salt and IV
            with open(self.vault_path, 'wb') as f:
                f.write(new_salt)
                f.write(iv)
                f.write(encrypted_data)
            
            # Update instance variables
            self._aes = new_aes
            self._salt = new_salt
            
            logger.info("Master password changed successfully")
            self._log_audit('MASTER_PASSWORD_CHANGE', True)
            return True
        except Exception as e:
            logger.error(f"Failed to change master password: {e}", exc_info=True)
            self._log_audit('MASTER_PASSWORD_CHANGE', False)
            return False
    
    def export_vault(self, export_path: str) -> bool:
        """Export the vault to a file."""
        if self._locked:
            logger.warning("Cannot export vault: vault is locked")
            return False
            
        logger.info(f"Exporting vault to: {export_path}")
        try:
            with open(export_path, 'wb') as f:
                f.write(self.vault_path.read_bytes())
            logger.info("Vault exported successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to export vault: {e}", exc_info=True)
            return False
    
    def import_vault(self, import_path: str) -> bool:
        """Import a vault from a file."""
        if self._locked:
            logger.warning("Cannot import vault: vault is locked")
            return False
            
        logger.info(f"Importing vault from: {import_path}")
        try:
            with open(import_path, 'rb') as f:
                data = f.read()
            with open(self.vault_path, 'wb') as f:
                f.write(data)
            logger.info("Vault imported successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to import vault: {e}", exc_info=True)
            return False
    
    def set_initial_password(self, master_password: str) -> bool:
        """Set the initial master password for a new vault."""
        logger.info("Setting initial master password")
        
        # Delete existing vault if it exists
        if self.vault_path.exists():
            try:
                self.vault_path.unlink()
                logger.info("Deleted existing vault")
            except Exception as e:
                logger.error(f"Failed to delete existing vault: {e}")
                return False
        
        return self.create_vault(master_password) 