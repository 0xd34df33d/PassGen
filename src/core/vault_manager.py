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
        self._last_activity_time = time.time()  # Initialize with current time
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
    
    def update_activity(self):
        """Update the last activity timestamp."""
        if not self._locked:  # Only update if vault is unlocked
            self._last_activity_time = time.time()
            logger.debug(f"Activity updated at {self._last_activity_time}")
    
    def should_auto_lock(self) -> bool:
        """Check if vault should be auto-locked based on inactivity."""
        if not self.is_unlocked():
            return False
            
        timeout = self.config.get_auto_lock_timeout()  # Already in seconds
        current_time = time.time()
        time_since_activity = current_time - self._last_activity_time
        
        logger.debug(f"Time since last activity: {time_since_activity:.1f}s, Timeout: {timeout}s")
        should_lock = time_since_activity >= timeout
        
        if should_lock:
            logger.info(f"Auto-lock condition met: {time_since_activity:.1f}s elapsed (timeout: {timeout}s)")
        
        return should_lock
    
    def _load_vault(self) -> bool:
        """Load encrypted vault data from file."""
        try:
            logger.debug("Loading vault data from file")
            if not self.vault_path.exists():
                logger.error("Vault file does not exist")
                return False
                
            with open(self.vault_path, 'rb') as f:
                data = f.read()
                
            if len(data) < 48:  # 32 bytes salt + 16 bytes IV
                logger.error("Invalid vault file format")
                return False
                
            # Extract salt, IV and encrypted data
            self._salt = data[:32]  # First 32 bytes are salt
            iv = data[32:48]  # Next 16 bytes are IV
            encrypted_data = data[48:]  # Rest is encrypted data
            
            self._vault_data = {
                'encrypted_data': encrypted_data,
                'iv': iv
            }
            
            logger.debug("Vault data loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load vault: {str(e)}", exc_info=True)
            return False
    
    def unlock_vault(self, master_password: str) -> bool:
        """Unlock the vault with the master password."""
        try:
            logger.info("Attempting to unlock vault")
            
            # Load vault data if not already loaded
            if self._vault_data is None:
                if not self._load_vault():
                    return False
            
            # Reset activity time when unlocking
            self._last_activity_time = time.time()
            
            # Decrypt vault data
            logger.debug("Attempting to decrypt vault data")
            decrypted_data = self._decrypt_vault_data(master_password)
            if decrypted_data is None:
                logger.error("Failed to decrypt vault data - password may be incorrect")
                self._failed_attempts += 1
                self._last_attempt_time = time.time()
                self._log_audit('VAULT_UNLOCK', False)
                return False
            
            # Store the decrypted data and initialize AES
            self._vault_data = decrypted_data
            self._aes = AES(self._derive_key(master_password, self._salt))
            self._locked = False
            self._failed_attempts = 0
            
            # Ensure the vault data has the required structure
            if 'entries' not in self._vault_data:
                self._vault_data['entries'] = []
            if 'version' not in self._vault_data:
                self._vault_data['version'] = '1.0'
                
            logger.info("Vault unlocked successfully")
            self._log_audit('VAULT_UNLOCK', True)
            return True
            
        except Exception as e:
            logger.error(f"Failed to unlock vault: {str(e)}", exc_info=True)
            self._failed_attempts += 1
            self._last_attempt_time = time.time()
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
        try:
            # Find the entry to update
            entry_to_update = None
            for entry in self._vault_data['entries']:
                if entry['id'] == entry_id:
                    entry_to_update = entry
                    break
                    
            if not entry_to_update:
                logger.warning(f"Entry not found: {entry_id}")
                return False
            
            # Validate required fields
            required_fields = {'title', 'username', 'password'}
            if not all(field in kwargs for field in required_fields):
                logger.error("Missing required fields in update data")
                return False
            
            # Update the entry
            entry_to_update.update({
                'title': kwargs['title'],
                'username': kwargs['username'],
                'password': kwargs['password'],
                'url': kwargs.get('url', ''),
                'notes': kwargs.get('notes', ''),
                'updated_at': time.time()
            })
            
            # Save the changes
            success = self._save_vault()
            if success:
                logger.info(f"Entry updated successfully: {entry_id}")
            else:
                logger.error(f"Failed to save updated entry: {entry_id}")
            return success
            
        except Exception as e:
            logger.error(f"Failed to update entry: {str(e)}", exc_info=True)
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
    
    def get_entry(self, entry_id: str) -> Optional[Dict]:
        """Get a specific entry from the vault by ID."""
        if self._locked:
            logger.warning("Cannot get entry: vault is locked")
            return None
            
        logger.debug(f"Retrieving entry: {entry_id}")
        for entry in self._vault_data['entries']:
            if entry['id'] == entry_id:
                return entry
        logger.warning(f"Entry not found: {entry_id}")
        return None
    
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
            # Create a copy of vault data without any internal state
            vault_data_to_save = {
                'entries': self._vault_data['entries'],
                'version': self._vault_data.get('version', '1.0')
            }
            
            # Encrypt vault data
            encrypted_data, iv = self._aes.encrypt(
                json.dumps(vault_data_to_save).encode()
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
    
    def _decrypt_vault_data(self, master_password: str) -> Optional[Dict]:
        """Decrypt vault data using the master password."""
        try:
            logger.debug("Starting vault decryption")
            if not self._vault_data:
                logger.error("No vault data to decrypt")
                return None
                
            # Derive key from password and salt
            logger.debug("Deriving key from password")
            key = self._derive_key(master_password, self._salt)
            
            # Create AES instance
            logger.debug("Creating AES instance")
            aes = AES(key)
            
            # Decrypt data
            logger.debug("Decrypting vault data")
            decrypted_data = aes.decrypt(self._vault_data['encrypted_data'], self._vault_data['iv'])
            
            # Parse JSON
            logger.debug("Parsing decrypted JSON data")
            vault_data = json.loads(decrypted_data.decode('utf-8'))
            
            # Verify vault data structure
            if not isinstance(vault_data, dict) or 'entries' not in vault_data:
                logger.error("Invalid vault data structure")
                return None
                
            logger.debug("Vault decryption successful")
            return vault_data
            
        except ValueError as e:
            logger.error(f"Failed to decrypt vault data: {str(e)}", exc_info=True)
            return None
        except Exception as e:
            logger.error(f"Unexpected error during decryption: {str(e)}", exc_info=True)
            return None 