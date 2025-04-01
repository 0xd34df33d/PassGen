import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class Config:
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration."""
        logger.info("Initializing configuration")
        
        # Set up paths
        self.config_dir = Path.home() / '.passgen'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        self.vault_file = self.config_dir / 'vault.enc'
        self.audit_log = self.config_dir / 'audit.log'
        self.config_path = Path(config_path) if config_path else self.config_dir / 'config.json'
        
        # Load or create configuration
        if self.config_path.exists():
            self._load_config()
        else:
            self._create_default_config()
        
        logger.info("Configuration initialized successfully")
    
    def _load_config(self):
        """Load configuration from file."""
        logger.debug("Loading configuration")
        if not self.config_dir.exists():
            logger.info("Creating configuration directory")
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
        if not self.config_path.exists():
            logger.info("Creating default configuration")
            self._create_default_config()
        else:
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
                logger.info("Configuration loaded successfully")
            except Exception as e:
                logger.error(f"Failed to load configuration: {e}", exc_info=True)
                logger.info("Creating default configuration")
                self._create_default_config()
    
    def _create_default_config(self):
        """Create default configuration."""
        logger.debug("Creating default configuration")
        self.config = {
            'vault_path': str(self.vault_file),
            'audit_log_path': str(self.audit_log),
            'min_password_length': 12,
            'max_failed_attempts': 3,
            'lockout_duration': 300,  # 5 minutes
            'pbkdf2_iterations': 600000,
            'auto_lock_timeout': 15,  # 15 minutes
            'clipboard_timeout': 30,  # 30 seconds
            'theme': 'default',
            'language': 'en'
        }
        self._save_config()
        logger.info("Default configuration created successfully")
    
    def _save_config(self):
        """Save configuration to file."""
        logger.debug("Saving configuration")
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=4)
            logger.info("Configuration saved successfully")
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}", exc_info=True)
            raise
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        logger.debug(f"Getting configuration value for key: {key}")
        return self.config.get(key, default)
    
    def set(self, key: str, value: Any):
        """Set configuration value."""
        logger.debug(f"Setting configuration value for key: {key}")
        self.config[key] = value
        self._save_config()
    
    def get_vault_path(self) -> str:
        """Get vault file path."""
        logger.debug("Getting vault path")
        return self.config.get('vault_path', str(self.vault_file))
    
    def get_audit_log_path(self) -> str:
        """Get audit log file path."""
        logger.debug("Getting audit log path")
        return self.config.get('audit_log_path', str(self.audit_log))
    
    def get_min_password_length(self) -> int:
        """Get minimum password length."""
        logger.debug("Getting minimum password length")
        return self.config.get('min_password_length', 12)
    
    def get_max_failed_attempts(self) -> int:
        """Get maximum failed attempts before lockout."""
        logger.debug("Getting maximum failed attempts")
        return self.config.get('max_failed_attempts', 3)
    
    def get_lockout_duration(self) -> int:
        """Get lockout duration in seconds."""
        logger.debug("Getting lockout duration")
        return self.config.get('lockout_duration', 300)
    
    def get_pbkdf2_iterations(self) -> int:
        """Get PBKDF2 iterations."""
        logger.debug("Getting PBKDF2 iterations")
        return self.config.get('pbkdf2_iterations', 600000)
    
    def get_auto_lock_timeout(self) -> int:
        """Get auto-lock timeout in seconds."""
        logger.debug("Getting auto-lock timeout")
        # Convert minutes to seconds
        return self.config.get('auto_lock_timeout', 15) * 60
    
    def get_clipboard_timeout(self) -> int:
        """Get clipboard timeout in seconds."""
        logger.debug("Getting clipboard timeout")
        return self.config.get('clipboard_timeout', 30)
    
    def get_theme(self) -> str:
        """Get current theme."""
        logger.debug("Getting theme")
        return self.config.get('theme', 'default')
    
    def get_language(self) -> str:
        """Get current language."""
        logger.debug("Getting language")
        return self.config.get('language', 'en')
    
    def get_vault_path(self):
        """Get the path to the vault file."""
        return str(self.vault_file)
    
    def get_audit_log_path(self):
        """Get the path to the audit log file."""
        return str(self.audit_log) 