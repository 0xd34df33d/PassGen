import sys
import logging
import platform
from pathlib import Path
from PyQt5.QtWidgets import QApplication
from .gui.main_window import MainWindow
from .utils.config import Config
from .core.vault_manager import VaultManager
from .core.password_generator import PasswordGenerator

def setup_logging():
    """Configure logging for the application."""
    # Create logs directory
    log_dir = Path.home() / '.passgen' / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Configure logging format
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_dir / 'passgen.log')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Log startup information
    logger = logging.getLogger(__name__)
    logger.info("Starting PassGen Password Manager")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Operating system: {platform.system()} {platform.release()}")
    logger.info(f"Log directory: {log_dir}")

def main():
    """Main application entry point."""
    try:
        # Setup logging
        setup_logging()
        logger = logging.getLogger(__name__)
        
        # Initialize configuration
        logger.info("Loading configuration")
        config = Config()
        
        # Initialize components
        logger.info("Initializing application components")
        vault_manager = VaultManager(config)
        password_generator = PasswordGenerator()
        
        # Create and show GUI
        logger.info("Creating main window")
        app = QApplication(sys.argv)
        window = MainWindow(vault_manager, password_generator, config)
        window.show()
        
        # Start event loop
        logger.info("Starting event loop")
        sys.exit(app.exec_())
        
    except Exception as e:
        logger.error("Application error", exc_info=True)
        sys.exit(1)

if __name__ == '__main__':
    main() 