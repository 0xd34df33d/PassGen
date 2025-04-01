# Secure Password Manager

A highly secure, asynchronous password generator and manager with a graphical user interface, built in pure Python.

## Features

- Secure password generation with configurable options
- Passphrase generation using a curated wordlist
- Encrypted vault for storing credentials
- Modern GUI using PyQt5
- Pure Python implementation with minimal dependencies
- Memory-safe operations
- Anti-brute-force protection

## Security Features

- PBKDF2-HMAC-SHA512 key derivation
- AES-256 encryption
- Constant-time password comparison
- Memory-safe operations
- Secure clipboard handling with automatic clearing
- Anti-brute-force protection
- Emergency wipe capability
- Auto-lock functionality

## Requirements

- Python 3.8 or higher
- PyQt5
- cryptography

## Installation

1. Clone this repository
2. Navigate to the project directory
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the application:
   ```bash
   python src/main.py
   ```

## Usage

1. Launch the application
2. Create a master password (minimum 12 characters)
3. Use the generator tab to create secure passwords or passphrases:
   - Configure password settings (length, character types)
   - Configure passphrase settings (word count, separator, capitalization)
   - Generated passwords/passphrases are automatically copied to clipboard
4. Store credentials in the encrypted vault
5. Access your stored passwords securely

## Security Notes

- The master password is the only secret required to access the vault
- All sensitive data is stored in memory only temporarily
- The vault is automatically encrypted at rest
- Generated passwords/passphrases are automatically copied to clipboard
- Clipboard is automatically cleared after the configured timeout
- The vault auto-locks after the configured period of inactivity
- User activity (mouse/keyboard) resets the auto-lock timer

## Configuration

The application can be configured through the Settings tab:

1. Clipboard Security:
   - Set how long generated passwords remain in clipboard
   - Default: 30 seconds

2. Auto-Lock:
   - Set how long before the vault automatically locks
   - Default: 15 minutes
   - Timer resets on user activity

## License

MIT License 