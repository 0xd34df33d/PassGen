# Secure Password Manager

A highly secure, asynchronous password generator and manager with a graphical user interface, built in pure Python.

## Features

- Secure password generation with configurable options
- Encrypted vault for storing credentials
- Asynchronous GUI using tkinter
- Pure Python implementation with no external dependencies
- Memory-safe operations
- Anti-brute-force protection
- Auto-lock functionality
- Password strength assessment

## Security Features

- PBKDF2-HMAC-SHA512 key derivation
- AES-256 encryption
- Constant-time password comparison
- Memory-safe operations
- Secure clipboard handling
- Anti-brute-force protection
- Emergency wipe capability

## Requirements

- Python 3.8 or higher
- No external dependencies required

## Installation

1. Clone this repository
2. Navigate to the project directory
3. Run the application:
   ```bash
   python src/main.py
   ```

## Usage

1. Launch the application
2. Create a master password (minimum 12 characters)
3. Use the generator tab to create secure passwords
4. Store credentials in the encrypted vault
5. Access your stored passwords securely

## Security Notes

- The master password is the only secret required to access the vault
- All sensitive data is stored in memory only
- The vault is automatically encrypted at rest
- Passwords are cleared from clipboard after 30 seconds
- The vault auto-locks after 5 minutes of inactivity

## License

MIT License 