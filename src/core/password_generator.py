import logging
import random
import string
from pathlib import Path

logger = logging.getLogger(__name__)

class PasswordGenerator:
    def __init__(self):
        """Initialize password generator."""
        logger.info("Initializing password generator")
        self.lowercase = string.ascii_lowercase
        self.uppercase = string.ascii_uppercase
        self.digits = string.digits
        self.special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        self.ambiguous = "l1I0O"
        self.wordlist_path = Path(__file__).parent.parent / 'resources' / 'wordlist.txt'
        logger.debug("Password generator initialized successfully")
    
    def generate_password(self, length=12, use_uppercase=True, use_lowercase=True, 
                        use_digits=True, use_symbols=True, avoid_ambiguous=False):
        """Generate a random password with the specified parameters."""
        try:
            logger.info(f"Generating password with length {length}")
            logger.debug(f"Options: lowercase={use_lowercase}, uppercase={use_uppercase}, "
                      f"digits={use_digits}, symbols={use_symbols}, avoid_ambiguous={avoid_ambiguous}")
            
            # Build character set based on options
            charset = ''
            if use_lowercase:
                charset += self.lowercase
            if use_uppercase:
                charset += self.uppercase
            if use_digits:
                charset += self.digits
            if use_symbols:
                charset += self.special
                
            if not charset:
                logger.error("No character sets selected")
                raise ValueError("At least one character set must be selected")
            
            if avoid_ambiguous:
                charset = ''.join(c for c in charset if c not in self.ambiguous)
                
            # Generate password
            password = ''.join(random.choice(charset) for _ in range(length))
            logger.info("Password generated successfully")
            return password
            
        except Exception as e:
            logger.error(f"Failed to generate password: {str(e)}")
            raise
            
    def generate_passphrase(self, word_count=4, separator=" ", capitalize=False):
        """Generate a passphrase from random words."""
        try:
            logger.info(f"Generating passphrase with {word_count} words")
            logger.debug(f"Options: separator='{separator}', capitalize={capitalize}")
            
            if not self.wordlist_path.exists():
                logger.error(f"Wordlist not found at {self.wordlist_path}")
                raise FileNotFoundError(f"Wordlist not found at {self.wordlist_path}")
            
            with open(self.wordlist_path, 'r') as f:
                words = f.read().splitlines()
                logger.debug(f"Loaded {len(words)} words from wordlist")
                
            # Generate passphrase
            selected_words = random.sample(words, word_count)
            if capitalize:
                selected_words = [w.capitalize() for w in selected_words]
                
            passphrase = separator.join(selected_words)
            logger.info("Passphrase generated successfully")
            return passphrase
            
        except Exception as e:
            logger.error(f"Failed to generate passphrase: {str(e)}")
            raise
            
    def calculate_entropy(self, password):
        """Calculate the entropy of a password in bits."""
        try:
            # Count character set sizes
            has_lower = any(c in self.lowercase for c in password)
            has_upper = any(c in self.uppercase for c in password)
            has_digits = any(c in self.digits for c in password)
            has_symbols = any(c in self.special for c in password)
            
            # Calculate total character set size
            charset_size = 0
            if has_lower:
                charset_size += len(self.lowercase)
            if has_upper:
                charset_size += len(self.uppercase)
            if has_digits:
                charset_size += len(self.digits)
            if has_symbols:
                charset_size += len(self.special)
                
            # Calculate entropy
            if charset_size == 0:
                return 0
            entropy = len(password) * (charset_size.bit_length())
            return entropy
            
        except Exception as e:
            logger.error(f"Failed to calculate entropy: {str(e)}")
            raise
    
    def check_strength(self, password: str) -> dict:
        """Check password strength and return detailed analysis."""
        logger.info("Checking password strength")
        analysis = {
            'length': len(password),
            'entropy': self.calculate_entropy(password),
            'has_uppercase': any(c in self.uppercase for c in password),
            'has_digits': any(c in self.digits for c in password),
            'has_special': any(c in self.special for c in password),
            'has_ambiguous': any(c in self.ambiguous for c in password),
            'is_strong': True
        }
        
        # Determine strength
        if analysis['length'] < 8:
            analysis['is_strong'] = False
            logger.warning("Password too short")
        if analysis['entropy'] < 64:
            analysis['is_strong'] = False
            logger.warning("Password entropy too low")
        if not analysis['has_uppercase']:
            analysis['is_strong'] = False
            logger.warning("Password missing uppercase characters")
        if not analysis['has_digits']:
            analysis['is_strong'] = False
            logger.warning("Password missing digits")
        if not analysis['has_special']:
            analysis['is_strong'] = False
            logger.warning("Password missing special characters")
        if analysis['has_ambiguous']:
            logger.warning("Password contains ambiguous characters")
        
        logger.info(f"Password strength analysis complete: {'strong' if analysis['is_strong'] else 'weak'}")
        return analysis 