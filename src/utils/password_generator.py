import secrets
import string
import math
from typing import List, Dict, Optional

class PasswordGenerator:
    # Character sets
    UPPERCASE = string.ascii_uppercase
    LOWERCASE = string.ascii_lowercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    
    # Ambiguous characters to exclude
    AMBIGUOUS = "Il1O0"
    
    # EFF Diceware wordlist (abbreviated for example)
    EFF_WORDS = [
        "abandon", "ability", "able", "about", "above",
        "absent", "absorb", "abstract", "absurd", "abuse",
        # ... more words would be added in full implementation
    ]
    
    @staticmethod
    def generate_password(
        length: int,
        use_uppercase: bool = True,
        use_lowercase: bool = True,
        use_digits: bool = True,
        use_symbols: bool = True,
        exclude_ambiguous: bool = True
    ) -> str:
        """Generate a secure random password."""
        # Build character set
        chars = ""
        if use_uppercase:
            chars += PasswordGenerator.UPPERCASE
        if use_lowercase:
            chars += PasswordGenerator.LOWERCASE
        if use_digits:
            chars += PasswordGenerator.DIGITS
        if use_symbols:
            chars += PasswordGenerator.SYMBOLS
            
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in PasswordGenerator.AMBIGUOUS)
            
        # Ensure at least one character from each selected set
        password = []
        if use_uppercase:
            password.append(secrets.choice(PasswordGenerator.UPPERCASE))
        if use_lowercase:
            password.append(secrets.choice(PasswordGenerator.LOWERCASE))
        if use_digits:
            password.append(secrets.choice(PasswordGenerator.DIGITS))
        if use_symbols:
            password.append(secrets.choice(PasswordGenerator.SYMBOLS))
            
        # Fill remaining length
        remaining_length = length - len(password)
        password.extend(secrets.choice(chars) for _ in range(remaining_length))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    @staticmethod
    def generate_passphrase(word_count: int = 4) -> str:
        """Generate a secure passphrase using EFF Diceware wordlist."""
        if not 4 <= word_count <= 8:
            raise ValueError("Word count must be between 4 and 8")
            
        words = [secrets.choice(PasswordGenerator.EFF_WORDS) for _ in range(word_count)]
        return ' '.join(words)
    
    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate the entropy of a password in bits."""
        # Count character sets used
        char_sets = 0
        if any(c in PasswordGenerator.UPPERCASE for c in password):
            char_sets += 1
        if any(c in PasswordGenerator.LOWERCASE for c in password):
            char_sets += 1
        if any(c in PasswordGenerator.DIGITS for c in password):
            char_sets += 1
        if any(c in PasswordGenerator.SYMBOLS for c in password):
            char_sets += 1
            
        # Calculate entropy
        if char_sets == 0:
            return 0
            
        # For each character set, calculate its contribution to entropy
        set_entropies = {
            PasswordGenerator.UPPERCASE: math.log2(26),
            PasswordGenerator.LOWERCASE: math.log2(26),
            PasswordGenerator.DIGITS: math.log2(10),
            PasswordGenerator.SYMBOLS: math.log2(len(PasswordGenerator.SYMBOLS))
        }
        
        # Calculate total entropy
        total_entropy = 0
        for char_set, entropy in set_entropies.items():
            if any(c in char_set for c in password):
                total_entropy += entropy
                
        return total_entropy * len(password)
    
    @staticmethod
    def is_strong(password: str, threshold: int = 80) -> bool:
        """Check if a password meets the strength threshold."""
        return PasswordGenerator.calculate_entropy(password) >= threshold 