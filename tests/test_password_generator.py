import unittest
from passgen.core.password_generator import PasswordGenerator

class TestPasswordGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = PasswordGenerator()

    def test_generate_password_length(self):
        """Test that generated passwords have the correct length."""
        lengths = [8, 12, 16, 32]
        for length in lengths:
            password = self.generator.generate(length=length)
            self.assertEqual(len(password), length)

    def test_generate_password_characters(self):
        """Test that generated passwords contain the expected character types."""
        password = self.generator.generate(length=16)
        self.assertTrue(any(c.isupper() for c in password), "Password should contain uppercase letters")
        self.assertTrue(any(c.islower() for c in password), "Password should contain lowercase letters")
        self.assertTrue(any(c.isdigit() for c in password), "Password should contain numbers")
        self.assertTrue(any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password), 
                        "Password should contain special characters")

    def test_generate_password_uniqueness(self):
        """Test that generated passwords are unique."""
        passwords = [self.generator.generate(length=16) for _ in range(100)]
        self.assertEqual(len(set(passwords)), len(passwords), 
                        "All generated passwords should be unique")

    def test_minimum_length(self):
        """Test that passwords cannot be generated below minimum length."""
        with self.assertRaises(ValueError):
            self.generator.generate(length=3)

    def test_maximum_length(self):
        """Test that passwords cannot be generated above maximum length."""
        with self.assertRaises(ValueError):
            self.generator.generate(length=1001)

    def test_custom_character_sets(self):
        """Test password generation with custom character sets."""
        # Only lowercase letters
        password = self.generator.generate(
            length=16,
            use_uppercase=False,
            use_numbers=False,
            use_special=False
        )
        self.assertTrue(all(c.islower() for c in password))
        
        # Only numbers
        password = self.generator.generate(
            length=16,
            use_uppercase=False,
            use_lowercase=False,
            use_special=False,
            use_numbers=True
        )
        self.assertTrue(all(c.isdigit() for c in password))

    def test_character_distribution(self):
        """Test that character types are reasonably distributed."""
        password = self.generator.generate(length=100)
        
        # Count character types
        uppercase = sum(1 for c in password if c.isupper())
        lowercase = sum(1 for c in password if c.islower())
        numbers = sum(1 for c in password if c.isdigit())
        special = sum(1 for c in password if c in "!@#$%^&*()_+-=[]{}|;:,.<>?")
        
        # Each type should be at least 10% of the password
        min_count = 10
        self.assertGreaterEqual(uppercase, min_count)
        self.assertGreaterEqual(lowercase, min_count)
        self.assertGreaterEqual(numbers, min_count)
        self.assertGreaterEqual(special, min_count)

    def test_entropy(self):
        """Test password entropy (randomness)."""
        import math
        
        # Generate a large sample of passwords
        passwords = [self.generator.generate(length=16) for _ in range(1000)]
        
        # Calculate character frequency distribution
        char_freq = {}
        total_chars = 0
        
        for password in passwords:
            for char in password:
                char_freq[char] = char_freq.get(char, 0) + 1
                total_chars += 1
        
        # Calculate entropy
        entropy = 0
        for count in char_freq.values():
            prob = count / total_chars
            entropy -= prob * math.log2(prob)
        
        # Entropy should be reasonably high (> 3 bits per character)
        self.assertGreater(entropy, 3.0)

if __name__ == '__main__':
    unittest.main() 