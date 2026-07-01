from cryptography.fernet import Fernet
from app.config import settings

# Initialize Fernet key directly from config.
# Since ENCRYPTION_KEY is required in settings, we initialize directly.
# This ensures we fail fast on startup if the key is invalid or missing.
fernet = Fernet(settings.ENCRYPTION_KEY.encode())


def encrypt_token(token: str) -> str:
    """
    Encrypts a plain-text token to a secure encrypted string.
    """
    if not token:
        return ""
    return fernet.encrypt(token.encode()).decode()

def decrypt_token(encrypted_token: str) -> str:
    """
    Decrypts an encrypted token back to plain-text.
    """
    if not encrypted_token:
        return ""
    return fernet.decrypt(encrypted_token.encode()).decode()
