import secrets
from base64 import urlsafe_b64encode as b64e
from base64 import urlsafe_b64decode as b64d
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

iterations = 100_000
backend = default_backend()


def _derive_key(password: bytes, salt: bytes, iterations: int = iterations) -> bytes:
    """Derive a secret key from a given password and salt"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt,
        iterations=iterations, backend=backend)
    return b64e(kdf.derive(password))


def password_encrypt(message: bytes, password: bytes) -> bytes:
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt, iterations)
    return b64e(b'%b%b%b' % (
        salt,
        iterations.to_bytes(4, 'big'),
        b64d(Fernet(key).encrypt(message))
    ))


def password_decrypt(cypher_text: bytes, password: bytes) -> bytes:
    decoded = b64d(cypher_text)
    salt, iter, cypher_text = decoded[:16], decoded[16:20], b64e(decoded[20:])
    iterations = int.from_bytes(iter, 'big')
    key = _derive_key(password, salt, iterations)
    return Fernet(key).decrypt(cypher_text)


# **** Model to use ****
#
#user_message = "hello".encode('utf-8')
#user_password = "1234".encode('utf-8')
#
#print("Phase 1 - encryption")
#encrypted_text = password_encrypt(user_message, user_password)
#print(encrypted_text)
#
#print("Phase 2 - decryption")
#decrypted_text = password_decrypt(encrypted_text, user_password)
#print(decrypted_text.decode('utf-8'))

