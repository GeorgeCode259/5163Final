import secrets
import hashlib
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization

# Fast power modulo arithmetic 
def mod_exp(base, exponent, modulus):
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent % 2:
            result = (result * base) % modulus
        exponent //= 2
        base = (base * base) % modulus
    return result

# Miller-Rabin  primality test
def is_probable_prime(n, k=40):
    if n in (2, 3):
        return True
    if n < 2 or n % 2 == 0:
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_exp(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Randomly generated prime numbers 
def generate_prime(bits=512): 
    while True:
        candidate = secrets.randbits(bits) | 1
        if is_probable_prime(candidate):
            return candidate

# Generate private key 
def generate_private_key(p):
    return secrets.randbelow(p - 2) + 2

# Generate public key 
def generate_public_key(g, private_key, p):
    return mod_exp(g, private_key, p)

# Calculating a shared key 
def compute_shared_secret(peer_public_key, private_key, p):
    return mod_exp(peer_public_key, private_key, p)

# HMAC-SHA256
def hmac_sha256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()

# Derived shared keys 
def derive_key(shared_secret: int, salt: bytes = b"PAKE") -> bytes:
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    return hashlib.pbkdf2_hmac('sha256', secret_bytes, salt, iterations=100000)

# === RSA ===

# Generate RSA key pairs 
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Sign the message 
def rsa_sign(message: bytes, private_key) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Verify Signature
def rsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# === ECC / ECDSA ===

def generate_ecdsa_keypair():
    """
    Generate ECDSA (secp256r1) key pair
    Returns (private_key, public_key)
    """
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def ecdsa_sign(message: bytes, private_key) -> bytes:
    """
    Use ECDSA to sign messages with SHA-256.
    """
    signature = private_key.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature

def ecdsa_verify(message: bytes, signature: bytes, public_key) -> bool:
    """
    Verify ECDSA signature, return True/False
    """
    try:
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False
