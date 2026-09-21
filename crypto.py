
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


AES_KEY_SIZE = 32

AES_IV_SIZE = 16


def generate_rsa_keypair(key_size: int = 2048):
    """Génère une paire de clés RSA (privée, publique)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, path: str):
    """Sauvegarde la clé privée au format PEM ."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)


def save_public_key(public_key, path: str):
    """Sauvegarde la clé publique au format PEM."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, "wb") as f:
        f.write(pem)


def load_private_key(path: str):
    """Charge une clé privée depuis un fichier PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def load_public_key(path: str):
    """Charge une clé publique depuis un fichier PEM."""
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )


def _pad(data: bytes) -> bytes:
    """Padding PKCS7 pour que les données soient un multiple de 16 octets (bloc AES)."""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    """Retire le padding PKCS7."""
    pad_len = data[-1]
    return data[:-pad_len]


def encrypt_file(input_path: str, output_path: str, public_key):
    """
    Chiffre un fichier 
    """
    aes_key = os.urandom(AES_KEY_SIZE)
    iv = os.urandom(AES_IV_SIZE)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    padded_data = _pad(plaintext)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_path, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(4, byteorder="big"))
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(ciphertext)


def decrypt_file(input_path: str, output_path: str, private_key):
    """
    Déchiffre un fichier chiffré par encrypt_file() 
    """
    with open(input_path, "rb") as f:
        key_len = int.from_bytes(f.read(4), byteorder="big")
        encrypted_aes_key = f.read(key_len)
        iv = f.read(AES_IV_SIZE)
        ciphertext = f.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    plaintext = _unpad(padded_data)

    with open(output_path, "wb") as f:
        f.write(plaintext)