import os
import pytest
from crypto_vault import crypto


@pytest.fixture
def rsa_keys():
    """Génère une paire de clés RSA de test (petite taille pour aller vite)."""
    private_key, public_key = crypto.generate_rsa_keypair(key_size=2048)
    return private_key, public_key


@pytest.fixture
def sample_file(tmp_path):
    """Crée un fichier de test temporaire avec du contenu connu."""
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(b"Ceci est un contenu secret de test 12345!")
    return file_path


def test_generate_rsa_keypair_produces_valid_keys(rsa_keys):
    """La génération de clés doit produire une clé privée et publique liées."""
    private_key, public_key = rsa_keys
    assert private_key is not None
    assert public_key is not None
    # La clé publique dérivée de la privée doit correspondre à la clé publique générée
    assert private_key.public_key().public_numbers() == public_key.public_numbers()


def test_save_and_load_private_key(rsa_keys, tmp_path):
    """Une clé privée sauvegardée puis rechargée doit être identique."""
    private_key, _ = rsa_keys
    key_path = tmp_path / "private_key.pem"
    crypto.save_private_key(private_key, str(key_path))

    assert key_path.exists()
    loaded_key = crypto.load_private_key(str(key_path))
    assert loaded_key.private_numbers() == private_key.private_numbers()


def test_save_and_load_public_key(rsa_keys, tmp_path):
    """Une clé publique sauvegardée puis rechargée doit être identique."""
    _, public_key = rsa_keys
    key_path = tmp_path / "public_key.pem"
    crypto.save_public_key(public_key, str(key_path))

    assert key_path.exists()
    loaded_key = crypto.load_public_key(str(key_path))
    assert loaded_key.public_numbers() == public_key.public_numbers()


def test_encrypt_produces_different_content(rsa_keys, sample_file, tmp_path):
    """Le fichier chiffré doit être différent du fichier original."""
    _, public_key = rsa_keys
    output_path = tmp_path / "sample.txt.enc"

    crypto.encrypt_file(str(sample_file), str(output_path), public_key)

    assert output_path.exists()
    original_content = sample_file.read_bytes()
    encrypted_content = output_path.read_bytes()
    assert original_content != encrypted_content


def test_encrypt_then_decrypt_returns_original_content(rsa_keys, sample_file, tmp_path):
    """Test bout-en-bout : chiffrer puis déchiffrer doit redonner le contenu original."""
    private_key, public_key = rsa_keys
    encrypted_path = tmp_path / "sample.txt.enc"
    decrypted_path = tmp_path / "sample_decrypted.txt"

    crypto.encrypt_file(str(sample_file), str(encrypted_path), public_key)
    crypto.decrypt_file(str(encrypted_path), str(decrypted_path), private_key)

    original_content = sample_file.read_bytes()
    decrypted_content = decrypted_path.read_bytes()
    assert original_content == decrypted_content


def test_decrypt_with_wrong_key_fails(sample_file, tmp_path):
    """Déchiffrer avec la mauvaise clé privée doit échouer proprement."""
    private_key_1, public_key_1 = crypto.generate_rsa_keypair(key_size=2048)
    private_key_2, _ = crypto.generate_rsa_keypair(key_size=2048)  # Clé différente

    encrypted_path = tmp_path / "sample.txt.enc"
    decrypted_path = tmp_path / "sample_decrypted.txt"

    crypto.encrypt_file(str(sample_file), str(encrypted_path), public_key_1)

    with pytest.raises(Exception):
        crypto.decrypt_file(str(encrypted_path), str(decrypted_path), private_key_2)


def test_encrypt_empty_file(rsa_keys, tmp_path):
    """Le chiffrement doit gérer un fichier vide sans planter."""
    _, public_key = rsa_keys
    private_key, _ = rsa_keys

    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")

    encrypted_path = tmp_path / "empty.txt.enc"
    decrypted_path = tmp_path / "empty_decrypted.txt"

    crypto.encrypt_file(str(empty_file), str(encrypted_path), public_key)
    crypto.decrypt_file(str(encrypted_path), str(decrypted_path), private_key)

    assert decrypted_path.read_bytes() == b""