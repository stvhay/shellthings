import binascii
import datetime
import hashlib
import os
import socket

import gnupg


class SecretVaultError(Exception):
    """Custom exception for SecretVault-related errors."""

    pass


class SecretVault:
    """A class to manage encrypted secrets using GPG."""

    def __init__(self):
        """Initialize the SecretVault."""
        self._secrets_dir = os.path.join(os.path.expanduser("~"), ".secrets")
        self._saltfile = os.path.join(self._secrets_dir, "salt")

        os.makedirs(self._secrets_dir, exist_ok=True)
        os.chmod(self._secrets_dir, 0o700)
        fqdn = socket.getfqdn().split(".", 1)[1]
        self._email = f"secret@{fqdn}"
        self._gpg = gnupg.GPG()
        self._name = os.getlogin()
        self._genkey()

    def _pbkdf(self, data, salt, iterations=100000):
        """Generate a secure hash using PBKDF2 with SHA-384."""
        return (
            hashlib.pbkdf2_hmac(
                "sha384", data.encode("utf-8"), salt.encode("utf-8"), iterations
            )
            .hex()
            .lower()
        )

    def _encrypt(self, data, output_file):
        """Encrypt data and save to output file."""
        encrypted_data = self._gpg.encrypt(
            data,
            recipients=[self._email],
            output=output_file,
            extra_args=["--cipher-algo", "AES256"],
        )
        if not encrypted_data.ok:
            raise SecretVaultError(f"Encryption failed: {encrypted_data.status}")

    def _decrypt(self, input_file):
        """Decrypt data from input file."""
        with open(input_file, "rb") as f:
            decrypted_data = self._gpg.decrypt_file(f)
        if not decrypted_data.ok:
            raise SecretVaultError(f"Decryption failed: {decrypted_data.status}")
        return str(decrypted_data)

    def _expiry(self):
        """Calculate expiry date based on NIST SP 800-57 Part 1 Rev. 5 guidance"""
        days = 2 * 365  # Table 1
        return datetime.datetime.now() + datetime.timedelta(days=days)

    def _genkey(self):
        """Generate GPG key if it doesn't exist."""
        keys = self._gpg.list_keys()
        expires = self._expiry()
        if not any(self._email in key["uids"][0] for key in keys):
            input_data = self._gpg.gen_key_input(
                name_real=self._name,
                name_email=self._email,
                key_type="RSA",
                key_length=4096,
                subkey_type="RSA",
                subkey_length=4096,
                expire_date="2y",
            )
            key = self._gpg.gen_key(input_data)

    def _salt(self):
        """Get or generate salt for key derivation."""
        if not os.path.exists(self._saltfile):
            salt = binascii.hexlify(os.urandom(32)).decode()
            self._encrypt(salt, self._saltfile)
        return self._decrypt(self._saltfile).strip()

    def _keyfile(self, key):
        """Generate a keyfile path for a given key."""
        p_hash = self._pbkdf(key, self._salt())
        filename = f"{p_hash}.gpg"
        return os.path.join(self._secrets_dir, filename)

    def get(self, key):
        """Retrieve a secret value for a given key."""
        keyfile = self._keyfile(key)
        if os.path.exists(keyfile):
            return self._decrypt(keyfile)
        else:
            raise KeyError("Key not found.")

    def set(self, key, value):
        """Set a secret value for a given key."""
        keyfile = self._keyfile(key)
        self._encrypt(value, keyfile)

    def rm(self, key):
        """Remove a secret for a given key."""
        keyfile = self._keyfile(key)
        if os.path.exists(keyfile):
            os.remove(keyfile)
