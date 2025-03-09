# shellthings

This is just a place to keep some shell utilities I've written for personal use.

## secret

A simple secret manager for the shell, wrapping GNUPG. There are both bash and Python implementations.

The lookup key for secrets is determined using the PBKDF2 algorithm and SHA-384 hash function to index the key values for lookup. The secrets themselves are encrypted with GnuPG using AES-256. The GnuPG key is a 4096 bit RSA key with 2 year expiration. The encrypted data is stored in ```~/.secrets/```.

Note: The PBKDF2 salt is encrypted.  This is done because key values could be very guessable. Encrypting the salt prevents an attacker from brute-force guessing the lookup key.

### CLI

```
$ source ./secret.sh

$ secret
Usage: /opt/homebrew/bin/bash set|get|rm key

$ secret set key
Enter secret value:

$ printf "Secret key: %s\n" "$(secret get key)"
Secret key: hi there

$ secret rm key
```

### Python

Use in a Python program.

```python
import secret

vault = secret.SecretVault()
vault.set("key")
vault.get("key")
vault.rm("key")
```

Install as a script.

```
$ uv sync

$ printf "Secret key: %s\n" "$(secret get key)"
Secret key: hi there
```
