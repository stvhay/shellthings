# shellthings

This is just a place to keep some shell utilities I've written for personal use.

## secret

A simple secret manager for the shell, wrapping GNUPG. There are both bash and Python implementations.

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

```python
import secret

vault = secret.SecretVault()
vault.set("key")
vault.get("key")
vault.rm("key")
```
