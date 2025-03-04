import argparse
import getpass
import sys

from .secret_vault import SecretVault


def main():
    """Main function to handle command-line operations."""
    parser = argparse.ArgumentParser(
        description="A simple secret vault using GPG encryption."
    )
    parser.add_argument(
        "command", choices=["get", "set", "rm"], help="Command to perform"
    )
    parser.add_argument("key", help="Lookup key (string) for the secret")
    args = parser.parse_args()

    vault = SecretVault()
    command = args.command
    key = args.key

    try:
        if command == "get":
            secret = vault.get(key)
            print(secret, end="")
        elif args.action == "set":
            value = getpass("Enter secret value: ")
            vault.set(args.key, value)
        elif args.action == "rm":
            vault.rm(args.key)
    except (KeyError, SecretVaultError) as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
