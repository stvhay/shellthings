# Uses GPG to make an encryption key for a simple vault. Commands 'set', 'get',
# and 'rm' are supported. Key values are hashed with an encrypted salt.
secret()
(
    secrets_dir="$HOME"/.secrets

    name()    { printf "%s" "$(whoami)"; }
    email()   { printf "%s" "secret@$(hostname -d)"; }
    encrypt() { gpg --quiet --encrypt --recipient "$(email)" --output "$1"; }
    decrypt() { gpg --quiet --decrypt "$1"; }
    pbkdf() {
        openssl kdf -keylen 32 \
            -kdfopt digest:SHA256 \
            -kdfopt pass:"$1" \
            -kdfopt salt:"$2" \
            -kdfopt iter:"100000" \
            PBKDF2 | tr -d :
    }
    expiry()  { date -d "+2 years" +%Y-%m-%d; }

    # Generate GPG key if it doesn't exist.
    genkey()
    { 
        if ! gpg --list-keys | grep --quiet "$(email)"
        then
            local fingerprint
            gpg --batch --quick-generate-key "$(name) <$(email)>" rsa4096 default "$(expiry)"
            fingerprint=$(gpg --list-secret-keys --with-colons "$(email)" | grep '^fpr' | head -n1 | awk -F: '/^fpr/ {print $10}' )
            gpg --batch --quick-add-key "$fingerprint" rsa4096 encrypt "$(expiry)"
        fi
    }

    # Get or generate salt for key derivation.
    salt() 
    {
        local saltfile="${secrets_dir}/salt"
        if [[ ! -f "$saltfile" ]]
        then
            openssl rand -hex 32 | encrypt "$saltfile"
        fi
        decrypt "$saltfile"
    }

    initialize()
    {
        mkdir -p  "$secrets_dir"
        chmod 700 "$secrets_dir"
        genkey
    }

    initialize
    if [ $# -eq 2 ]
    then
        keyfile="${secrets_dir}/$(pbkdf "$2" "$(salt)").gpg"
        case "$1" in
            get)
                if [[ -f "$keyfile" ]]
                then
                    decrypt "$keyfile"
                else
                    >&2 echo "Key not found."
                    exit 1
                fi
                ;;
            set)
                read -r -s -p "Enter secret value: " secret
                printf "%s" "$secret" | encrypt "$keyfile"
                ;;
            rm)
                rm -f "$keyfile"
                ;;
            *)
                >&2 echo "Invalid command: $1"
                exit 1
                ;;
        esac
    else
        >&2 echo "Usage: $0 set|get|rm key"
        exit 1
    fi    
)
