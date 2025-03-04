secret() (
    secrets_dir="$HOME"/.secrets
    
    salt() {
        local saltfile="${secrets_dir}/salt"
        if [[ ! -f "$saltfile" ]]
        then
            openssl rand -hex 32 > "$saltfile"
        fi
        printf "%s" $(<"$saltfile")
    }
    
    mkdir -p "$secrets_dir"
    keyfile="${secrets_dir}/$(sha224 -s "$1$(salt)").gpg"
    # look up a key
    if [ $# -eq 1 ]
    then
        if [[ -f "$keyfile" ]]
        then
            gpg --quiet --batch --decrypt "$keyfile"
        else
            >&2 echo "Key not found."
            exit 1
        fi
    elif [ $# -eq 2 ] # set a key
    then
        printf "$2" | gpg -c --output "$keyfile"
    else
        >&2 echo "Usage: $0 key [value]"
        exit 1
    fi    
)

