secret() (
  secrets_dir="$HOME"/.secrets

  encrypt() { gpg -c --output "$1"; }
  decrypt() { gpg --quiet --batch --decrypt "$1"; }
  hash()    { printf "%s" "$1" | openssl dgst -sha512 | awk '{print $2}'; }

  salt() {
    local saltfile="${secrets_dir}/salt"
    if [[ ! -f "$saltfile" ]]
    then
      openssl rand -hex 32 | encrypt "$saltfile"
    fi
    decrypt "$saltfile"
  }

    
  mkdir -p "$secrets_dir"
  chmod 700 "$secrets_dir"
  if [ $# -eq 2 ]
  then
    keyfile="${secrets_dir}/$(hash "$2$(salt)").gpg"
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
        read -s -p "Enter secret value: " secret
        printf "%s" "$secret" | encrypt "$keyfile"
        ;;
      *)
        >&2 echo "Invalid command: $1"
        exit 1
        ;;
    esac
  else
    >&2 echo "Usage: $0 set|get key"
    exit 1
  fi    
)

