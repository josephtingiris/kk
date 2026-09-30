#!/usr/bin/env bats
#
# kk - comprehensive bats test suite
# Run:  bats ~/tests/bats/kk.bats
#
# Covers: every action, every modifier flag, flag permutations and
# combinations, error paths, tamper detection, mtime round-trip,
# JSON output validity, and a multi-file stress pass.

setup_file() {
    SAFE_XDG_RUNTIME_DIR=$(assembly_runtime_dir || true)
    RUNTIME_PARENT=$(assembly_parent || true)
    RUNTIME_SNAPSHOT_FILE=$(mktemp)
    export RUNTIME_PARENT RUNTIME_SNAPSHOT_FILE SAFE_XDG_RUNTIME_DIR
    runtime_snapshot > "$RUNTIME_SNAPSHOT_FILE"
}

setup() {
    WORKDIR=$(mktemp -d)
    cd "$WORKDIR" || exit 1
    export KK=~/bin/kk
    unset KAUTHORITY KK_PPFILE KK_PP KK_SESSION KK_DIR KK_DIR_TYPE KK_CHECKSUM
    if [[ -n "${SAFE_XDG_RUNTIME_DIR:-}" ]]; then
        export XDG_RUNTIME_DIR="$SAFE_XDG_RUNTIME_DIR"
    fi
    printf 'test-pass-123\n' > pp
    printf 'wrong-pass-999\n' > ppwrong
    chmod 600 pp ppwrong
}

teardown_file() {
    rm -f -- "${RUNTIME_SNAPSHOT_FILE:-}"
}

teardown() {
    cd /
    rm -rf "$WORKDIR"
}

# -- helpers --
cap() { # cap <stdin-line> <cmd...> -> cap_out / cap_status
    # `|| cap_status=$?` keeps bats' set -e from killing the test on failure
    local input="$1"
    shift
    cap_status=0
    cap_out=$("$@" <<< "$input" 2>&1) || cap_status=$?
}

valid_json() { python3 -m json.tool <<< "$1" > /dev/null 2>&1; }

asset_count() { ls .kk/*.kk 2> /dev/null | wc -l; }

asset_header_decode() { head -n 1 -- "$1" | base64 -d; }

asset_header_get() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1; }

asset_payload_rewrite() { # $1 = asset, $2 = replacement payload.tar.gz
    local asset="$1" replacement_payload="$2"
    local auth_header_file auth_input_file hdr hlen meta_plaintext_file metadata_auth_salt
    local metadata_bytes metadata_file metadata_hmac metadata_key payload_file payload_hmac payload_key payload_salt
    local payload_sha512 passphrase

    hdr=$(asset_header_decode "$asset")
    hlen=$(head -n 1 -- "$asset" | wc -c)
    metadata_bytes=$(asset_header_get "$hdr" metadata_bytes)
    metadata_file="$WORKDIR/meta.enc"
    meta_plaintext_file="$WORKDIR/meta.txt"
    payload_file="$WORKDIR/payload.enc"
    auth_header_file="$WORKDIR/auth.header"
    auth_input_file="$WORKDIR/auth.input"
    passphrase=$(head -n 1 pp 2> /dev/null || true)

    tail -c +$((hlen + 1)) "$asset" | head -c "$metadata_bytes" > "$metadata_file"
    printf '%s\n' "$passphrase" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -pass stdin \
        -in "$metadata_file" -out "$meta_plaintext_file" 2> /dev/null
    payload_sha512=$(openssl dgst -sha512 -r "$replacement_payload" | cut -d' ' -f1)
    sed -i "s/^payload_sha512=.*/payload_sha512=$payload_sha512/" "$meta_plaintext_file"
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -salt -pass stdin \
        -in "$meta_plaintext_file" -out "$metadata_file" 2> /dev/null
    metadata_bytes=$(stat -c %s -- "$metadata_file")

    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -salt -pass stdin \
        -in "$replacement_payload" -out "$payload_file" 2> /dev/null

    printf '%s\n' \
        "magic=$(asset_header_get "$hdr" magic)" \
        "version=$(asset_header_get "$hdr" version)" \
        "auth_scheme=$(asset_header_get "$hdr" auth_scheme)" \
        "cipher=$(asset_header_get "$hdr" cipher)" \
        "kdf=$(asset_header_get "$hdr" kdf)" \
        "iter=$(asset_header_get "$hdr" iter)" \
        "metadata_auth_salt=$(asset_header_get "$hdr" metadata_auth_salt)" \
        "metadata_bytes=$metadata_bytes" \
        "payload_auth_salt=$(asset_header_get "$hdr" payload_auth_salt)" > "$auth_header_file"

    metadata_auth_salt=$(asset_header_get "$hdr" metadata_auth_salt)
    payload_salt=$(asset_header_get "$hdr" payload_auth_salt)
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -S "$metadata_auth_salt" -P -pass stdin > "$WORKDIR/keymeta.out" 2> /dev/null
    metadata_key=$(sed -n 's/^key=//p' "$WORKDIR/keymeta.out" | head -n 1 | tr '[:upper:]' '[:lower:]')
    {
        cat "$auth_header_file"
        printf '\n'
        cat "$metadata_file"
    } > "$auth_input_file"
    metadata_hmac=$(openssl mac -digest sha512 -macopt "hexkey:$metadata_key" -in "$auth_input_file" HMAC 2> /dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\n\r')
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -S "$payload_salt" -P -pass stdin > "$WORKDIR/key.out" 2> /dev/null
    payload_key=$(sed -n 's/^key=//p' "$WORKDIR/key.out" | head -n 1 | tr '[:upper:]' '[:lower:]')
    {
        cat "$auth_header_file"
        printf '\n'
        cat "$metadata_file"
        cat "$payload_file"
    } > "$auth_input_file"
    payload_hmac=$(openssl mac -digest sha512 -macopt "hexkey:$payload_key" -in "$auth_input_file" HMAC 2> /dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\n\r')
    hdr=$(printf '%s\n' "$hdr" | sed "s/^metadata_bytes=.*/metadata_bytes=$metadata_bytes/" | sed "s/^metadata_hmac=.*/metadata_hmac=$metadata_hmac/" | sed "s/^payload_hmac=.*/payload_hmac=$payload_hmac/")
    {
        printf '%s\n' "$(printf '%s\n' "$hdr" | base64 -w0)"
        cat "$metadata_file"
        cat "$payload_file"
    } > "$asset"
}

assembly_runtime_dir() {
    local candidate fstype mode uid
    uid=$(id -u)

    for candidate in "${XDG_RUNTIME_DIR:-}" "/run/user/$uid"; do
        [[ -n "$candidate" && -d "$candidate" ]] || continue
        mode=$(stat -c %a -- "$candidate" 2> /dev/null || true)
        fstype=$(stat -f -c %T -- "$candidate" 2> /dev/null || true)
        if [[ "$mode" == "700" && "$fstype" == "tmpfs" && -O "$candidate" ]]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done

    return 1
}

assembly_parent() {
    local runtime_dir
    runtime_dir=$(assembly_runtime_dir) || return 1
    printf '%s/.kk\n' "$runtime_dir"
}

assembly_namespace_dir() {
    local kk_dir_real="$1" parent
    parent=$(assembly_parent) || return 1
    printf '%s/%s\n' "$parent" "$(printf '%s' "$kk_dir_real" | openssl dgst -sha256 -r | cut -c1-16)"
}

runtime_snapshot() {
    if [[ -n "${RUNTIME_PARENT:-}" && -d "${RUNTIME_PARENT:-}" ]]; then
        find "$RUNTIME_PARENT" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort
    fi
}

runtime_print_new_namespaces() {
    local current
    current=$(mktemp)
    runtime_snapshot > "$current"
    comm -13 "$RUNTIME_SNAPSHOT_FILE" "$current"
    rm -f -- "$current"
}

enc() { run "$KK" "$@" --encrypt --ppfile pp; }
dec() { run "$KK" "$@" --decrypt --ppfile pp; }

# ======================== stress ========================

@test "stress: 20 files encrypt + check + decrypt + compare" {
    local i
    mkdir -p src && cd src
    for i in $(seq 1 20); do
        head -c $((i * 137)) /dev/urandom | base64 > "file_$i.bin"
        sha256sum "file_$i.bin" | cut -d' ' -f1 > "file_$i.sha"
    done
    run "$KK" --encrypt file_1.bin --ppfile "$WORKDIR/pp"
    [ "$status" -eq 0 ]
    for i in $(seq 2 20); do
        run "$KK" --encrypt "file_$i.bin" --ppfile "$WORKDIR/pp"
        [ "$status" -eq 0 ]
    done
    [ "$(asset_count)" -eq 20 ]
    # originals still present; check must pass
    run "$KK" --check --ppfile "$WORKDIR/pp"
    [ "$status" -eq 0 ]
    # move originals away, decrypt everything back
    mkdir -p bak && mv file_*.bin bak/
    for i in $(seq 1 20); do
        run "$KK" "file_$i.bin" --decrypt --yes --ppfile "$WORKDIR/pp"
        [ "$status" -eq 0 ]
    done
    local bad=0
    for i in $(seq 1 20); do
        local want got
        want=$(cat "file_$i.sha")
        got=$(sha256sum "file_$i.bin" | cut -d' ' -f1)
        [ "$want" = "$got" ] || bad=$((bad + 1))
    done
    [ "$bad" -eq 0 ]
    run "$KK" --check --ppfile "$WORKDIR/pp"
    [ "$status" -eq 0 ]
}

@test "stress: directory with 100 files round-trips" {
    mkdir big
    local i
    for i in $(seq 1 100); do
        printf 'content-%s\n' "$i" > "big/f$i.txt"
    done
    run "$KK" big --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -rf big
    run "$KK" big --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f big/f1.txt ]
    [ -f big/f100.txt ]
    [ "$(cat big/f42.txt)" = "content-42" ]
    [ "$(ls big | wc -l)" -eq 100 ]
    run "$KK" --check --ppfile pp
    [ "$status" -eq 0 ]
}

@test "stress: concurrent encrypts sharing KK_DIR leave no residue" {
    local shared_kk="$WORKDIR/shared-concurrent-assets"
    local namespace runs_dir rc=0 i pid
    local -a pids=()

    namespace=$(assembly_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    runs_dir="$namespace/runs"

    mkdir -p src && cd src
    for i in $(seq 1 8); do
        printf 'content-%s\n' "$i" > "f$i.txt"
    done

    for i in $(seq 1 8); do
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --encrypt --yes --ppfile "$WORKDIR/pp" > "job.$i.out" 2>&1 &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || rc=1
    done

    [ "$rc" -eq 0 ]
    [ "$(find "$shared_kk" -maxdepth 1 -name "*.kk" | wc -l)" -eq 8 ]
    [ "$(find "$shared_kk" -maxdepth 1 -name ".pending.runid-*" | wc -l)" -eq 0 ]
    [ ! -d "$namespace" ]

    for i in $(seq 1 8); do
        ! grep -q "kk: error:" "job.$i.out"
        ! grep -q "orphan namespace scan lock" "job.$i.out"
        ! grep -q "unexpected runtime namespace entry" "job.$i.out"
    done
}

@test "stress: concurrent decrypts sharing KK_DIR leave no residue" {
    local shared_kk="$WORKDIR/shared-concurrent-decrypt-assets"
    local namespace runs_dir rc=0 i pid
    local -a pids=()

    namespace=$(assembly_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    runs_dir="$namespace/runs"

    mkdir -p src bak && cd src
    for i in $(seq 1 4); do
        printf 'payload-%s\n' "$i" > "f$i.txt"
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --encrypt --ppfile "$WORKDIR/pp" > /dev/null 2>&1
        mv "f$i.txt" ../bak/
    done

    for i in $(seq 1 4); do
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --decrypt --yes --ppfile "$WORKDIR/pp" > "job.dec.$i.out" 2>&1 &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || rc=1
    done

    [ "$rc" -eq 0 ]
    for i in $(seq 1 4); do
        cmp -s "f$i.txt" "../bak/f$i.txt"
    done
    [ "$(find "$shared_kk" -maxdepth 1 -name ".pending.runid-*" | wc -l)" -eq 0 ]
    [ ! -d "$namespace" ]

    for i in $(seq 1 4); do
        ! grep -q "kk: error:" "job.dec.$i.out"
        ! grep -q "orphan namespace scan lock" "job.dec.$i.out"
        ! grep -q "unexpected runtime namespace entry" "job.dec.$i.out"
    done
}

@test "stress: rapid-fire encrypts never lose an asset" {
    local i
    for i in $(seq 1 10); do
        echo "rapid-$i" > "r$i.txt"
        run "$KK" "r$i.txt" --encrypt --ppfile pp
        [ "$status" -eq 0 ]
    done
    [ "$(asset_count)" -eq 10 ]
}
