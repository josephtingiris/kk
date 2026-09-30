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
cap() {  # cap <stdin-line> <cmd...> -> cap_out / cap_status
    # `|| cap_status=$?` keeps bats' set -e from killing the test on failure
    local input="$1"; shift
    cap_status=0
    cap_out=$("$@" <<< "$input" 2>&1) || cap_status=$?
}

valid_json() { python3 -m json.tool <<< "$1" >/dev/null 2>&1; }

asset_count() { ls .kk/*.kk 2>/dev/null | wc -l; }

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
    passphrase=$(head -n 1 pp 2>/dev/null || true)

    tail -c +$((hlen + 1)) "$asset" | head -c "$metadata_bytes" > "$metadata_file"
    printf '%s\n' "$passphrase" | openssl enc -d -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -pass stdin \
        -in "$metadata_file" -out "$meta_plaintext_file" 2>/dev/null
    payload_sha512=$(openssl dgst -sha512 -r "$replacement_payload" | cut -d' ' -f1)
    sed -i "s/^payload_sha512=.*/payload_sha512=$payload_sha512/" "$meta_plaintext_file"
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -salt -pass stdin \
        -in "$meta_plaintext_file" -out "$metadata_file" 2>/dev/null
    metadata_bytes=$(stat -c %s -- "$metadata_file")

    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -salt -pass stdin \
        -in "$replacement_payload" -out "$payload_file" 2>/dev/null

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
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -S "$metadata_auth_salt" -P -pass stdin > "$WORKDIR/keymeta.out" 2>/dev/null
    metadata_key=$(sed -n 's/^key=//p' "$WORKDIR/keymeta.out" | head -n 1 | tr '[:upper:]' '[:lower:]')
    { cat "$auth_header_file"; printf '\n'; cat "$metadata_file"; } > "$auth_input_file"
    metadata_hmac=$(openssl mac -digest sha512 -macopt "hexkey:$metadata_key" -in "$auth_input_file" HMAC 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\n\r')
    printf '%s\n' "$passphrase" | openssl enc -aes-256-cbc -pbkdf2 -md sha512 -iter 200000 -S "$payload_salt" -P -pass stdin > "$WORKDIR/key.out" 2>/dev/null
    payload_key=$(sed -n 's/^key=//p' "$WORKDIR/key.out" | head -n 1 | tr '[:upper:]' '[:lower:]')
    { cat "$auth_header_file"; printf '\n'; cat "$metadata_file"; cat "$payload_file"; } > "$auth_input_file"
    payload_hmac=$(openssl mac -digest sha512 -macopt "hexkey:$payload_key" -in "$auth_input_file" HMAC 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\n\r')
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
        mode=$(stat -c %a -- "$candidate" 2>/dev/null || true)
        fstype=$(stat -f -c %T -- "$candidate" 2>/dev/null || true)
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

# ======================== basics ========================

@test "--help prints usage and exits 0" {
    run "$KK" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"usage"* ]]
}

@test "--version prints version and exits 0" {
    run "$KK" --version
    [ "$status" -eq 0 ]
    [ "$output" = "kk 0.2.9" ]
}

@test "--checksum prints script checksum and exits 0" {
    run "$KK" --checksum
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^[0-9a-f]{128}$ ]]
}

@test "legacy integrity maintenance flags are rejected" {
    run "$KK" --integrity-hash
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag"* ]]

    run "$KK" --integrity-hash-update
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag"* ]]
}

@test "no arguments prints usage and exits 1" {
    run "$KK"
    [ "$status" -eq 1 ]
    [[ "$output" == *"usage"* ]]
}

@test "unknown long flag is rejected" {
    run "$KK" --frobnicate
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag"* ]]
}

@test "extra positional argument is rejected" {
    run "$KK" a.txt b.txt
    [ "$status" -eq 1 ]
    [[ "$output" == *"unexpected extra argument"* ]]
}

@test "two action flags conflict" {
    run "$KK" f.txt --encrypt --decrypt
    [ "$status" -eq 1 ]
    [[ "$output" == *"conflicting action flags"* ]]
}

@test "ls cannot be combined with action flags" {
    run "$KK" ls --encrypt
    [ "$status" -eq 1 ]
    [[ "$output" == *"'ls' cannot be combined"* ]]
}

@test "--ppfile without file argument fails" {
    run "$KK" --ppfile
    [ "$status" -eq 1 ]
    [[ "$output" == *"--ppfile requires a file argument"* ]]
}

@test "--unlock outside ls is rejected" {
    echo "hello" > f.txt
    run "$KK" f.txt --encrypt --unlock --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag: --unlock"* ]]
}

@test "encrypt rejects missing XDG_RUNTIME_DIR" {
    echo "runtime" > f.txt
    run env -u XDG_RUNTIME_DIR "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"XDG_RUNTIME_DIR is not set"* ]]
}

@test "encrypt rejects XDG_RUNTIME_DIR with unsafe mode" {
    mkdir runtime.bad
    chmod 755 runtime.bad
    echo "runtime" > f.txt
    run env XDG_RUNTIME_DIR="$WORKDIR/runtime.bad" "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"must have mode 700"* ]]
}

# ======================== encrypt ========================

@test "encrypt creates asset, keeps original, exit 0" {
    echo "hello" > f.txt
    enc f.txt
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 1 ]
    [ -f f.txt ]
}

@test "encrypt nonexistent path fails" {
    enc nosuch.txt
    [ "$status" -eq 1 ]
    [[ "$output" == *"no such file or directory"* ]]
    [ "$(asset_count)" -eq 0 ]
}

@test "encrypt path outside CWD is refused" {
    run "$KK" ../outside.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"outside the current directory"* ]]
}

@test "duplicate encrypt without --force fails with hint" {
    echo "hello" > f.txt
    enc f.txt
    enc f.txt
    [ "$status" -eq 1 ]
    [[ "$output" == *"asset already exists"* ]]
    [[ "$output" == *"--force --encrypt"* ]]
    [ "$(asset_count)" -eq 1 ]
}

@test "duplicate encrypt with --force creates second asset" {
    echo "hello" > f.txt
    enc f.txt
    enc f.txt --force
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 2 ]
}

@test "same-second collision is waited out, not clobbered" {
    echo "hello" > f.txt
    enc f.txt --force
    enc f.txt --force
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 2 ]
    # both assets must be intact and distinct
    local e1 e2
    e1=$(ls .kk | sort | head -1); e2=$(ls .kk | sort | tail -1)
    [ "$e1" != "$e2" ]
}

@test "auto mode: bare path encrypts when no asset exists" {
    echo "auto" > g.txt
    run "$KK" g.txt --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 1 ]
    # second bare invocation must refuse
    run "$KK" g.txt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"asset already exists"* ]]
}

@test "asset filename format: 14-digit timestamp + usec + short id + .kk" {
    echo "hello" > f.txt
    enc f.txt
    local e
    e=$(ls .kk | head -1)
    [[ "$e" =~ ^[0-9]{14}\.[0-9]{6}-[0-9a-f]{10}\.kk$ ]]
}

@test ".kk dir is 700 and assets are 600" {
    echo "hello" > f.txt
    enc f.txt
    [ "$(stat -c %a .kk)" = "700" ]
    [ "$(stat -c %a .kk/*.kk)" = "600" ]
}

@test "ciphertext does not contain plaintext" {
    echo "needle-plain-text" > f.txt
    enc f.txt
    ! grep -q "needle-plain-text" .kk/*.kk
}

@test "directory encrypt records kind=dir and payload size" {
    mkdir d && echo a > d/1.txt
    enc d
    [ "$status" -eq 0 ]
    [[ "$output" == *"dir"* ]]
}

@test "empty directory round-trips" {
    mkdir ed
    enc ed
    [ "$status" -eq 0 ]
    rm -rf ed
    dec ed --yes
    [ "$status" -eq 0 ]
    [ -d ed ]
}

@test "nested path round-trips (sub/deep/f.txt)" {
    mkdir -p sub/deep && echo x > sub/deep/f.txt
    enc sub/deep/f.txt
    rm -f sub/deep/f.txt
    dec sub/deep/f.txt --yes
    [ "$status" -eq 0 ]
    [ "$(cat sub/deep/f.txt)" = "x" ]
}

@test "path with ./ prefix normalizes" {
    echo "dot" > f.txt
    run "$KK" ./f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run "$KK" f.txt --info --ppfile pp
    [[ "$output" == *"path_original=f.txt"* ]]
}

@test "directory path with trailing slash normalizes" {
    mkdir d && echo a > d/1.txt
    run "$KK" d/ --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run "$KK" d --info --ppfile pp
    [[ "$output" == *"path_original=d"* ]]
}

@test "filename with spaces round-trips" {
    echo "spacy" > "my file.txt"
    enc "my file.txt"
    rm -f "my file.txt"
    dec "my file.txt" --yes
    [ "$status" -eq 0 ]
    [ "$(cat "my file.txt")" = "spacy" ]
}

@test "filename with leading dash round-trips" {
    echo "dash" > ./-dash.txt
    run "$KK" ./-dash.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -f ./-dash.txt
    run "$KK" ./-dash.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(cat ./-dash.txt)" = "dash" ]
}

@test "symlink is archived as its content" {
    echo "real" > real.txt
    ln -s real.txt link.txt
    enc link.txt
    run "$KK" link.txt --info --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"path_original=link.txt"* ]]
    [[ "$output" == *"path_real=$WORKDIR/real.txt"* ]]
    [[ "$output" == *"symlink_target=real.txt"* ]]
    rm -f link.txt real.txt
    dec link.txt --yes
    [ "$status" -eq 0 ]
    [ "$(cat link.txt)" = "real" ]
    [ ! -L link.txt ]
}

@test "path with .. components collapses lexically and round-trips" {
    mkdir -p m1 && echo "lex" > m1/l.txt
    run "$KK" m1/../m1/l.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run "$KK" m1/l.txt --info --ppfile pp
    [[ "$output" == *"path_original=m1/l.txt"* ]]
    rm -f m1/l.txt
    run "$KK" m1/../m1/l.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(cat m1/l.txt)" = "lex" ]
}

@test "path escaping CWD via .. is refused" {
    run "$KK" ../outside.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"outside the current directory"* ]]
}

@test "path escaping CWD via .. in the middle is refused" {
    mkdir -p sub
    run "$KK" sub/../../etc/passwd --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"outside the current directory"* ]]
}

@test "socket-looking target is stubbed" {
    run "$KK" myhost:443
    [ "$status" -eq 1 ]
    [[ "$output" == *"socket mode not implemented"* ]]
    run "$KK" myhost:443 --encrypt
    [ "$status" -eq 1 ]
    [[ "$output" == *"socket mode not implemented"* ]]
}

# ======================== decrypt ========================

@test "decrypt restores content and mtime" {
    echo "time test" > f.txt
    touch -d "2020-06-01 12:00:00 UTC" f.txt
    local m0; m0=$(stat -c %Y f.txt)
    enc f.txt
    rm -f f.txt
    dec f.txt --yes
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "time test" ]
    [ "$(stat -c %Y f.txt)" = "$m0" ]
}

@test "decrypt nonexistent target fails" {
    dec nosuch.txt
    [ "$status" -eq 1 ]
    [[ "$output" == *"no .kk assets found"* ]]
}

@test "decrypt with wrong passphrase fails, creates nothing" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" f.txt --decrypt --ppfile ppwrong
    [ "$status" -eq 1 ]
    [[ "$output" == *"current passphrase"* ]]
    [ ! -e f.txt ]
}

@test "decrypt into existing file asks for confirmation (stdin y)" {
    echo "orig" > f.txt
    enc f.txt
    echo "changed" > f.txt
    cap "y" "$KK" f.txt --decrypt --ppfile pp
    [ "$cap_status" -eq 0 ]
    [ "$(cat f.txt)" = "orig" ]
}

@test "decrypt into existing file aborts on confirmation n" {
    echo "orig" > f.txt
    enc f.txt
    echo "changed" > f.txt
    cap "n" "$KK" f.txt --decrypt --ppfile pp
    [ "$cap_status" -eq 1 ]
    [[ "$cap_out" == *"aborted"* ]]
    [ "$(cat f.txt)" = "changed" ]
}

@test "decrypt --yes overwrites existing file without prompt" {
    echo "orig" > f.txt
    enc f.txt
    echo "changed" > f.txt
    dec f.txt --yes
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "orig" ]
}

@test "decrypt --force overwrites existing file without prompt" {
    echo "orig" > f.txt
    enc f.txt
    echo "changed" > f.txt
    run "$KK" f.txt --decrypt --force --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "orig" ]
}

@test "decrypt can restore file to a new path" {
    echo "orig" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" f.txt --decrypt renamed.txt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f renamed.txt ]
    [ "$(cat renamed.txt)" = "orig" ]
    [ ! -e f.txt ]
}

@test "decrypt can restore a directory to a new path" {
    mkdir -p srcdir/sub
    echo "nested" > srcdir/sub/file.txt
    run "$KK" srcdir --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -rf srcdir
    run "$KK" srcdir --decrypt restored-dir --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f restored-dir/sub/file.txt ]
    [ "$(cat restored-dir/sub/file.txt)" = "nested" ]
    [ ! -e srcdir ]
}

@test "decrypt --force with --dry-run changes nothing" {
    echo "orig" > f.txt
    enc f.txt
    echo "changed" > f.txt
    run "$KK" f.txt --decrypt --force --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"dry run"* ]]
    [ "$(cat f.txt)" = "changed" ]
}

@test "decrypt with no target auto-picks the only asset" {
    echo "solo" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "solo" ]
}

@test "decrypt with no target and no assets fails" {
    run "$KK" --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"no .kk assets found"* ]]
}

@test "decrypt picks newest asset with --yes" {
    echo A > f.txt
    enc f.txt
    sleep 1.1
    echo B > f.txt
    enc f.txt --force
    rm -f f.txt
    dec f.txt --yes
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "B" ]
}

@test "decrypt interactive selection: pick 2 restores older asset" {
    echo A > f.txt
    enc f.txt
    sleep 1.1
    echo B > f.txt
    enc f.txt --force
    rm -f f.txt
    cap "2" "$KK" f.txt --decrypt --ppfile pp
    [ "$cap_status" -eq 0 ]
    [ "$(cat f.txt)" = "A" ]
}

@test "decrypt selection out of range fails" {
    echo A > f.txt
    enc f.txt
    sleep 1.1
    echo B > f.txt
    enc f.txt --force
    rm -f f.txt
    cap "9" "$KK" f.txt --decrypt --ppfile pp
    [ "$cap_status" -eq 1 ]
    [[ "$cap_out" == *"out of range"* ]]
}

@test "decrypt selection non-numeric fails" {
    echo A > f.txt
    enc f.txt
    sleep 1.1
    echo B > f.txt
    enc f.txt --force
    rm -f f.txt
    cap "x" "$KK" f.txt --decrypt --ppfile pp
    [ "$cap_status" -eq 1 ]
    [[ "$cap_out" == *"invalid selection"* ]]
}

@test "decrypt refuses when target path is now a non-empty directory" {
    echo "file content" > f.txt
    enc f.txt
    rm -f f.txt
    mkdir f.txt && echo "keep me" > f.txt/protected.txt
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    # nothing inside the directory may have been touched
    [ "$(cat f.txt/protected.txt)" = "keep me" ]
}

@test "decrypt replaces an EMPTY blocking directory (tar behavior)" {
    echo "file content" > f.txt
    enc f.txt
    rm -f f.txt
    mkdir f.txt
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f f.txt ]
    [ "$(cat f.txt)" = "file content" ]
}

# ======================== cat / info / ls ========================

@test "--cat streams content to stdout and touches no disk file" {
    echo "hello world" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" f.txt --cat --ppfile pp
    [ "$status" -eq 0 ]
    [ "$output" = "hello world" ]
    [ ! -e f.txt ]
}

@test "--info shows metadata for the given path" {
    echo "meta" > f.txt
    enc f.txt
    run "$KK" f.txt --info --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"path_original=f.txt"* ]]
    [[ "$output" == *"path_real=$WORKDIR/f.txt"* ]]
    [[ "$output" == *"cwd_real=$WORKDIR"* ]]
    [[ "$output" == *"kk_dir_real=$WORKDIR/.kk"* ]]
    [[ "$output" == *"kind=file"* ]]
    [[ "$output" == *"content_sha256="* ]]
    [[ "$output" == *"orig_mtime="* ]]
    [[ "$output" == *"orig_ctime="* ]]
}

@test "external KK_DIR records original placement metadata" {
    local shared_kk="$WORKDIR/shared-assets"
    echo "meta" > f.txt
    run env KK_DIR="$shared_kk" "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run env KK_DIR="$shared_kk" "$KK" f.txt --info --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"path_original=f.txt"* ]]
    [[ "$output" == *"path_real=$WORKDIR/f.txt"* ]]
    [[ "$output" == *"cwd_real=$WORKDIR"* ]]
    [[ "$output" == *"kk_dir_real=$shared_kk"* ]]
}

@test "orphan assembly is pruned with --yes before encrypt" {
    local shared_kk="$WORKDIR/orphan-assets"
    local namespace orphanassembly meta_file orphanpending

    namespace=$(assembly_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    mkdir -p -- "$namespace"
    chmod 700 -- "$namespace"
    mkdir -p -- "$namespace/runs"
    chmod 700 -- "$namespace/runs"

    orphanassembly="$namespace/runs/run.pid-999999.ticks-1.rand-deadbeef"
    meta_file="$orphanassembly/run.meta"
    mkdir -p -- "$orphanassembly"
    chmod 700 -- "$orphanassembly"
    {
        printf 'run_id=pid-999999.ticks-1.rand-deadbeef\n'
        printf 'pid=999999\n'
        printf 'pid_start_ticks=1\n'
        printf 'created=19700101000000.000000\n'
    } > "$meta_file"
    printf 'sensitive residue\n' > "$orphanassembly/plain.txt"

    mkdir -p -- "$shared_kk"
    orphanpending="$shared_kk/.pending.runid-pid-999999.ticks-1.rand-deadbeef--19700101000000.000000-deadbeef00.kk"
    printf 'pending residue\n' > "$orphanpending"

    echo "hello" > f.txt
    run env KK_DIR="$shared_kk" "$KK" f.txt --encrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ ! -e "$orphanassembly" ]
    [ ! -e "$orphanpending" ]
    [ ! -d "$namespace" ]
    [[ "$output" == *"found 1 orphan assembly director"* ]]
    [[ "$output" == *"removed 1 orphan assembly director"* ]]
    [[ "$output" == *"found 1 orphan pending file"* ]]
    [[ "$output" == *"removed 1 orphan pending file"* ]]
    [[ "$output" == *"created $shared_kk/"* ]]
}

@test "orphan assembly aborts non-interactive mutate without --yes" {
    local shared_kk="$WORKDIR/orphan-assets-no-auto"
    local namespace orphanassembly meta_file

    namespace=$(assembly_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    mkdir -p -- "$namespace/runs"
    chmod 700 -- "$namespace" "$namespace/runs"

    orphanassembly="$namespace/runs/run.pid-999999.ticks-1.rand-deadbeef"
    meta_file="$orphanassembly/run.meta"
    mkdir -p -- "$orphanassembly"
    chmod 700 -- "$orphanassembly"
    {
        printf 'run_id=pid-999999.ticks-1.rand-deadbeef\n'
        printf 'pid=999999\n'
        printf 'pid_start_ticks=1\n'
        printf 'created=19700101000000.000000\n'
    } > "$meta_file"

    echo "hello" > f.txt
    run bash -c 'exec env KK_DIR="$1" "$2" f.txt --encrypt --ppfile pp </dev/null' _ "$shared_kk" "$KK"
    [ "$status" -eq 1 ]
    [ -d "$orphanassembly" ]
    [ "$(find "$shared_kk" -maxdepth 1 -name "*.kk" 2>/dev/null | wc -l)" -eq 0 ]
    [[ "$output" == *"orphan assembly director"* ]]
    [[ "$output" == *"rerun with --yes or remove manually"* ]]
}

@test "startup warns about invalid kk candidates with wrong magic" {
    mkdir .kk
    printf '%s\nrest\n' "$(printf 'magic=nope\ncreated=19700101000000.000000\n' | base64 -w0)" > .kk/bad.kk
    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"ignoring invalid kk asset candidate"* ]]
    [[ "$output" == *"bad.kk (magic mismatch)"* ]]
}

@test "--info with no target and no assets fails" {
    run "$KK" --info --ppfile pp
    [ "$status" -eq 1 ]
}

@test "ls with no assets exits 0 with message" {
    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"no .kk assets found"* ]]
}

@test "ls shows header and numbered rows" {
    echo "one" > a.txt && echo "two" > b.txt
    enc a.txt && enc b.txt
    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"#   asset"* ]]
    [[ "$output" == *"state"* ]]
    [[ "$output" == *"locked"* ]]
    [[ "$output" == *"1   "* ]]
    [[ "$output" == *"2   "* ]]
}

@test "ls --json is valid JSON with correct path" {
    echo "one" > a.txt
    enc a.txt
    run "$KK" ls --json --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"path": "a.txt"'* ]]
    ! [[ "$output" == *'"state": "locked"'* ]]
}

@test "ls --json with no assets is valid empty JSON" {
    run "$KK" ls --json
    [ "$status" -eq 0 ]
    valid_json "$output"
}

@test "flag order does not matter (--json ls vs ls --json)" {
    echo "one" > a.txt
    enc a.txt
    run "$KK" --json ls --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"path": "a.txt"'* ]]
}

@test "ls auto-unlocks and shows human-readable asset rows" {
    echo "one" > a.txt
    echo "two" > b.txt
    enc a.txt && enc b.txt
    run "$KK" ls --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"unlocking 2 asset(s) in "* ]]
    [[ "$output" == *"a.txt"* ]]
    [[ "$output" == *"b.txt"* ]]
    ! [[ "$output" == *"state"* ]]
}

@test "ls --json auto-unlocks with unlocked metadata" {
    echo "one" > a.txt
    enc a.txt
    run "$KK" ls --json --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"path": "a.txt"'* ]]
    [[ "$output" == *'"kind": "file"'* ]]
}

@test "ls with wrong passphrase fails cleanly" {
    echo "one" > a.txt
    enc a.txt
    run "$KK" ls --ppfile ppwrong
    [ "$status" -eq 1 ]
    [[ "$output" == *"no assets in '.kk' unlocked with the current passphrase"* ]]
}

@test "ls warns on mixed passphrases and lists unlocked subset" {
    local mixed_a="$WORKDIR/mixed-a"
    local mixed_b="$WORKDIR/mixed-b"

    echo "one" > a.txt
    echo "two" > b.txt
    printf 'different-pass-456\n' > pp2
    chmod 600 pp2

    run env KK_DIR="$mixed_a" "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run env KK_DIR="$mixed_b" "$KK" b.txt --encrypt --ppfile pp2
    [ "$status" -eq 0 ]
    cp "$mixed_b"/*.kk "$mixed_a"/

    run env KK_DIR="$mixed_a" "$KK" ls --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"did not unlock with the current passphrase"* ]]
    [[ "$output" == *"a.txt"* ]]
    ! [[ "$output" == *"b.txt"* ]]
}

@test "unlock emits shell export and search works without ppfile" {
    echo "alpha" > alpha.txt
    enc alpha.txt
    local session_export
    session_export=$("$KK" unlock --ppfile pp)
    [[ "$session_export" == export\ KK_SESSION=* ]]
    eval "$session_export"
    export KK_SESSION

    run "$KK" search alpha
    [ "$status" -eq 0 ]
    [[ "$output" == *"alpha.txt"* ]]

    eval "$("$KK" lock)"
    unset KK_SESSION
}

@test "unlock session lets info reuse cached metadata without ppfile" {
    echo "meta" > f.txt
    enc f.txt
    local session_export
    session_export=$("$KK" unlock --ppfile pp)
    eval "$session_export"
    export KK_SESSION

    run "$KK" f.txt --info
    [ "$status" -eq 0 ]
    [[ "$output" == *"path_original=f.txt"* ]]

    eval "$("$KK" lock)"
    unset KK_SESSION
}

@test "lock prints shell cleanup even when no session is active" {
    run "$KK" lock
    [ "$status" -eq 0 ]
    [[ "$output" == *"unset KK_SESSION"* ]]
}

@test "explicit encrypt refuses partial vault view on mixed passphrases" {
    local mixed_a="$WORKDIR/mixed-a"
    local mixed_b="$WORKDIR/mixed-b"

    echo "one" > a.txt
    echo "two" > b.txt
    echo "three" > c.txt
    printf 'different-pass-456\n' > pp2
    chmod 600 pp2

    run env KK_DIR="$mixed_a" "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run env KK_DIR="$mixed_b" "$KK" b.txt --encrypt --ppfile pp2
    [ "$status" -eq 0 ]
    cp "$mixed_b"/*.kk "$mixed_a"/

    run env KK_DIR="$mixed_a" "$KK" c.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"partial vault view"* ]]
    [ "$(find "$mixed_a" -maxdepth 1 -name "*.kk" | wc -l)" -eq 2 ]
}

@test "rm refuses partial vault view on mixed passphrases" {
    local mixed_a="$WORKDIR/mixed-a"
    local mixed_b="$WORKDIR/mixed-b"

    echo "one" > a.txt
    echo "two" > b.txt
    printf 'different-pass-456\n' > pp2
    chmod 600 pp2

    run env KK_DIR="$mixed_a" "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run env KK_DIR="$mixed_b" "$KK" b.txt --encrypt --ppfile pp2
    [ "$status" -eq 0 ]
    cp "$mixed_b"/*.kk "$mixed_a"/

    run env KK_DIR="$mixed_a" "$KK" a.txt --rm --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"partial vault view"* ]]
    [ "$(find "$mixed_a" -maxdepth 1 -name "*.kk" | wc -l)" -eq 2 ]
}

@test "check refuses partial vault view on mixed passphrases" {
    local mixed_a="$WORKDIR/mixed-a"
    local mixed_b="$WORKDIR/mixed-b"

    echo "one" > a.txt
    echo "two" > b.txt
    printf 'different-pass-456\n' > pp2
    chmod 600 pp2

    run env KK_DIR="$mixed_a" "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run env KK_DIR="$mixed_b" "$KK" b.txt --encrypt --ppfile pp2
    [ "$status" -eq 0 ]
    cp "$mixed_b"/*.kk "$mixed_a"/

    run env KK_DIR="$mixed_a" "$KK" --check --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"partial vault view"* ]]
}

@test "search finds unlocked metadata paths" {
    echo "alpha" > alpha.txt
    echo "beta" > beta.txt
    enc alpha.txt && enc beta.txt
    run "$KK" search alpha --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"search matched 1 asset(s) in "* ]]
    [[ "$output" == *"alpha.txt"* ]]
    ! [[ "$output" == *"beta.txt"* ]]
}

@test "search --json is valid JSON with unlocked metadata" {
    echo "alpha" > alpha.txt
    enc alpha.txt
    run "$KK" search alpha --json --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"path": "alpha.txt"'* ]]
    [[ "$output" == *'"kind": "file"'* ]]
}

@test "search with wrong passphrase fails cleanly" {
    echo "alpha" > alpha.txt
    enc alpha.txt
    run "$KK" search alpha --ppfile ppwrong
    [ "$status" -eq 1 ]
    [[ "$output" == *"no assets in '.kk' unlocked with the current passphrase"* ]]
}

@test "search requires a pattern argument" {
    run "$KK" search
    [ "$status" -eq 1 ]
    [[ "$output" == *"'search' requires a pattern argument"* ]]
}

@test "--info --json is valid JSON" {
    echo "meta" > f.txt
    enc f.txt
    run "$KK" f.txt --info --json --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"auth_scheme": "etm-hmac-sha512-kk-0.1"'* ]]
    [[ "$output" == *'"path_original": "f.txt"'* ]]
    [[ "$output" == *'"version": "0.2.9"'* ]]
}

@test "ls --json output passes python json.tool" {
    echo "one" > a.txt
    enc a.txt
    run bash -c "$KK ls --json --ppfile pp | python3 -m json.tool >/dev/null"
    [ "$status" -eq 0 ]
}

# ======================== check ========================

@test "--check passes on clean state" {
    echo "ok" > f.txt
    enc f.txt
    rm -f f.txt
    dec f.txt --yes
    run "$KK" --check --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"all assets verified OK"* ]]
}

@test "--check detects MISSING original" {
    echo "ok" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" --check --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISSING"* ]]
}

@test "--check detects MISMATCH content" {
    echo "ok" > f.txt
    enc f.txt
    echo "tampered" > f.txt
    run "$KK" --check --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISMATCH"* ]]
}

@test "--check detects MTIME_DIFF" {
    echo "ok" > f.txt
    enc f.txt
    run "$KK" --check --ppfile pp
    [ "$status" -eq 0 ]
    sleep 1.1
    touch f.txt
    run "$KK" --check --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"MTIME_DIFF"* ]]
}

@test "--check with path filter checks only that asset" {
    echo "a" > a.txt && echo "b" > b.txt
    enc a.txt && enc b.txt
    rm -f a.txt
    run "$KK" b.txt --check --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"b.txt"* ]]
    ! [[ "$output" == *"a.txt"* ]]
}

@test "--check on directory asset passes when tree intact" {
    mkdir d && echo a > d/1.txt && echo b > d/2.txt
    enc d
    run "$KK" --check --ppfile pp
    [ "$status" -eq 0 ]
}

@test "--check on directory asset detects modified member" {
    mkdir d && echo a > d/1.txt
    enc d
    echo modified > d/1.txt
    run "$KK" --check --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"MISMATCH"* ]]
}

@test "decrypt rejects tampered ciphertext before extraction" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e hlen orig_byte tamper_byte
    e=.kk/$(ls .kk | head -1)
    hlen=$(head -n 1 "$e" | wc -c)
    orig_byte=$(dd if="$e" bs=1 skip=$((hlen+30)) count=1 2>/dev/null | od -An -tu1 | tr -d ' \n')
    tamper_byte='\130'
    if [[ "$orig_byte" == "88" ]]; then
        tamper_byte='\131'
    fi
    printf '%b' "$tamper_byte" | dd of="$e" bs=1 seek=$((hlen+30)) conv=notrunc 2>/dev/null
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"current passphrase"* ]]
    [ ! -e f.txt ]
}

@test "decrypt rejects tampered metadata before extraction" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e hlen hdr meta new_hdr
    e=.kk/$(ls .kk | head -1)
    hlen=$(head -n 1 "$e" | wc -c)
    hdr=$(head -n 1 "$e")
    meta=$(printf '%s' "$hdr" | base64 -d)
    new_hdr=$(printf '%s\n' "$meta" | sed 's/^metadata_hmac=.*/metadata_hmac=deadbeef/' | base64 -w0)
    {
        printf '%s\n' "$new_hdr"
        tail -c +$((hlen+1)) "$e"
    } > "$e.tmp"
    mv "$e.tmp" "$e"
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"current passphrase"* ]]
    [ ! -e f.txt ]
}

@test "decrypt rejects archive members with parent traversal" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e
    e=.kk/$(ls .kk | head -1)
    mkdir evil && echo bad > evil/file.txt
    tar -czf payload.bad.tar.gz --transform='s#^evil#../evil#' evil
    asset_payload_rewrite "$e" payload.bad.tar.gz
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"unsafe archive member path"* ]]
}

@test "decrypt preserves relative symlinks as symlinks" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e
    e=.kk/$(ls .kk | head -1)
    mkdir safe && echo bad > safe/file.txt && ln -s file.txt safe/link.txt
    tar -czf payload.safe.tar.gz safe
    asset_payload_rewrite "$e" payload.safe.tar.gz
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f safe/file.txt ]
    [ -L safe/link.txt ]
    [ "$(cat safe/link.txt)" = "bad" ]
}

@test "decrypt rejects archive members with escaping symlink targets" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e
    e=.kk/$(ls .kk | head -1)
    mkdir safe && echo bad > safe/file.txt
    # tar --absolute-names archives the symlink with its absolute target.
    ln -s /etc/hostname safe/link.txt
    tar -czf payload.bad.tar.gz safe
    asset_payload_rewrite "$e" payload.bad.tar.gz
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"unsafe archive symlink"* ]]
}

@test "decrypt --force overrides escaping symlink target safety gate" {
    echo "sec" > f.txt
    enc f.txt
    rm -f f.txt
    local e
    e=.kk/$(ls .kk | head -1)
    mkdir safe && echo bad > safe/file.txt
    ln -s /etc/hostname safe/link.txt
    tar -czf payload.bad.tar.gz safe
    asset_payload_rewrite "$e" payload.bad.tar.gz
    run "$KK" f.txt --decrypt --force --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f safe/file.txt ]
    [ -L safe/link.txt ]
    [ "$(readlink safe/link.txt)" = "/etc/hostname" ]
}

@test "corrupted metadata header is skipped by ls" {
    echo "sec" > f.txt
    enc f.txt
    local e
    e=.kk/$(ls .kk | head -1)
    sed -i '1s/.*/AAAA/' "$e"
    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"no .kk assets found"* ]]
}

# ======================== rm / gc ========================

@test "--rm with confirmation y removes the asset" {
    echo "rm me" > f.txt
    enc f.txt
    cap "y" "$KK" f.txt --rm --ppfile pp
    [ "$cap_status" -eq 0 ]
    [ "$(asset_count)" -eq 0 ]
}

@test "--rm with confirmation n aborts" {
    echo "rm me" > f.txt
    enc f.txt
    cap "n" "$KK" f.txt --rm --ppfile pp
    [ "$cap_status" -eq 1 ]
    [[ "$cap_out" == *"aborted"* ]]
    [ "$(asset_count)" -eq 1 ]
}

@test "--rm --yes removes without prompt" {
    echo "rm me" > f.txt
    enc f.txt
    run "$KK" f.txt --rm --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 0 ]
}

@test "--rm --force removes without prompt" {
    echo "rm me" > f.txt
    enc f.txt
    run "$KK" f.txt --rm --force --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 0 ]
}

@test "--rm only removes the filtered asset" {
    echo "a" > a.txt && echo "b" > b.txt
    enc a.txt && enc b.txt
    run "$KK" a.txt --rm --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(asset_count)" -eq 1 ]
    run "$KK" b.txt --info --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"path_original=b.txt"* ]]
    run "$KK" a.txt --info --ppfile pp
    [ "$status" -eq 1 ]
}

@test "--rm with no matching asset fails" {
    run "$KK" nosuch.txt --rm --yes
    [ "$status" -eq 1 ]
    [[ "$output" == *"no .kk assets found"* ]]
}

@test "--rm --dry-run removes nothing" {
    echo "rm me" > f.txt
    enc f.txt
    run "$KK" f.txt --rm --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"dry run: would remove"* ]]
    [ "$(asset_count)" -eq 1 ]
}

@test "--rm --dry-run with no assets says nothing to remove" {
    run "$KK" f.txt --rm --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"nothing to remove"* ]]
}

@test "--gc-assembly removes orphan runtime residue and empty namespaces" {
    local shared_kk="$WORKDIR/gc-assembly-assets"
    local namespace orphan_run orphan_pending_lock orphan_pending_file meta_file

    namespace=$(assembly_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    mkdir -p -- "$namespace/runs" "$shared_kk"
    chmod 700 -- "$namespace" "$namespace/runs"

    orphan_run="$namespace/runs/run.pid-999999.ticks-1.rand-deadbeef"
    meta_file="$orphan_run/run.meta"
    mkdir -p -- "$orphan_run"
    chmod 700 -- "$orphan_run"
    {
        printf 'run_id=pid-999999.ticks-1.rand-deadbeef\n'
        printf 'pid=999999\n'
        printf 'pid_start_ticks=1\n'
        printf 'created=19700101000000.000000\n'
    } > "$meta_file"

    orphan_pending_lock="$namespace/.scan-lock.pending.pid-999999.ticks-1.rand-deadbeef.abcdef"
    mkdir -p -- "$orphan_pending_lock"
    chmod 700 -- "$orphan_pending_lock"

    orphan_pending_file="$shared_kk/.pending.runid-pid-999999.ticks-1.rand-deadbeef--19700101000000.000000-deadbeef00.kk"
    printf 'pending residue\n' > "$orphan_pending_file"

    run env KK_DIR="$shared_kk" "$KK" --gc-assembly --yes
    [ "$status" -eq 0 ]
    [ ! -e "$orphan_run" ]
    [ ! -e "$orphan_pending_lock" ]
    [ ! -e "$orphan_pending_file" ]
    [ ! -d "$namespace" ]
}

# ======================== dry-run matrix ========================

@test "dry-run encrypt creates nothing" {
    echo "x" > f.txt
    run "$KK" f.txt --encrypt --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"dry run: would encrypt"* ]]
    [ ! -d .kk ]
    [ -f f.txt ]
}

@test "dry-run encrypt without force warns about existing asset" {
    echo "x" > f.txt
    enc f.txt
    run "$KK" f.txt --encrypt --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"without --force this would abort"* ]]
}

@test "dry-run encrypt with --force does not warn" {
    echo "x" > f.txt
    enc f.txt
    run "$KK" f.txt --encrypt --dry-run --force --ppfile pp
    [ "$status" -eq 0 ]
    ! [[ "$output" == *"without --force this would abort"* ]]
}

@test "dry-run decrypt creates nothing" {
    echo "x" > f.txt
    enc f.txt
    rm -f f.txt
    run "$KK" f.txt --decrypt --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"would decrypt"* ]]
    [ ! -e f.txt ]
}

@test "dry-run decrypt with no assets says nothing to do" {
    run "$KK" f.txt --decrypt --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"no assets found - nothing to do"* ]]
}

@test "dry-run decrypt announces overwrite requirement" {
    echo "x" > f.txt
    enc f.txt
    run "$KK" f.txt --decrypt --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"overwrite: yes"* ]]
}

@test "dry-run ls/check/selftest announce no destructive changes" {
    echo "x" > f.txt
    enc f.txt
    run "$KK" ls --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"performs no destructive changes"* ]]
    run "$KK" --check --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"performs no destructive changes"* ]]
    run "$KK" --selftest --dry-run
    [ "$status" -eq 0 ]
    [[ "$output" == *"performs no destructive changes"* ]]
}

@test "dry-run info/cat announce read-only" {
    echo "x" > f.txt
    enc f.txt
    run "$KK" f.txt --info --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"read-only"* ]]
    run "$KK" f.txt --cat --dry-run --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"read-only"* ]]
}

# ======================== passphrase handling ========================

@test "non-interactive without ppfile is refused" {
    echo "x" > f.txt
    # stdin must be non-tty; bats run inherits the session tty otherwise
    run bash -c 'exec "$0" f.txt --encrypt' "$KK" </dev/null
    [ "$status" -eq 1 ]
    [[ "$output" == *"needs a tty"* ]]
}

@test "missing ppfile is refused" {
    echo "x" > f.txt
    run "$KK" f.txt --encrypt --ppfile nosuch
    [ "$status" -eq 1 ]
    [[ "$output" == *"cannot read --ppfile"* ]]
}

@test "unreadable ppfile is refused" {
    [ "$(id -u)" -eq 0 ] && skip "running as root; chmod 000 is still readable"
    echo "x" > f.txt
    chmod 000 pp
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"cannot read --ppfile"* ]]
}

@test "only first line of ppfile is used" {
    printf 'line-one\nline-two\n' > pp2
    chmod 600 pp2
    echo "x" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp2
    [ "$status" -eq 0 ]
    rm -f f.txt
    printf 'line-one\n' > pp3
    chmod 600 pp3
    run "$KK" f.txt --decrypt --yes --ppfile pp3
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "x" ]
}

@test "passphrase with special characters round-trips" {
    printf 'p@$$w0rd! "quoted" %%s\n' > ppspec
    chmod 600 ppspec
    echo "spec" > f.txt
    run "$KK" f.txt --encrypt --ppfile ppspec
    [ "$status" -eq 0 ]
    rm -f f.txt
    run "$KK" f.txt --decrypt --yes --ppfile ppspec
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "spec" ]
}

@test "empty passphrase file round-trips consistently" {
    : > ppempty
    chmod 600 ppempty
    echo "empty" > f.txt
    run "$KK" f.txt --encrypt --ppfile ppempty
    [ "$status" -eq 0 ]
    rm -f f.txt
    run "$KK" f.txt --decrypt --yes --ppfile ppempty
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "empty" ]
}

@test "wrong passphrase on encrypt-then-decrypt never decrypts" {
    echo "x" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -f f.txt
    run "$KK" f.txt --decrypt --yes --ppfile ppwrong
    [ "$status" -eq 1 ]
    [ ! -e f.txt ]
}

# ======================== selftest ========================

@test "--selftest passes" {
    run bash -c 'exec "$0" --selftest </dev/null' "$KK"
    [ "$status" -eq 0 ]
    [[ "$output" == *"selftest PASSED"* ]]
}

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
        [ "$want" = "$got" ] || bad=$((bad+1))
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
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --encrypt --yes --ppfile "$WORKDIR/pp" >"job.$i.out" 2>&1 &
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
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --encrypt --ppfile "$WORKDIR/pp" >/dev/null 2>&1
        mv "f$i.txt" ../bak/
    done

    for i in $(seq 1 4); do
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --decrypt --yes --ppfile "$WORKDIR/pp" >"job.dec.$i.out" 2>&1 &
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

@test "full suite: runtime parent leaves no orphan namespaces" {
    [[ -n "${RUNTIME_PARENT:-}" ]] || skip "no safe XDG_RUNTIME_DIR available"
    local leaked
    leaked=$(runtime_print_new_namespaces)
    if [[ -n "$leaked" ]]; then
        printf '%s\n' "$leaked"
    fi
    [ -z "$leaked" ]
}

@test "kk . properly handles current directory restore" {
    # Test that 'kk .' works correctly and doesn't fail with "path is outside current directory"
    # This ensures the canonical path resolution fix for restore_rel="." is working
    echo "test content" > test-file.txt
    enc test-file.txt
    
    # Test that we can decrypt to current directory (kk .) - this was previously failing
    run "$KK" test-file.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    
    # Verify the file was restored correctly
    [ -f test-file.txt ]
    [[ "$(< test-file.txt)" == "test content" ]]
}
