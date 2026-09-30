#!/usr/bin/env bats
#
# kk - quick regression bats suite
# Run: bats ~/tests/bats/kk.quick.bats
#
# Covers the main flows without the slower long-form stress cases.

setup_file() {
    SAFE_XDG_RUNTIME_DIR=$(stage_runtime_dir || true)
    RUNTIME_PARENT=$(stage_parent || true)
    RUNTIME_SNAPSHOT_FILE=$(mktemp)
    export RUNTIME_PARENT RUNTIME_SNAPSHOT_FILE SAFE_XDG_RUNTIME_DIR
    runtime_snapshot > "$RUNTIME_SNAPSHOT_FILE"
}

setup() {
    WORKDIR=$(mktemp -d)
    cd "$WORKDIR" || exit 1
    export KK=~/bin/kk
    # isolate tests from any KK_* vars/overrides inherited from the caller's
    # shell; every test builds its own vault in an empty tmpdir, so a KK_DIR
    # exported by the user would otherwise redirect all encrypts elsewhere
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

valid_json() { python3 -m json.tool <<< "$1" >/dev/null 2>&1; }

stage_runtime_dir() {
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

stage_parent() {
    local runtime_dir
    runtime_dir=$(stage_runtime_dir) || return 1
    printf '%s/.kk\n' "$runtime_dir"
}

stage_namespace_dir() {
    local kk_dir_real="$1" parent
    parent=$(stage_parent) || return 1
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

@test "quick regression: cli basics" {
    run "$KK" --help
    [ "$status" -eq 0 ]
    [[ "$output" == *"usage"* ]]

    run "$KK" --checksum
    [ "$status" -eq 0 ]
    [[ "$output" =~ ^[0-9a-f]{128}$ ]]

    run "$KK" --version
    [ "$status" -eq 0 ]
    [ "$output" = "kk 0.2.9" ]

    run "$KK" --integrity-hash
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag"* ]]

    run "$KK" --frobnicate
    [ "$status" -eq 1 ]
    [[ "$output" == *"unknown flag"* ]]
}

@test "quick regression: encrypt rejects missing XDG_RUNTIME_DIR" {
    echo "runtime" > f.txt
    run env -u XDG_RUNTIME_DIR "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 1 ]
    [[ "$output" == *"XDG_RUNTIME_DIR is not set"* ]]
}

@test "quick regression: encrypt decrypt info and check" {
    echo "hello quick" > f.txt
    touch -d "2020-06-01 12:00:00 UTC" f.txt
    local m0
    m0=$(stat -c %Y f.txt)

    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    run "$KK" f.txt --info --json --ppfile pp
    [ "$status" -eq 0 ]
    valid_json "$output"
    [[ "$output" == *'"path_original": "f.txt"'* ]]
    [[ "$output" == *'"path_real": '* ]]

    rm -f f.txt
    run "$KK" f.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ "$(cat f.txt)" = "hello quick" ]
    [ "$(stat -c %Y f.txt)" = "$m0" ]

    run "$KK" --check --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"all assets verified OK"* ]]
}

@test "quick regression: decrypt can restore file to a new path" {
    echo "rename me" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -f f.txt

    run "$KK" f.txt --decrypt renamed.txt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ -f renamed.txt ]
    [ "$(cat renamed.txt)" = "rename me" ]
    [ ! -e f.txt ]
}

@test "quick regression: decrypt can restore a directory to a new path" {
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

@test "quick regression: plain force encrypt duplicates existing asset" {
    echo "hello quick" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    run "$KK" f.txt --force --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"created .kk/"* ]]
}

@test "quick regression: encrypt writes a sibling .sha256 companion" {
    echo "digest me" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    local asset
    asset=$(ls .kk/*.kk | head -1)
    [ -f "$asset.sha256" ]
    [ "$(stat -c %a "$asset.sha256")" = "600" ]
    # companion is sha256sum -c compatible and verifies OK
    ( cd .kk && sha256sum -c -- "$(basename "$asset").sha256" ) > "$WORKDIR/digest.out" 2>&1
    grep -Eq 'OK$' "$WORKDIR/digest.out"
    # a directory asset also gets a companion
    mkdir -p d && echo x > d/x.txt
    run "$KK" d --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    local dasset
    dasset=$(ls .kk/*.kk | grep -v '\.sha256$' | sort | tail -1)
    [ -f "$dasset.sha256" ]
    # the companion must not be treated as an asset by the inventory
    run "$KK" ls --ppfile pp
    [ "$status" -eq 0 ]
    ! [[ "$output" == *".sha256"* ]]
}

@test "quick regression: ls auto-unlocks and shows human-readable rows" {
    echo "alpha" > a.txt
    echo "beta" > b.txt
    run "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run "$KK" b.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    run "$KK" ls --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"unlocking 2 asset(s) in "* ]]
    [[ "$output" == *"a.txt"* ]]
    [[ "$output" == *"b.txt"* ]]
    ! [[ "$output" == *"state"* ]]
}

@test "quick regression: ls auto-unlocks with ppfile" {
    echo "alpha" > a.txt
    run "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    run "$KK" ls --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"unlocking 1 asset(s) in "* ]]
    [[ "$output" == *"a.txt"* ]]
    ! [[ "$output" == *"state"* ]]
}

@test "quick regression: ls auto-unlocks with session token" {
    echo "alpha" > a.txt
    run "$KK" a.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    local session_export
    session_export=$("$KK" unlock --ppfile pp)
    eval "$session_export"
    export KK_SESSION

    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"unlocking 1 asset(s) in "* ]]
    [[ "$output" == *"a.txt"* ]]

    eval "$($KK lock)"
    unset KK_SESSION
}

@test "quick regression: search unlocks once and finds metadata paths" {
    echo "alpha" > alpha.txt
    echo "beta" > beta.txt
    run "$KK" alpha.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    run "$KK" beta.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    run "$KK" search alpha --ppfile pp
    [ "$status" -eq 0 ]
    [[ "$output" == *"search matched 1 asset(s) in "* ]]
    [[ "$output" == *"alpha.txt"* ]]
    ! [[ "$output" == *"beta.txt"* ]]
}

@test "quick regression: unlock session reuses metadata across invocations" {
    echo "alpha" > alpha.txt
    run "$KK" alpha.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    local session_export
    session_export=$("$KK" unlock --ppfile pp)
    eval "$session_export"
    export KK_SESSION

    run "$KK" ls
    [ "$status" -eq 0 ]
    [[ "$output" == *"alpha.txt"* ]]

    run "$KK" search alpha
    [ "$status" -eq 0 ]
    [[ "$output" == *"alpha.txt"* ]]

    eval "$("$KK" lock)"
    unset KK_SESSION
}

@test "quick regression: wrong passphrase is rejected" {
    echo "secret" > f.txt
    run "$KK" f.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]
    rm -f f.txt

    run "$KK" f.txt --decrypt --yes --ppfile ppwrong
    [ "$status" -eq 1 ]
    [[ "$output" == *"current passphrase"* ]]
    [ ! -e f.txt ]
}

@test "quick regression: orphan cleanup and invalid asset warning" {
    local shared_kk="$WORKDIR/shared-quick"
    local namespace orphan_stage orphan_pending meta_file

    namespace=$(stage_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    mkdir -p -- "$namespace/runs" "$shared_kk"
    chmod 700 -- "$namespace" "$namespace/runs"

    orphan_stage="$namespace/runs/run.pid-999999.ticks-1.rand-deadbeef"
    meta_file="$orphan_stage/run.meta"
    mkdir -p -- "$orphan_stage"
    chmod 700 -- "$orphan_stage"
    {
        printf 'run_id=pid-999999.ticks-1.rand-deadbeef\n'
        printf 'pid=999999\n'
        printf 'pid_start_ticks=1\n'
        printf 'created=19700101000000.000000\n'
    } > "$meta_file"
    orphan_pending="$shared_kk/.pending.runid-pid-999999.ticks-1.rand-deadbeef--19700101000000.000000-deadbeef00.kk"
    printf 'pending residue\n' > "$orphan_pending"
    printf '%s\nrest\n' "$(printf 'magic=nope\ncreated=19700101000000.000000\n' | base64 -w0)" > "$shared_kk/bad.kk"

    echo "quick" > f.txt
    run env KK_DIR="$shared_kk" "$KK" f.txt --encrypt --yes --ppfile pp
    [ "$status" -eq 0 ]
    [ ! -e "$orphan_stage" ]
    [ ! -e "$orphan_pending" ]
    [ ! -d "$namespace" ]
    [[ "$output" == *"ignoring invalid kk asset candidate"* ]]
    [[ "$output" == *"bad.kk (magic mismatch)"* ]]
}

@test "quick regression: concurrent shared KK_DIR encrypt and decrypt" {
    local shared_kk="$WORKDIR/shared-concurrent"
    local namespace runs_dir rc=0 i pid
    local -a pids=()

    namespace=$(stage_namespace_dir "$(realpath -m -- "$shared_kk")") || skip "no safe XDG_RUNTIME_DIR available"
    runs_dir="$namespace/runs"

    mkdir -p src bak && cd src
    for i in $(seq 1 4); do
        printf 'payload-%s\n' "$i" > "f$i.txt"
    done

    for i in $(seq 1 4); do
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --encrypt --yes --ppfile "$WORKDIR/pp" >"enc.$i.out" 2>&1 &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || rc=1
    done
    [ "$rc" -eq 0 ]
    [ "$(find "$shared_kk" -maxdepth 1 -name "*.kk" | wc -l)" -eq 4 ]

    for i in $(seq 1 4); do
        mv "f$i.txt" ../bak/
    done

    pids=()
    rc=0
    for i in $(seq 1 4); do
        env KK_DIR="$shared_kk" "$KK" "f$i.txt" --decrypt --yes --ppfile "$WORKDIR/pp" >"dec.$i.out" 2>&1 &
        pids+=("$!")
    done

    for pid in "${pids[@]}"; do
        wait "$pid" || rc=1
    done
    [ "$rc" -eq 0 ]

    for i in $(seq 1 4); do
        cmp -s "f$i.txt" "../bak/f$i.txt"
        ! grep -q "kk: error:" "enc.$i.out"
        ! grep -q "kk: error:" "dec.$i.out"
    done

    [ "$(find "$shared_kk" -maxdepth 1 -name ".pending.runid-*" | wc -l)" -eq 0 ]
    [ ! -d "$namespace" ]
}

@test "quick regression: --dir flag shows evaluated KK_DIR_NAME" {
    # Test that --dir flag shows the correct directory path
    run "$KK" --dir
    [ "$status" -eq 0 ]
    # Should return the default KK_DIR_NAME which is .kk in current directory
    [[ "$output" == *".kk" ]]
}

@test "quick regression: kk . properly handles current directory restore" {
    # Test that 'kk .' works correctly with current directory restore
    echo "test content" > test-file.txt
    run "$KK" test-file.txt --encrypt --ppfile pp
    [ "$status" -eq 0 ]

    # Test that we can decrypt to current directory (kk .) - this was previously failing
    run "$KK" test-file.txt --decrypt --yes --ppfile pp
    [ "$status" -eq 0 ]

    # Verify the file was restored correctly
    [ -f test-file.txt ]
    [[ "$(< test-file.txt)" == "test content" ]]
}
