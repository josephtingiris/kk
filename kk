#!/usr/bin/bash
#
# kk - knock knock, who's there?
#
# encrypts/decrypts files/directories on-demand to/from .kk/ assets (and more)
#
# 20260911 - joseph@tingiris.net ... security is a feeling
#
# usage         : kk --help
#
# crypt info (all keys derived from the passphrase stdin which is never saved or stored) ...
#
#   payload     : tar -c -I 'gzip -n' of the path, relative to CWD
#   checksum    : bootstrap script checksum after the marker below; fails closed when the script changes
#   auth        : encrypt-then-mac for new assets: HMAC-SHA512 over authenticated metadata + ciphertext, verified before decrypt
#   cipher      : AES-256-CBC, key+IV from PBKDF2-SHA512 (200k iterations), random salt/IV embedded by openssl, passphrase fed via stdin
#   asset       : .kk/YYYYMMDDHHMMSS-<id>.kk = [base64 public header][metadata ciphertext][payload ciphertext]
#   metadata    : path/hash/timestamp details are encrypted in a small metadata block
#
# dependencies  : bash 4+, awk, gnu coreutils, gnu tar, gzip, openssl 3.5+
#
readonly _KK_CHECKSUM_HASH="a75399d7811ec53e815517524563849a243544d9367fc6763984d9898cc74c2eb4ed9294d39c379e87fd7542d6c0c4ab9012b3b9557611b5c684cb02ca2b7281"
#
# -----BEGIN CHECKSUM HASH-----

# -- guards --

set -euo pipefail

if [[ "${BASH_VERSINFO[0]}" -lt 4 ]]; then
    printf 'kk: error: bash 4+ is required; aborting\n' >&2
    exit 1
fi

_KK_DEPENDENCIES=(awk base64 cut date head mkdir openssl readlink rm sed stty tar tail tr true uname wc)

for _KK_DEPENDENCY in "${_KK_DEPENDENCIES[@]}"; do
    if ! command -v "$_KK_DEPENDENCY" &> /dev/null; then
        printf 'kk: error: missing dependency: %s; aborting\n' "$_KK_DEPENDENCY" >&2
        exit 1
    fi
done

# -- bootstrap checksum --

_KK_CHECKSUM=${1:-}

if [[ -z "${_KK_CHECKSUM_HASH:-}" ]]; then
    printf 'kk: error: checksum hash is empty; aborting\n' >&2
    exit 1
else
    _KK_CHECKSUM_HASH_MARKER=$(awk '/^# -----BEGIN CHECKSUM HASH-----$/ {print NR; exit}' "$0" || true)
    if [[ -z "$_KK_CHECKSUM_HASH_MARKER" ]]; then
        printf 'kk: error: checksum hash marker not found; aborting\n' >&2
        exit 1
    fi
    _KK_CHECKSUM_HASH_MARKER_START=$((_KK_CHECKSUM_HASH_MARKER + 1))
    _KK_CHECKSUM_HASH_MARKER_ACTUAL=$(tail -n +"$_KK_CHECKSUM_HASH_MARKER_START" "$0" 2> /dev/null | openssl dgst -sha512 -r | cut -d' ' -f1 2> /dev/null) || {
        printf 'kk: error: failed to compute checksum hash\n' >&2
        exit 1
    }

    _KK_CHECKSUM_HASH_MARKER_ACTUAL=${_KK_CHECKSUM_HASH_MARKER_ACTUAL,,}
    expected=${_KK_CHECKSUM_HASH,,}
    if [[ "$_KK_CHECKSUM_HASH_MARKER_ACTUAL" != "$expected" ]]; then
        case "${_KK_CHECKSUM:-}" in
            --checksum | --checksum-update) ;;
            *)
                printf 'kk: error: runtime checksum check failed: expected %s, _KK_CHECKSUM_HASH_MARKER_ACTUAL %s - aborting\n' "$expected" "$_KK_CHECKSUM_HASH_MARKER_ACTUAL" >&2
                exit 1
                ;;
        esac
    fi
fi

# -- runtime configuration --

# NOTE: 'runtime' explains the scope of a single invocation of kk, while 'run' and 'runs' refer to the potential of multiple runtimes running simultaneously, each with its own assembly directory and unique run id

readonly KK_ASSEMBLY_ASSET_ID_RANDOM_BYTES=5
readonly KK_ASSEMBLY_META_FILE="run.meta"
readonly KK_ASSEMBLY_NAMESPACE_BYTES=16
readonly KK_ASSET_COUNT_MAX=10000
readonly KK_ASSET_MAX_BYTES=10737418240 # 10 GiB cap on any single asset file
readonly KK_ASSET_PERMISSIONS=600
readonly KK_AUTH_SCHEME="etm-hmac-sha512-kk-0.1"
readonly KK_CIPHER="aes-256-cbc" # inner cipher (AEAD/GCM unsupported by openssl enc)
readonly KK_COLLISION_RETRIES=16

# a ./.kk file overrides all, including an exported KK_DIR
KK_DIR_TYPE=".kk"
if [ -f "${KK_DIR_TYPE}" ] && [ -r "${KK_DIR_TYPE}" ]; then
    if [ -s "${KK_DIR_TYPE}" ]; then
        while IFS= read -r kkline; do
            [[ "$kkline" =~ ^# ]] && continue
            [[ -z "$kkline" ]] && continue
            export KK_DIR="$kkline"
            break
        done < "${KK_DIR_TYPE}"
        unset -v kkline

        export KK_DIR="${KK_DIR/#\~/$HOME}"
    else
        echo "kk: error: ${KK_DIR_TYPE} is a zero byte file" >&2
        exit 1
    fi
fi

KK_DIR_NAME_NORM="${KK_DIR:-.kk}"
KK_DIR_NAME_NORM="${KK_DIR_NAME_NORM//\/.\//\/}"
KK_DIR_NAME_NORM="${KK_DIR_NAME_NORM//\/\//\/}"
case "$KK_DIR_NAME_NORM" in ./*) KK_DIR_NAME_NORM="${KK_DIR_NAME_NORM#./}" ;; esac
readonly KK_DIR_NAME="$KK_DIR_NAME_NORM"
unset -v KK_DIR_NAME_NORM

readonly KK_DIR_PERMISSIONS=700 # owner only, no world, no group
readonly KK_FILENAME_EXT=".kk"
readonly KK_HEADER_DECODED_MAX_BYTES=8192
readonly KK_HEADER_LINE_MAX_BYTES=16384
readonly KK_INTEGRITY_DIGEST="sha512" # inner plaintext-integrity hash
readonly KK_KDF_ALGO="pbkdf2"
readonly KK_KDF_DIGEST="sha512"
readonly KK_KDF_VERSION="v1"
readonly KK_MAC_DIGEST="sha512"
readonly KK_MAGIC="49084249083"        # 2147483647 ;)
readonly KK_METADATA_MAX_BYTES=1048576 # 1 MiB cap on encrypted metadata block
readonly KK_ORPHAN_GRACE_SECONDS=2
readonly KK_PBKDF2_ITERATIONS=200000
readonly KK_PENDING_PREFIX=".pending.runid-"
readonly KK_RUN_DIR_NAME="runs"
readonly KK_RUN_ID_RANDOM_BYTES=4
readonly KK_SALT_BYTES=16 # embedded by openssl per run (auth salt)
readonly KK_SCAN_LOCK_META_FILE="lock.meta"
readonly KK_SCAN_LOCK_NAME=".scan-lock"
readonly KK_SCAN_LOCK_RETRIES=50
readonly KK_SCAN_LOCK_SLEEP_SECONDS=0.1
readonly KK_SECRET_PHRASES=('q' 'quit') # exceptions honored at the passphrase prompt, i.e. 'q' to abort instead of being used as a passphrase
readonly KK_SESSION_INVENTORY_FILE="inventory.tsv"
readonly KK_SESSION_METADATA_DIR_NAME="metadata"
readonly KK_SESSION_METADATA_FILE="session.meta"
readonly KK_SESSION_PARENT_DIR_NAME=".kk-session"
readonly KK_SESSION_TTL_SECONDS=300
readonly KK_STTY="$(stty -g 2> /dev/null)"
readonly KK_TIMESTAMP_FORMAT="%Y%m%d%H%M%S" # utc
readonly KK_VERSION="0.2.9"

# -- runtime state --

KK_ACTION=""
KK_ASSEMBLY_DIR=""
KK_ASSEMBLY_NAMESPACE_DIR=""
KK_ASSEMBLY_PREFLIGHT_DONE=false
KK_ASSETS_INVENTORY_FILE=""
KK_ASSETS_INVENTORY_MILLISECONDS=0
KK_ASSETS_INVENTORY_READY=false
KK_ASSETS_INVENTORY_UNLOCK_ERRORS=0
KK_ASSETS_SESSION_DIR=""
KK_CTIME_ROOT_WARNED=false
KK_DIR_REAL=""
KK_DIR_STAGE=""
KK_DRY_RUN=false
KK_FORCE=false
KK_JSON_OUT=false
KK_PENDING_ASSET_FILE=""
KK_PP="" # passphrase (set by asset_prompt_passphrase or --ppfile)
KK_PPFILE="${KK_PPFILE:-}"
KK_PROC_START_TICKS=""
KK_RUN_ID=""
KK_RUNS_DIR=""
KK_ASSEMBLY_RESTORE_DIR=""
KK_SCAN_LOCK_DIR=""
KK_SCAN_LOCK_HELD=false
KK_SEARCH_PATTERN=""
KK_SIGNAL=""
KK_TARGET=""
KK_TARGET_RAW=""
KK_RESTORE_TARGET=""
KK_YES_MODE=false

# -- runtime state overrides --

[ -n "${KK_PPFILE:-}" ] && [ -r "${KK_PPFILE:-}" ] && KK_PPFILE="${KK_PPFILE:-}"   # KK_PPFILE is the true external authority
[ -z "${KK_PPFILE:-}" ] && [ -r "${KAUTHORITY:-}" ] && KK_PPFILE="${KAUTHORITY:-}" # KAUTHORITY may be used as well, i.e. clustering

# -- failsafes --

# restore terminal state and remove any per-run temporary artifacts
exit_cleanup() {
    if [ -n "$KK_STTY" ]; then
        stty echo &> /dev/null || true
        stty "$KK_STTY" &> /dev/null || true
    fi

    if [[ -n "${KK_PENDING_ASSET_FILE:-}" && -e "${KK_PENDING_ASSET_FILE:-}" ]]; then
        assembly_namespace_cleanup_files "$KK_PENDING_ASSET_FILE" || true
    fi

    if [[ -n "${KK_ASSEMBLY_RESTORE_DIR:-}" && -d "${KK_ASSEMBLY_RESTORE_DIR:-}" ]]; then
        rm -rf -- "$KK_ASSEMBLY_RESTORE_DIR" 2> /dev/null || true
    fi

    if [[ -n "${KK_DIR_STAGE:-}" && -d "${KK_DIR_STAGE:-}" ]]; then
        assembly_dir_remove "$KK_DIR_STAGE" || true
    fi

    if [[ "${KK_SCAN_LOCK_HELD:-false}" == true && -n "${KK_SCAN_LOCK_DIR:-}" && -d "${KK_SCAN_LOCK_DIR:-}" ]]; then
        assembly_dir_remove "$KK_SCAN_LOCK_DIR" || true
        KK_SCAN_LOCK_HELD=false
    fi

    if [[ -n "${KK_ASSEMBLY_NAMESPACE_DIR:-}" ]]; then
        assembly_namespace_prune "$KK_ASSEMBLY_NAMESPACE_DIR" "${KK_RUNS_DIR:-}"
    fi

    if [[ -n "${KK_SIGNAL:-}" ]]; then
        print_warning "caught $KK_SIGNAL - cleanup finished"
    fi
}

# -- abstractions --

# print an error and exit with status 1
aborting() {
    print_error "$*"
    exit 1
}

# identify whether a path currently names a file or directory
is_file_or_dir() { # $1 = path -> file|dir
    if [[ -d "$1" ]]; then
        printf 'dir\n'
    elif [[ -f "$1" ]]; then
        printf 'file\n'
    else
        aborting "not a regular file or directory: '$1'"
    fi
}

# detect host:port style socket targets
is_network_socket() { # $1 = target
    if [[ -e "$1" ]]; then
        return 1
    fi
    case "$1" in
        *":"*) return 0 ;;
        *) return 1 ;;
    esac
}

# return success when the current process is running as root
is_root() { [[ "$(id -u)" -eq 0 ]]; }

# compute a file digest in lowercase hexadecimal
openssl_file_digest_calc() { # $1 = digest name (sha256|sha512), $2 = file -> hex digest
    openssl dgst -"$1" -r -- "$2" | cut -d' ' -f1
}

# generate a random hex string for use as a salt
openssl_rand_hex_calc() { # -> lowercase hex salt
    openssl rand -hex "$KK_SALT_BYTES" | tr '[:upper:]' '[:lower:]'
}

# print an error message to stderr
print_error() { printf 'kk: error: %s\n' "$*" >&2; }

# print an informational message to stdout
print_info() { printf 'kk: %s\n' "$*"; }

# escape a string for JSON string output
print_json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    printf '%s' "$s"
}

# normalize a target path for kk
print_path() { # $1 = raw path -> stored path (absolute physical path when CWD)
    local raw="$1" abs real_pwd
    local -a parts=()
    local comp old_ifs="$IFS"
    real_pwd=$(realpath -m -- "$PWD") || aborting "cannot resolve current directory: $PWD"
    abs=$(realpath -m -- "$raw") ||
        aborting "cannot resolve path: $raw"
    case "$abs" in
        "$real_pwd" | "$real_pwd"/*) ;;
        *) aborting "path '$raw' is outside the current directory ($PWD); refusing" ;;
    esac
    if [[ "$abs" == "$real_pwd" ]]; then
        printf '%s\n' "$real_pwd"
        return 0
    fi
    if [[ "$raw" == /* ]]; then
        printf '%s\n' "${abs#"$real_pwd"/}"
        return 0
    fi
    IFS='/'
    for comp in $raw; do
        case "$comp" in
            '' | .) ;;
            ..)
                if ((${#parts[@]} > 0)); then
                    unset "parts[$((${#parts[@]} - 1))]"
                else
                    IFS="$old_ifs"
                    aborting "path escapes current directory: $raw"
                fi
                ;;
            *) parts+=("$comp") ;;
        esac
    done
    printf '%s\n' "${parts[*]##./}" # joins with '/' while IFS is still '/'
    IFS="$old_ifs"
}

# print the path's age in whole seconds from its mtime
print_path_age_seconds() { # $1 = path -> integer seconds since mtime, 0 on failure
    local now mtime
    now=$(date +%s)
    mtime=$(stat -c %Y -- "$1" 2> /dev/null || printf '0')
    if [[ "$mtime" =~ ^[0-9]+$ ]] && ((mtime > 0)); then
        printf '%s\n' "$((now - mtime))"
    else
        printf '0\n'
    fi
}

# print the physical working directory with symlinks resolved
print_path_pwd() {
    pwd -P
}

# print an absolute real path when possible, else a lexical absolute path
print_path_real() { # $1 = path -> absolute real path if it exists, else lexical absolute path
    realpath -e -- "$1" 2> /dev/null || realpath -m -- "$1"
}

# print the raw target of a symlink path
print_path_symlink_target() { # $1 = path -> raw symlink target if the path is a symlink
    if [[ -L "$1" ]]; then
        readlink -- "$1"
    fi
}

# render a compact utc date/time stamp in human-readable form
print_timestamp_canonical() { # YYYYMMDDHHMMSS[.uuuuuu] -> YYYY-MM-DD HH:MM:SS[.uuuuuu] UTC
    local t="$1"
    local base fraction=""
    base="$t"
    if [[ "$t" == *.* ]]; then
        base="${t%%.*}"
        fraction="${t#*.}"
        fraction=".${fraction}"
    fi
    printf '%s-%s-%s %s:%s:%s%s UTC' \
        "${base:0:4}" "${base:4:2}" "${base:6:2}" "${base:8:2}" "${base:10:2}" "${base:12:2}" "$fraction"
}

# print the current utc timestamp with microsecond precision
print_timestamp_now_utc() { # -> YYYYMMDDHHMMSS.uuuuuu
    local raw fraction
    raw=$(date -u +"%Y%m%d%H%M%S.%N")
    fraction=${raw#*.}
    printf '%s.%s\n' "${raw%%.*}" "${fraction:0:6}"
}

# print a warning message to stderr
print_warning() { printf 'kk: warning: %s\n' "$*" >&2; }

# archive a path as a deterministic gzip-compressed tarball
tar_gzip() { # $1 = relpath, $2 = output .tar.gz, $3 = kind (file|dir); run from CWD
    local rel="$1" out="$2" kind="${3:-}"
    if [[ "$kind" == "dir" ]]; then
        if [[ "$rel" == /* ]]; then
            # absolute stored path (current directory): archive its contents
            # as relative "./..." members so restore can promote them
            tar -c -h -I 'gzip -n' --exclude="./$KK_DIR_NAME" -C "$rel" . > "$out"
        else
            # never archive the vault itself when it sits inside the path
            tar -c -I 'gzip -n' --exclude="$rel/$KK_DIR_NAME" -- "$rel" > "$out"
        fi
    else
        tar -c -h -I 'gzip -n' -- "$rel" > "$out"
    fi
}

# -- crypt logic --

# mark the beginning of alphabetically sorted assembly_* functions
assembly_begin() {
    :
}

# create a directory and lock it down to mode 700
assembly_dir_ensure() { # $1 = dir
    mkdir -p -- "$1" || aborting "failed to create assembly directory '$1'"
    chmod 700 -- "$1" || aborting "failed to secure assembly directory '$1'"
    [[ -O "$1" ]] || aborting "assembly directory is not owned by the current user: '$1'"
}

# decide whether a run directory belongs to a dead process
assembly_dir_is_orphan() { # $1 = dir -> 0 orphan, 1 active
    local dir="$1" meta="$1/$KK_ASSEMBLY_META_FILE" pid ticks age
    [[ -d "$dir" ]] || return 1
    if [[ ! -r "$meta" ]]; then
        age=$(print_path_age_seconds "$dir")
        ((age >= KK_ORPHAN_GRACE_SECONDS)) && return 0
        return 1
    fi
    pid=$(assembly_metadata_get "$meta" pid)
    ticks=$(assembly_metadata_get "$meta" pid_start_ticks)
    if [[ -z "$pid" || -z "$ticks" ]]; then
        age=$(print_path_age_seconds "$meta")
        ((age >= KK_ORPHAN_GRACE_SECONDS)) && return 0
        return 1
    fi
    if [[ "$(assembly_run_id_print_state "pid-$pid.ticks-$ticks.rand-deadbeef")" != "live" ]]; then
        return 0
    fi
    return 1
}

# remove a runtime directory and warn if anything remains behind
assembly_dir_remove() { # $1 = dir -> 0 removed, 1 still exists
    local dir="$1"
    rm -rf -- "$dir" 2> /dev/null || true
    if [[ -e "$dir" ]]; then
        print_warning "security warning: assembly directory persists after cleanup: $dir"
        return 1
    fi
    return 0
}

# require a safe XDG_RUNTIME_DIR parent directory for runtime namespace state
assembly_dir_runtime_ensure() { # -> secure XDG_RUNTIME_DIR parent directory for assembly namespaces
    local fstype mode

    if [[ -z "${XDG_RUNTIME_DIR:-}" ]]; then
        aborting "XDG_RUNTIME_DIR is not set; aborting. Fix the runtime environment so XDG_RUNTIME_DIR points to a user-owned tmpfs directory with mode 700."
    fi

    if [[ ! -d "$XDG_RUNTIME_DIR" ]]; then
        aborting "XDG_RUNTIME_DIR '$XDG_RUNTIME_DIR' is not a directory; aborting. Fix the runtime environment so XDG_RUNTIME_DIR points to a user-owned tmpfs directory with mode 700."
    fi

    if [[ ! -O "$XDG_RUNTIME_DIR" ]]; then
        aborting "XDG_RUNTIME_DIR '$XDG_RUNTIME_DIR' is not owned by the current user; aborting. Fix the login/session runtime directory before running kk."
    fi

    mode=$(stat -c %a -- "$XDG_RUNTIME_DIR" 2> /dev/null || true)
    if [[ "$mode" != "700" ]]; then
        aborting "XDG_RUNTIME_DIR '$XDG_RUNTIME_DIR' must have mode 700; aborting. Fix it with: chmod 700 '$XDG_RUNTIME_DIR'"
    fi

    fstype=$(stat -f -c %T -- "$XDG_RUNTIME_DIR" 2> /dev/null || true)
    if [[ "$fstype" != "tmpfs" ]]; then
        aborting "XDG_RUNTIME_DIR '$XDG_RUNTIME_DIR' is mounted on '$fstype', not tmpfs; aborting. Fix the system runtime directory (for example via pam_systemd) before running kk."
    fi

    printf '%s/.kk\n' "$XDG_RUNTIME_DIR"
}

# remove orphan assembly residue from the runtime parent and current KK_DIR
assembly_gc_orphans() {
    local record kind path removed=0
    local -a records=()

    mapfile -t records < <(assembly_print_orphans_gc)
    if ((${#records[@]} == 0)); then
        print_info "nothing to garbage-collect"
        return 0
    fi

    print_info "orphan assembly residue:"
    local n=0
    for record in "${records[@]}"; do
        IFS=$'\t' read -r kind path <<< "$record"
        n=$((n + 1))
        printf '%s\t%s\n' "$n" "$path"
    done

    if ! asset_prompt_confirm "remove $n orphan assembly residue(s)?"; then
        aborting "aborted - nothing removed"
    fi

    for record in "${records[@]}"; do
        IFS=$'\t' read -r kind path <<< "$record"
        case "$kind" in
            pending-file)
                assembly_namespace_cleanup_files "$path" || aborting "failed to remove orphan assembly residue '$path'"
                ;;
            run-dir)
                assembly_dir_remove "$path" || aborting "failed to remove orphan assembly residue '$path'"
                assembly_namespace_prune "${path%/$KK_RUN_DIR_NAME/*}" "${path%/$KK_RUN_DIR_NAME/*}/$KK_RUN_DIR_NAME"
                ;;
            scan-lock | scan-lock-pending)
                assembly_dir_remove "$path" || aborting "failed to remove orphan assembly residue '$path'"
                assembly_namespace_prune "${path%/*}" "${path%/*}/$KK_RUN_DIR_NAME"
                ;;
            namespace-dir)
                assembly_dir_remove "$path" || aborting "failed to remove orphan assembly residue '$path'"
                ;;
            *)
                aborting "internal error: unknown assembly gc kind '$kind'"
                ;;
        esac
        removed=$((removed + 1))
    done

    print_info "removed $removed assembly residue(s)"
}

# base64-encode metadata lines into a single header string
assembly_metadata_build() { # $@ = key=value pairs -> one base64 line
    printf '%s\n' "$@" | base64 -w0
}

# build the locked metadata lines for a new asset
assembly_metadata_build_locked() { # $1 = created, $2 = content sha, $3 = cwd logical, $4 = cwd real, $5 = kind, $6 = kk dir real, $7 = orig ctime, $8 = orig mtime, $9 = path original, ${10} = path real, ${11} = payload sha, ${12} = size, ${13} = symlink target
    local created="$1" content_sha256="$2" cwd_logical="$3" cwd_real="$4"
    local kind="$5" kk_dir_real="$6" orig_ctime="$7" orig_mtime="$8"
    local path_original="$9" path_real="${10}" payload_sha512="${11}"
    local size="${12}" symlink_target="${13}"
    printf '%s\n' \
        "created=$created" \
        "content_sha256=$content_sha256" \
        "cwd_logical=$cwd_logical" \
        "cwd_real=$cwd_real" \
        "kind=$kind" \
        "kk_dir_real=$kk_dir_real" \
        "orig_ctime=$orig_ctime" \
        "orig_mtime=$orig_mtime" \
        "path_original=$path_original" \
        "path_real=$path_real" \
        "payload_sha512=$payload_sha512" \
        "size=$size" \
        "symlink_target=$symlink_target"
}

# build the plaintext public header lines for a new asset
assembly_metadata_build_public() { # $1 = metadata auth salt, $2 = metadata bytes, $3 = metadata hmac, $4 = payload auth salt, $5 = payload hmac
    local metadata_auth_salt="$1" metadata_bytes="$2" metadata_hmac="$3"
    local payload_auth_salt="$4" payload_hmac="$5"
    printf '%s\n' \
        "magic=$KK_MAGIC" \
        "version=$KK_VERSION" \
        "auth_scheme=$KK_AUTH_SCHEME" \
        "cipher=$KK_CIPHER" \
        "kdf=$KK_KDF_ALGO-$KK_KDF_DIGEST-$KK_KDF_VERSION" \
        "iter=$KK_PBKDF2_ITERATIONS" \
        "metadata_auth_salt=$metadata_auth_salt" \
        "metadata_bytes=$metadata_bytes" \
        "metadata_hmac=$metadata_hmac" \
        "payload_auth_salt=$payload_auth_salt" \
        "payload_hmac=$payload_hmac"
}

# rebuild the canonical public header for HMAC verification
assembly_metadata_build_public_canonical() { # $1 = decoded public header text
    local meta="$1"
    printf '%s\n' \
        "magic=$(asset_metadata_get "$meta" magic)" \
        "version=$(asset_metadata_get "$meta" version)" \
        "auth_scheme=$(asset_metadata_get "$meta" auth_scheme)" \
        "cipher=$(asset_metadata_get "$meta" cipher)" \
        "kdf=$(asset_metadata_get "$meta" kdf)" \
        "iter=$(asset_metadata_get "$meta" iter)" \
        "metadata_auth_salt=$(asset_metadata_get "$meta" metadata_auth_salt)" \
        "metadata_bytes=$(asset_metadata_get "$meta" metadata_bytes)" \
        "payload_auth_salt=$(asset_metadata_get "$meta" payload_auth_salt)"
}

# read a key value from an assembly or lock metadata file
assembly_metadata_get() { # $1 = file, $2 = key
    sed -n "s/^$2=//p" "$1" 2> /dev/null | head -n 1
}

# save ownership and location metadata into the current run directory
assembly_metadata_save() { # $1 = assembly dir, $2 = asset dir realpath
    local dir="$1" asset_dir_real="$2" meta="$1/$KK_ASSEMBLY_META_FILE"
    assembly_run_id_ensure
    {
        printf 'run_id=%s\n' "$KK_RUN_ID"
        printf 'pid=%s\n' "$$"
        printf 'pid_start_ticks=%s\n' "$KK_PROC_START_TICKS"
        printf 'created=%s\n' "$(print_timestamp_now_utc)"
        printf 'cwd_logical=%s\n' "$PWD"
        printf 'cwd_real=%s\n' "$(print_path_pwd)"
        printf 'kk_dir_real=%s\n' "$asset_dir_real"
    } > "$meta" || aborting "failed to save assembly metadata: '$meta'"
    chmod 600 -- "$meta" || aborting "failed to chmod assembly metadata: '$meta'"
}

# confirm and remove orphan namespace assets of a single kind
assembly_namespace_cleanup() { # $1 = label, $2 = kind(dir|file), $3... = paths
    local label="$1" kind="$2" removed=0 path
    shift 2
    local -a paths=("$@")

    if ((${#paths[@]} == 0)); then
        return 0
    fi

    print_warning "found ${#paths[@]} orphan $label for '$KK_DIR_NAME':"
    printf '%s\n' "${paths[@]}" >&2

    if ! $KK_YES_MODE && ! $KK_FORCE; then
        if [[ -t 0 ]]; then
            if ! asset_prompt_confirm "remove orphan $label?"; then
                print_warning "leaving orphan $label in place"
                if kk_action_is_filesystem_dependent; then
                    aborting "orphan $label found for '$KK_DIR_NAME'; refusing to continue without assembly cleanup"
                fi
                return 0
            fi
        elif kk_action_is_filesystem_dependent; then
            aborting "orphan $label found for '$KK_DIR_NAME' in non-interactive mode; rerun with --yes or remove manually"
        else
            print_warning "non-interactive mode: orphan $label left in place"
            return 0
        fi
    fi

    for path in "${paths[@]}"; do
        case "$kind" in
            dir) assembly_dir_remove "$path" || aborting "failed to remove orphan $label asset '$path'" ;;
            file) assembly_namespace_cleanup_files "$path" || aborting "failed to remove orphan $label asset '$path'" ;;
            *) aborting "internal error: unknown cleanup kind '$kind'" ;;
        esac
        removed=$((removed + 1))
    done
    print_warning "removed $removed orphan $label"
}

# remove a pending asset file and warn if it remains behind
assembly_namespace_cleanup_files() { # $1 = file -> 0 removed, 1 still exists
    local file="$1"
    rm -f -- "$file" 2> /dev/null || true
    if [[ -e "$file" ]]; then
        print_warning "security warning: pending file persists after cleanup: $file"
        return 1
    fi
    return 0
}

# create the current run's assembly directory and metadata on first use
assembly_namespace_ensure() {
    if [[ -n "${KK_DIR_STAGE:-}" && -d "${KK_DIR_STAGE:-}" ]]; then
        return 0
    fi

    assembly_preflight_check
    assembly_namespace_lock_acquire
    assembly_run_id_ensure

    KK_DIR_STAGE="$KK_RUNS_DIR/run.$KK_RUN_ID"
    mkdir -- "$KK_DIR_STAGE" || aborting "failed to create assembly dir '$KK_DIR_STAGE'"
    chmod 700 -- "$KK_DIR_STAGE" || aborting "failed to secure assembly dir '$KK_DIR_STAGE'"
    assembly_metadata_save "$KK_DIR_STAGE" "$KK_DIR_REAL"
    assembly_namespace_lock_release
}

# hash a KK_DIR realpath into a short runtime namespace id
assembly_namespace_id() { # $1 = asset-dir realpath -> short digest
    printf '%s' "$1" | openssl dgst -sha256 -r | cut -c1-"$KK_ASSEMBLY_NAMESPACE_BYTES"
}

# resolve and init runtime namespace paths for the current KK_DIR
assembly_namespace_init() {
    if [[ -n "${KK_ASSEMBLY_NAMESPACE_DIR:-}" && -n "${KK_RUNS_DIR:-}" && -n "${KK_SCAN_LOCK_DIR:-}" ]]; then
        return 0
    fi

    KK_DIR_REAL=$(print_path_real "$KK_DIR_NAME")

    KK_ASSEMBLY_DIR=$(assembly_dir_runtime_ensure)
    assembly_dir_ensure "$KK_ASSEMBLY_DIR"

    KK_ASSEMBLY_NAMESPACE_DIR="$KK_ASSEMBLY_DIR/$(assembly_namespace_id "$KK_DIR_REAL")"
    assembly_dir_ensure "$KK_ASSEMBLY_NAMESPACE_DIR"

    KK_RUNS_DIR="$KK_ASSEMBLY_NAMESPACE_DIR/$KK_RUN_DIR_NAME"
    assembly_dir_ensure "$KK_RUNS_DIR"

    KK_SCAN_LOCK_DIR="$KK_ASSEMBLY_NAMESPACE_DIR/$KK_SCAN_LOCK_NAME"
}

# return success when a namespace contains no live residue beyond an empty runs/ dir
assembly_namespace_is_prunable() { # $1 = namespace dir -> 0 removable, 1 keep
    local namespace="$1" runs_dir="$1/$KK_RUN_DIR_NAME"
    local -a entries=() run_entries=()

    [[ -d "$namespace" ]] || return 1

    if [[ -d "$runs_dir" ]]; then
        shopt -s nullglob dotglob
        run_entries=("$runs_dir"/*)
        shopt -u nullglob dotglob
        if ((${#run_entries[@]} > 0)); then
            return 1
        fi
    fi

    shopt -s nullglob dotglob
    entries=("$namespace"/*)
    shopt -u nullglob dotglob

    if ((${#entries[@]} == 0)); then
        return 0
    fi

    if ((${#entries[@]} == 1)) && [[ "${entries[0]}" == "$runs_dir" ]]; then
        return 0
    fi

    return 1
}

# serialize namespace scanning with an ownership-aware lock directory
assembly_namespace_lock_acquire() {
    local tries=0 temp_lock
    assembly_namespace_init
    assembly_run_id_ensure
    while :; do
        temp_lock=$(mktemp -d "$KK_ASSEMBLY_NAMESPACE_DIR/.scan-lock.pending.$KK_RUN_ID.XXXXXX") ||
            aborting "failed to create namespace lock assembly dir in '$KK_ASSEMBLY_NAMESPACE_DIR'"
        assembly_namespace_lock_save "$temp_lock"
        if mv -T -- "$temp_lock" "$KK_SCAN_LOCK_DIR" 2> /dev/null; then
            KK_SCAN_LOCK_HELD=true
            return 0
        fi
        assembly_dir_remove "$temp_lock" || aborting "failed to discard namespace lock assembly dir '$temp_lock'"
        if [[ ! -d "$KK_SCAN_LOCK_DIR" ]]; then
            continue
        fi
        if assembly_namespace_lock_is_orphan "$KK_SCAN_LOCK_DIR"; then
            print_warning "removing orphan namespace scan lock: $KK_SCAN_LOCK_DIR"
            assembly_dir_remove "$KK_SCAN_LOCK_DIR" || aborting "failed to remove orphan namespace scan lock '$KK_SCAN_LOCK_DIR'"
            continue
        fi
        tries=$((tries + 1))
        if ((tries >= KK_SCAN_LOCK_RETRIES)); then
            aborting "timed out waiting for namespace scan lock for '$KK_DIR_NAME'"
        fi
        sleep "$KK_SCAN_LOCK_SLEEP_SECONDS"
    done
}

# decide whether a namespace scan lock belongs to a dead process
assembly_namespace_lock_is_orphan() { # $1 = lock dir -> 0 orphan, 1 active
    local lock_dir="$1" meta="$1/$KK_SCAN_LOCK_META_FILE" pid ticks age
    [[ -d "$lock_dir" ]] || return 1
    if [[ ! -r "$meta" ]]; then
        age=$(print_path_age_seconds "$lock_dir")
        ((age >= KK_ORPHAN_GRACE_SECONDS)) && return 0
        return 1
    fi
    pid=$(assembly_metadata_get "$meta" pid)
    ticks=$(assembly_metadata_get "$meta" pid_start_ticks)
    if [[ -z "$pid" || -z "$ticks" ]]; then
        age=$(print_path_age_seconds "$meta")
        ((age >= KK_ORPHAN_GRACE_SECONDS)) && return 0
        return 1
    fi
    if [[ "$(assembly_run_id_print_state "pid-$pid.ticks-$ticks.rand-deadbeef")" != "live" ]]; then
        return 0
    fi
    return 1
}

# decide whether a pending namespace lock belongs to an orphaned process
assembly_namespace_lock_pending_is_orphan() { # $1 = pending lock dir -> 0 orphan, 1 active
    local dir="$1" base run_id age
    [[ -d "$dir" ]] || return 1
    base=${dir##*/}

    if [[ "$base" =~ ^\.scan-lock\.pending\.(pid-[0-9]+\.ticks-[0-9]+\.rand-[0-9a-f]+)\.[^.]+$ ]]; then
        run_id="${BASH_REMATCH[1]}"
        if [[ "$(assembly_run_id_print_state "$run_id")" != "live" ]]; then
            return 0
        fi
        return 1
    fi

    age=$(print_path_age_seconds "$dir")
    ((age >= KK_ORPHAN_GRACE_SECONDS))
}

# release the namespace scan lock when this run still owns it
assembly_namespace_lock_release() {
    local current_run_id meta
    if [[ "${KK_SCAN_LOCK_HELD:-false}" != true ]]; then
        return 0
    fi
    meta="$KK_SCAN_LOCK_DIR/$KK_SCAN_LOCK_META_FILE"
    rm -rf -- "$KK_SCAN_LOCK_DIR" 2> /dev/null || true
    if [[ -d "$KK_SCAN_LOCK_DIR" ]]; then
        current_run_id=$(assembly_metadata_get "$meta" run_id)
        if [[ -n "$current_run_id" && "$current_run_id" != "$KK_RUN_ID" ]]; then
            KK_SCAN_LOCK_HELD=false
            return 0
        fi
        aborting "failed to release namespace scan lock '$KK_SCAN_LOCK_DIR'"
    fi
    KK_SCAN_LOCK_HELD=false
}

# save ownership metadata into a namespace scan lock directory
assembly_namespace_lock_save() { # $1 = lock dir
    local meta="$1/$KK_SCAN_LOCK_META_FILE" ticks
    assembly_run_id_ensure
    ticks=$(assembly_run_proc_start_ticks "$$")
    {
        printf 'run_id=%s\n' "$KK_RUN_ID"
        printf 'pid=%s\n' "$$"
        printf 'pid_start_ticks=%s\n' "$ticks"
        printf 'created=%s\n' "$(print_timestamp_now_utc)"
    } > "$meta" || aborting "failed to save namespace lock metadata: '$meta'"
    chmod 600 -- "$meta" || aborting "failed to secure namespace lock metadata: '$meta'"
}

# remove empty namespace scaffolding left after run and lock cleanup
assembly_namespace_prune() { # $1 = namespace dir, $2 = runs dir (optional)
    local namespace="${1:-}" runs_dir="${2:-}"

    [[ -n "$namespace" ]] || return 0
    if [[ -z "$runs_dir" ]]; then
        runs_dir="$namespace/$KK_RUN_DIR_NAME"
    fi

    if [[ -d "$runs_dir" ]]; then
        rmdir -- "$runs_dir" 2> /dev/null || true
    fi

    if [[ -d "$namespace" ]]; then
        rmdir -- "$namespace" 2> /dev/null || true
    fi
}

# scan for orphan or invalid state before the current run proceeds
assembly_preflight_check() {
    local invalid record reason path
    local -a stale_runs=() orphans_pending=() invalids_pending=()

    $KK_ASSEMBLY_PREFLIGHT_DONE && return 0

    assembly_namespace_init
    assembly_namespace_lock_acquire

    mapfile -t stale_runs < <(assembly_print_orphans)
    mapfile -t orphans_pending < <(kk_print_orphans)
    mapfile -t invalids_pending < <(kk_print_invalids)

    assembly_preflight_check_assets_unexpected

    if ((${#stale_runs[@]} > 0)); then
        assembly_namespace_cleanup "assembly director(y/ies)" dir "${stale_runs[@]}"
    fi

    if ((${#orphans_pending[@]} > 0)); then
        assembly_namespace_cleanup "pending file(s)" file "${orphans_pending[@]}"
    fi

    for record in "${invalids_pending[@]}"; do
        IFS=$'\t' read -r path reason <<< "$record"
        print_warning "ignoring invalid kk asset candidate in '$KK_DIR_NAME': $path ($reason)"
    done

    assembly_namespace_lock_release
    KK_ASSEMBLY_PREFLIGHT_DONE=true
}

# check and warn about unexpected assets in the runtime namespace layout
assembly_preflight_check_assets_unexpected() {
    local path base
    shopt -s nullglob dotglob
    for path in "$KK_ASSEMBLY_NAMESPACE_DIR"/*; do
        [[ -e "$path" ]] || continue
        base=${path##*/}
        case "$base" in
            "$KK_RUN_DIR_NAME" | "$KK_SCAN_LOCK_NAME" | .scan-lock.pending.*) ;;
            *) print_warning "found unexpected runtime namespace asset for '$KK_DIR_NAME': $path" ;;
        esac
    done
    for path in "$KK_RUNS_DIR"/*; do
        [[ -e "$path" ]] || continue
        base=${path##*/}
        case "$base" in
            run.*) ;;
            *) print_warning "found unexpected runtime run asset for '$KK_DIR_NAME': $path" ;;
        esac
    done
    shopt -u nullglob dotglob
}

# list orphan run directories in the current runtime namespace
assembly_print_orphans() {
    local dir
    shopt -s nullglob
    for dir in "$KK_RUNS_DIR"/run.*; do
        [[ -d "$dir" ]] || continue
        if assembly_dir_is_orphan "$dir"; then
            printf '%s\n' "$dir"
        fi
    done
    shopt -u nullglob
}

# print manual assembly-gc candidates as kind<TAB>path records
assembly_print_orphans_gc() {
    local path namespace runs_dir assembly_dir
    local -a pending_files=()

    if [[ -d "$KK_DIR_NAME" ]]; then
        mapfile -t pending_files < <(kk_print_orphans)
        for path in "${pending_files[@]}"; do
            printf 'pending-file\t%s\n' "$path"
        done
    fi

    assembly_dir=$(assembly_dir_runtime_ensure)
    [[ -d "$assembly_dir" ]] || return 0

    shopt -s nullglob dotglob
    for namespace in "$assembly_dir"/*; do
        [[ -d "$namespace" ]] || continue
        runs_dir="$namespace/$KK_RUN_DIR_NAME"

        for path in "$runs_dir"/run.*; do
            [[ -d "$path" ]] || continue
            if assembly_dir_is_orphan "$path"; then
                printf 'run-dir\t%s\n' "$path"
            fi
        done

        path="$namespace/$KK_SCAN_LOCK_NAME"
        if [[ -d "$path" ]] && assembly_namespace_lock_is_orphan "$path"; then
            printf 'scan-lock\t%s\n' "$path"
        fi

        for path in "$namespace"/.scan-lock.pending.*; do
            [[ -d "$path" ]] || continue
            if assembly_namespace_lock_pending_is_orphan "$path"; then
                printf 'scan-lock-pending\t%s\n' "$path"
            fi
        done

        if assembly_namespace_is_prunable "$namespace"; then
            printf 'namespace-dir\t%s\n' "$namespace"
        fi
    done
    shopt -u nullglob dotglob
}

# validate an extracted restore assembly before promoting it into place
assembly_restore_validate() { # $1 = assembly restore dir
    local path root restore_path
    root="$1"
    [[ -d "$root" && -O "$root" ]] || aborting "assembly restore dir is not owned by the current user: '$root'"
    shopt -s nullglob dotglob
    for restore_path in "$root"/*; do
        [[ -e "$restore_path" ]] || continue
        path=${restore_path#"$root"/}
        case "$path" in
            /* | ../* | */../* | ..)
                aborting "restore member path is unsafe: '$path'"
                ;;
        esac
    done
    shopt -u nullglob dotglob
}

# extract the run id from a pending asset filename
assembly_run_id() { # $1 = pending file basename -> run id
    local base="$1" rest
    base=${base##*/}
    [[ "$base" == ${KK_PENDING_PREFIX}* ]] || return 1
    rest=${base#$KK_PENDING_PREFIX}
    [[ "$rest" == *--* ]] || return 1
    printf '%s\n' "${rest%%--*}"
}

# create and cache a unique run identifier for this process
assembly_run_id_ensure() {
    local rand
    if [[ -n "${KK_RUN_ID:-}" ]]; then
        return 0
    fi
    KK_PROC_START_TICKS=$(assembly_run_proc_start_ticks "$$")
    [[ -n "$KK_PROC_START_TICKS" ]] || aborting "failed to determine process start ticks"
    rand=$(openssl rand -hex "$KK_RUN_ID_RANDOM_BYTES" | tr '[:upper:]' '[:lower:]') || aborting "failed to create run id"
    KK_RUN_ID="pid-$$.ticks-$KK_PROC_START_TICKS.rand-$rand"
}

# classify a run identifier as live, orphan, or unknown
assembly_run_id_print_state() { # $1 = run id -> live|orphan|unknown
    local run_id="$1" current
    if [[ "$run_id" =~ ^pid-([0-9]+)\.ticks-([0-9]+)\.rand-[0-9a-f]+$ ]]; then
        current=$(assembly_run_proc_start_ticks "${BASH_REMATCH[1]}")
        if [[ -z "$current" ]]; then
            printf 'orphan\n'
        elif [[ "$current" == "${BASH_REMATCH[2]}" ]]; then
            printf 'live\n'
        else
            printf 'orphan\n'
        fi
        return 0
    fi
    printf 'unknown\n'
}

# read a process start time in kernel ticks from procfs
assembly_run_proc_start_ticks() { # $1 = pid -> /proc start ticks, empty when unavailable
    awk '{print $22}' "/proc/$1/stat" 2> /dev/null
}

# mark the beginning of alphabetically sorted asset_* functions
asset_begin() {
    :
}

# decrypt an asset and stream its payload to stdout
asset_cat() { # $1 = relpath or empty
    local asset f hdr meta rel
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    asset_prompt_passphrase
    asset=$(asset_get_selection "${1:-}")
    f="$KK_DIR_NAME/$asset"
    hdr=$(asset_get_header "$f")
    asset_metadata_decrypt_into "$hdr" "$f" meta
    rel=$(asset_metadata_get_path_original "$meta")
    asset_decrypt_payload "$hdr" "$meta" "$f" "$asset" "$KK_DIR_STAGE/payload.tar.gz"
    tar -xzOf "$KK_DIR_STAGE/payload.tar.gz"
}

# check stored asset metadata against current on-disk content
asset_check() { # $1 = relpath or empty
    local row_file rows
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    row_file="$KK_DIR_STAGE/assets.rows.tsv"
    assets_print_tsv "${1:-}" "$row_file"
    mapfile -t rows < "$row_file"
    if ((${#rows[@]} == 0)); then
        print_info "no assets to check"
        return 0
    fi
    local fails=0 r i asset epath kind size created csha res h om dm
    printf '%-3s %-36s %-10s %s\n' "#" "asset" "result" "path"
    for r in "${rows[@]}"; do
        local meta
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$r"
        res="OK"
        if [[ ! -e "$epath" ]]; then
            res="MISSING"
            fails=$((fails + 1))
        elif [[ "$kind" == "file" ]]; then
            h=$(openssl_file_digest_calc sha256 "$epath")
            if [[ "$h" != "$csha" ]]; then
                res="MISMATCH"
                fails=$((fails + 1))
            else
                if ! assets_inventory_session_metadata_load_into "$asset" meta; then
                    asset_metadata_decrypt_into "$(asset_get_header "$KK_DIR_NAME/$asset")" "$KK_DIR_NAME/$asset" meta
                fi
                om=$(asset_metadata_get "$meta" orig_mtime)
                if [[ -n "$om" ]]; then
                    dm=$(stat -c %Y -- "$epath")
                    if [[ "$dm" != "$om" ]]; then
                        res="MTIME_DIFF"
                        fails=$((fails + 1))
                    fi
                fi
            fi
        else
            assembly_namespace_ensure
            if tar_gzip "$epath" "$KK_DIR_STAGE/p.tar.gz" dir 2> /dev/null; then
                h=$(openssl_file_digest_calc sha256 "$KK_DIR_STAGE/p.tar.gz")
                if [[ "$h" != "$csha" ]]; then
                    res="MISMATCH"
                    fails=$((fails + 1))
                fi
            else
                res="TAR_FAILED"
                fails=$((fails + 1))
            fi

            #rm -rf -- "$KK_DIR_STAGE" || aborting "failed to clean up KK_DIR_STAGE dir '$KK_DIR_STAGE'"

            # redundancy: top-level directory mtime must match the recorded one
            if ! assets_inventory_session_metadata_load_into "$asset" meta; then
                asset_metadata_decrypt_into "$(asset_get_header "$KK_DIR_NAME/$asset")" "$KK_DIR_NAME/$asset" meta
            fi
            om=$(asset_metadata_get "$meta" orig_mtime)
            if [[ -n "$om" && "$res" == "OK" ]]; then
                dm=$(stat -c %Y -- "$epath")
                if [[ "$dm" != "$om" ]]; then
                    res="MTIME_DIFF"
                    fails=$((fails + 1))
                fi
            fi
        fi
        printf '%-3s %-36s %-10s %s\n' "$i" "$asset" "$res" "$epath"
    done
    if ((fails > 0)); then
        printf '\n'
        print_warning "verification found $fails issue(s)"
        exit 1
    fi
    print_info "all assets verified OK"
}

# decrypt an asset back into its original path or an explicit restore path
asset_decrypt() { # $1 = relpath filter or empty, $2 = restore relpath or empty
    local asset f hdr rel meta restore_rel kind
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    asset_prompt_passphrase
    asset=$(asset_get_selection "${1:-}")
    f="$KK_DIR_NAME/$asset"
    hdr=$(asset_get_header "$f")
    asset_metadata_decrypt_into "$hdr" "$f" meta
    rel=$(asset_metadata_get_path_original "$meta")
    [[ -n "$rel" ]] || aborting "asset $f has no recorded path"
    kind=$(asset_metadata_get "$meta" kind)
    restore_rel="${2:-$rel}"
    if [[ -n "${2:-}" && -d "$restore_rel" && "$kind" == "file" ]]; then
        restore_rel="${restore_rel%/}/${rel##*/}"
    fi
    asset_decrypt_payload "$hdr" "$meta" "$f" "$asset" "$KK_DIR_STAGE/payload.tar.gz"
    if [[ -d "$restore_rel" && -n "$(ls -A "$restore_rel" 2> /dev/null)" ]]; then
        aborting "refusing to overwrite non-empty directory '$restore_rel'"
    fi
    if [[ -e "$restore_rel" ]]; then
        asset_prompt_confirm "'$restore_rel' already exists - overwrite it?" ||
            aborting "aborted - nothing extracted (use --force to skip confirmation)"
    fi
    local assembly_restore_dir
    if $KK_FORCE; then
        print_warning "--force active: skipping asset payload member validation"
    else
        asset_payload_check_members_safe "$KK_DIR_STAGE/payload.tar.gz"
    fi
    assembly_restore_dir="$PWD/.kk-assembly.$$"
    KK_ASSEMBLY_RESTORE_DIR="$assembly_restore_dir"
    rm -rf -- "$assembly_restore_dir" || aborting "failed to clear assembly restore dir '$assembly_restore_dir'"
    mkdir -- "$assembly_restore_dir" || aborting "failed to create assembly restore dir '$assembly_restore_dir'"
    chmod 700 -- "$assembly_restore_dir" || aborting "failed to secure assembly restore dir '$assembly_restore_dir'"
    tar -xzf "$KK_DIR_STAGE/payload.tar.gz" -C "$assembly_restore_dir" || aborting "extraction failed"
    if $KK_FORCE; then
        print_warning "--force active: skipping asset restore directory validation"
    else
        assembly_restore_validate "$assembly_restore_dir"
    fi
    local om
    om=$(asset_metadata_get "$meta" orig_mtime)
    if [[ -n "$om" && "$rel" != /* && "$restore_rel" != /* ]]; then
        touch -d "@$om" -- "$assembly_restore_dir/$rel" 2> /dev/null || print_info "could not restore mtime for '$restore_rel'"
    fi
    local -a assembly_restore_entries=()
    local assembly_restore_name
    if [[ "$rel" == /* || "$restore_rel" == /* ]]; then
        if [[ ! -d "$restore_rel" ]]; then
            mkdir -p -- "$restore_rel" || aborting "failed to create restore directory '$restore_rel'"
        fi
        shopt -s dotglob nullglob
        assembly_restore_entries=("$assembly_restore_dir"/*)
        shopt -u dotglob nullglob
        for assembly_restore_name in "${assembly_restore_entries[@]}"; do
            rm -rf -- "$restore_rel/${assembly_restore_name##*/}" 2> /dev/null || true
            mv -- "$assembly_restore_name" "$restore_rel/${assembly_restore_name##*/}" ||
                aborting "failed to promote restore of '$restore_rel'"
        done
        # CWD restore: the recorded mtime applies to the directory root
        if [[ -n "$om" ]]; then
            touch -d "@$om" -- "$restore_rel" 2> /dev/null || print_info "could not restore mtime for '$restore_rel'"
        fi
    else
        rm -rf -- "$restore_rel" 2> /dev/null || true
        if [[ "$restore_rel" == */* ]]; then
            mkdir -p -- "${restore_rel%/*}" 2> /dev/null || true
        fi
        mv -- "$assembly_restore_dir/$rel" "$restore_rel" || aborting "failed to promote restore of '$restore_rel'"
    fi
    rm -rf -- "$assembly_restore_dir" 2> /dev/null || true
    asset_metadata_check_root_ctime "$meta"
    local kind stored_content now_sha
    kind=$(asset_metadata_get "$meta" kind)
    stored_content=$(asset_metadata_get "$meta" content_sha256)
    if [[ "$kind" == "file" ]]; then
        now_sha=$(openssl_file_digest_calc sha256 "$restore_rel")
        if [[ "$now_sha" == "$stored_content" ]]; then
            print_info "integrity check OK: $restore_rel"
        else
            print_info "WARNING: integrity check MISMATCH for $restore_rel (payload itself verified; on-disk content differs)"
        fi
    fi
    print_info "decrypted '$restore_rel' from $KK_DIR_NAME/$asset"
}

# check and decrypt ciphertext into a payload tarball
asset_decrypt_payload() { # $1 = decoded public header text, $2 = decoded locked metadata text, $3 = asset file, $4 = asset name, $5 = payload out
    local hdr="$1" meta="$2" asset_file="$3" asset_name="$4" payload_out="$5"
    asset_get_metadata_ciphertext "$asset_file" "$hdr" "$KK_DIR_STAGE/meta.enc"
    asset_get_payload "$asset_file" "$hdr" "$KK_DIR_STAGE/enc.bin"
    asset_payload_check_auth "$hdr" "$KK_DIR_STAGE/meta.enc" "$KK_DIR_STAGE/enc.bin"
    printf '%s\n' "$KK_PP" | openssl enc -d -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -pass stdin \
        -in "$KK_DIR_STAGE/enc.bin" -out "$payload_out" 2> /dev/null ||
        aborting "decryption failed (wrong passphrase or corrupted asset)"
    asset_metadata_check_payload_hash "$meta" "$payload_out" "$asset_name"
}

# encrypt a directory or file path into a new .kk asset
asset_encrypt() { # $1 = relpath
    local rel="$1"
    [[ -e "$rel" ]] || aborting "no such file or directory: '$rel'"
    kk_dir_ensure
    assembly_namespace_ensure

    asset_prompt_passphrase confirm

    assets_inventory_ensure
    assets_inventory_require_complete
    local kind
    kind=$(is_file_or_dir "$rel")
    local row_file
    local -a existing=()
    row_file="$KK_DIR_STAGE/assets.rows.tsv"
    assets_print_tsv "$rel" "$row_file"
    mapfile -t existing < "$row_file"
    if ((${#existing[@]} > 0)) && ! $KK_FORCE; then
        aborting "asset already exists for '$rel' (${#existing[@]} found). Use -d, --decrypt, or --force --encrypt to create another."
    fi
    tar_gzip "$rel" "$KK_DIR_STAGE/payload.tar.gz" "$kind" || aborting "tar failed for '$rel'"
    local payload_sha512 content_sha256 payload_size ts asset hdr tmp orig_mtime orig_ctime
    local metadata_bytes public_canonical
    local metadata_auth_salt metadata_hmac payload_auth_salt payload_hmac
    local metadata_key_hex payload_key_hex
    local -a metadata_lines=() public_lines=()
    local path_real path_original symlink_target cwd_logical cwd_real kk_dir_real
    payload_sha512=$(openssl_file_digest_calc sha512 "$KK_DIR_STAGE/payload.tar.gz")
    payload_size=$(stat -c %s -- "$KK_DIR_STAGE/payload.tar.gz")
    orig_mtime=$(stat -c %Y -- "$rel")
    orig_ctime=$(stat -c %Z -- "$rel")
    path_real=$(print_path_real "$rel")
    path_original="$rel"
    symlink_target=$(print_path_symlink_target "$rel")
    cwd_logical="$PWD"
    cwd_real=$(print_path_pwd)
    kk_dir_real=$(print_path_real "$KK_DIR_NAME")
    if [[ "$kind" == "file" ]]; then
        content_sha256=$(openssl_file_digest_calc sha256 "$rel")
    else
        content_sha256=$(openssl_file_digest_calc sha256 "$KK_DIR_STAGE/payload.tar.gz")
    fi
    printf '%s\n' "$KK_PP" | openssl enc -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -salt -pass stdin \
        -in "$KK_DIR_STAGE/payload.tar.gz" -out "$KK_DIR_STAGE/enc.bin" 2> /dev/null ||
        aborting "openssl encryption failed"

    asset=$(asset_get_filename)
    ts=${asset%%-*}
    mapfile -t metadata_lines < <(assembly_metadata_build_locked \
        "$ts" "$content_sha256" "$cwd_logical" "$cwd_real" "$kind" \
        "$kk_dir_real" "$orig_ctime" "$orig_mtime" "$path_original" \
        "$path_real" "$payload_sha512" "$payload_size" "$symlink_target")
    printf '%s\n' "${metadata_lines[@]}" > "$KK_DIR_STAGE/meta.txt" ||
        aborting "failed to build locked metadata"
    printf '%s\n' "$KK_PP" | openssl enc -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -salt -pass stdin \
        -in "$KK_DIR_STAGE/meta.txt" -out "$KK_DIR_STAGE/meta.enc" 2> /dev/null ||
        aborting "openssl metadata encryption failed"

    metadata_bytes=$(stat -c %s -- "$KK_DIR_STAGE/meta.enc")
    metadata_auth_salt=$(openssl_rand_hex_calc)
    payload_auth_salt=$(openssl_rand_hex_calc)
    metadata_key_hex=$(asset_hmac_key_calc "$metadata_auth_salt")
    payload_key_hex=$(asset_hmac_key_calc "$payload_auth_salt")
    public_canonical=$(assembly_metadata_build_public_canonical "$(assembly_metadata_build_public "$metadata_auth_salt" "$metadata_bytes" "" "$payload_auth_salt" "")")
    asset_hmac_input_build "$public_canonical" "$KK_DIR_STAGE/auth-input.bin" "$KK_DIR_STAGE/meta.enc"
    metadata_hmac=$(asset_hmac_calc "$metadata_key_hex" "$KK_DIR_STAGE/auth-input.bin")
    asset_hmac_input_build "$public_canonical" "$KK_DIR_STAGE/auth-input.bin" "$KK_DIR_STAGE/meta.enc" "$KK_DIR_STAGE/enc.bin"
    payload_hmac=$(asset_hmac_calc "$payload_key_hex" "$KK_DIR_STAGE/auth-input.bin")
    mapfile -t public_lines < <(assembly_metadata_build_public "$metadata_auth_salt" "$metadata_bytes" "$metadata_hmac" "$payload_auth_salt" "$payload_hmac")
    hdr=$(assembly_metadata_build "${public_lines[@]}")
    tmp=$(asset_print_path "$asset")
    KK_PENDING_ASSET_FILE="$tmp"
    rm -f -- "$tmp" || aborting "failed to clear pending asset '$tmp'"
    {
        printf '%s\n' "$hdr"
        cat -- "$KK_DIR_STAGE/meta.enc"
        cat -- "$KK_DIR_STAGE/enc.bin"
    } > "$tmp" || aborting "failed to save asset"
    chmod "$KK_ASSET_PERMISSIONS" -- "$tmp"
    mv -- "$tmp" "$KK_DIR_NAME/$asset" || aborting "failed to rename asset into place"
    asset_sha256_write "$KK_DIR_NAME/$asset" || {
        rm -f -- "$KK_DIR_NAME/$asset" 2> /dev/null || true
        aborting "failed to write sha256 companion for '$KK_DIR_NAME/$asset'"
    }
    KK_PENDING_ASSET_FILE=""
    print_info "created $KK_DIR_NAME/$asset  ($kind: $rel, payload ${payload_size} bytes)"
}

# generate a collision-resistant flat asset filename
asset_get_filename() { # -> YYYYMMDDHHMMSS.uuuuuu-<id>.kk
    local i ts asset_id asset
    for ((i = 0; i < KK_COLLISION_RETRIES; i++)); do
        ts=$(print_timestamp_now_utc)
        asset_id=$(openssl rand -hex "$KK_ASSEMBLY_ASSET_ID_RANDOM_BYTES" | tr '[:upper:]' '[:lower:]') ||
            aborting "failed to create asset filename id"
        asset="${ts}-${asset_id}${KK_FILENAME_EXT}"
        if [[ ! -e "$KK_DIR_NAME/$asset" ]]; then
            printf '%s\n' "$asset"
            return 0
        fi
    done
    aborting "asset filename collision persists for '$KK_DIR_NAME' - aborting (nothing written)"
}

# decode the public header from an asset file
asset_get_header() { # $1 = asset file -> decoded public header text
    local hdr
    asset_size_validate "$1"
    hdr=$(head -n 1 -- "$1") || aborting "cannot read header of $1"
    if [[ -n "$hdr" && "${#hdr}" -gt "$KK_HEADER_LINE_MAX_BYTES" ]]; then
        aborting "asset header is too large for $1"
    fi
    hdr=$(printf '%s' "$hdr" | base64 -d 2> /dev/null) || aborting "metadata decode failed for $1"
    if [[ "${#hdr}" -gt "$KK_HEADER_DECODED_MAX_BYTES" ]]; then
        aborting "asset decoded header is too large for $1"
    fi
    printf '%s' "$hdr"
}

# extract the encrypted metadata bytes from an asset file
asset_get_metadata_ciphertext() { # $1 = asset file, $2 = decoded public header text, $3 = output metadata ciphertext file
    local hlen metadata_bytes expected_bytes actual_bytes
    hlen=$(head -n 1 -- "$1" | wc -c)
    metadata_bytes=$(asset_metadata_get "$2" metadata_bytes)
    [[ "$metadata_bytes" =~ ^[0-9]+$ ]] || aborting "asset metadata length is invalid for $1"
    [[ "$metadata_bytes" -le "$KK_METADATA_MAX_BYTES" ]] || aborting "asset metadata block is too large for $1"
    expected_bytes="$metadata_bytes"
    if ! (
        set +o pipefail
        tail -c +"$((hlen + 1))" -- "$1" | head -c "$metadata_bytes" > "$3"
    ); then
        aborting "cannot read metadata of $1"
    fi
    actual_bytes=$(stat -c %s -- "$3")
    [[ "$actual_bytes" -eq "$expected_bytes" ]] || aborting "cannot read metadata of $1"
}

# extract the encrypted payload bytes from an asset file
asset_get_payload() { # $1 = asset file, $2 = decoded public header text, $3 = output payload ciphertext file
    local hlen metadata_bytes expected_bytes actual_bytes total_bytes
    hlen=$(head -n 1 -- "$1" | wc -c)
    metadata_bytes=$(asset_metadata_get "$2" metadata_bytes)
    [[ "$metadata_bytes" =~ ^[0-9]+$ ]] || aborting "asset metadata length is invalid for $1"
    [[ "$metadata_bytes" -le "$KK_METADATA_MAX_BYTES" ]] || aborting "asset metadata block is too large for $1"
    total_bytes=$(stat -c %s -- "$1")
    expected_bytes=$((total_bytes - hlen - metadata_bytes))
    [[ "$expected_bytes" -ge 0 ]] || aborting "cannot read payload of $1"
    if ! (
        set +o pipefail
        tail -c +"$((hlen + metadata_bytes + 1))" -- "$1" > "$3"
    ); then
        aborting "cannot read payload of $1"
    fi
    actual_bytes=$(stat -c %s -- "$3")
    [[ "$actual_bytes" -eq "$expected_bytes" ]] || aborting "cannot read payload of $1"
}

# select an asset automatically or interactively from a filtered set
asset_get_selection() { # $1 = relpath filter or empty -> echoes asset name
    local row_file rows
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    row_file="$KK_DIR_STAGE/assets.rows.tsv"
    assets_print_tsv "${1:-}" "$row_file"
    mapfile -t rows < "$row_file"
    if ((${#rows[@]} == 0)); then
        if [[ -n "${1:-}" ]]; then
            aborting "no $KK_DIR_NAME assets found for '$1'"
        fi
        aborting "no $KK_DIR_NAME assets found"
    fi
    local asset
    if ((${#rows[@]} == 1)); then
        IFS=$'\t' read -r _ asset _ <<< "${rows[0]}"
        printf '%s\n' "$asset"
        return 0
    fi
    if $KK_FORCE || $KK_YES_MODE; then
        IFS=$'\t' read -r _ asset _ <<< "${rows[0]}" # rows are newest first
        printf '%s\n' "$asset"
        return 0
    fi
    assets_print "${1:-}" >&2
    local ans
    printf '\nselect asset [1-%s] (default 1 = newest): ' "${#rows[@]}" >&2
    read -r ans || aborting "no input for selection"
    printf '\n' >&2
    if [[ -z "$ans" ]]; then
        ans=1
    fi
    case "$ans" in
        '' | *[!0-9]*) aborting "invalid selection: '$ans'" ;;
    esac
    if ((ans < 1 || ans > ${#rows[@]})); then
        aborting "selection out of range: $ans"
    fi
    IFS=$'\t' read -r _ asset _ <<< "${rows[ans - 1]}"
    printf '%s\n' "$asset"
}

# compute the authenticated metadata HMAC for asset input
asset_hmac_calc() { # $1 = lowercase hex key, $2 = input file -> lowercase hex hmac
    local hmac
    hmac=$(openssl mac -digest "$KK_MAC_DIGEST" -macopt "hexkey:$1" -in "$2" HMAC 2> /dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\n\r') ||
        aborting "failed to compute asset authentication tag"
    [[ -n "$hmac" ]] || aborting "failed to compute asset authentication tag"
    printf '%s\n' "$hmac"
}

# assemble canonical header text plus ciphertext blocks for HMAC computation
asset_hmac_input_build() { # $1 = canonical header text, $2 = output file, $3... = ciphertext file(s)
    local header_text="$1" output_file="$2" input_file
    shift 2
    printf '%s\n\n' "$header_text" > "$output_file" || aborting "failed to assemble asset authentication header"
    for input_file in "$@"; do
        cat -- "$input_file" >> "$output_file" || aborting "failed to assemble asset authentication input"
    done
}

# derive an asset authentication key from the passphrase and salt
asset_hmac_key_calc() { # $1 = auth salt hex -> lowercase hex key
    local out keyhex
    out=$(printf '%s\n' "$KK_PP" | openssl enc -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -S "$1" -P -pass stdin 2> /dev/null) ||
        aborting "failed to derive asset authentication key"
    keyhex=$(printf '%s\n' "$out" | sed -n 's/^key=//p' | head -n 1 | tr '[:upper:]' '[:lower:]')
    [[ -n "$keyhex" ]] || aborting "failed to parse asset authentication key"
    printf '%s\n' "$keyhex"
}

# check the authenticated metadata tag before decryption
asset_metadata_check_auth() { # $1 = decoded public header text, $2 = metadata ciphertext file
    local hdr="$1" ciphertext="$2"
    local auth_scheme auth_salt expected actual keyhex auth_input auth_meta
    assembly_namespace_ensure
    auth_scheme=$(asset_metadata_get "$hdr" auth_scheme)
    if [[ "$auth_scheme" != "$KK_AUTH_SCHEME" ]]; then
        aborting "asset is missing authenticated metadata; re-encrypt it with a current kk version"
    fi
    auth_salt=$(asset_metadata_get "$hdr" metadata_auth_salt)
    expected=$(asset_metadata_get "$hdr" metadata_hmac)
    [[ -n "$auth_salt" && -n "$expected" ]] || aborting "asset authentication metadata incomplete - refusing to decrypt"
    keyhex=$(asset_hmac_key_calc "$auth_salt")
    auth_meta=$(assembly_metadata_build_public_canonical "$hdr")
    auth_input="$KK_DIR_STAGE/auth-input.bin"
    asset_hmac_input_build "$auth_meta" "$auth_input" "$ciphertext"
    actual=$(asset_hmac_calc "$keyhex" "$auth_input")
    rm -f -- "$auth_input" || aborting "failed to remove temporary auth input file '$auth_input'"
    if [[ "$actual" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]]; then
        aborting "decryption failed (wrong passphrase or corrupted asset)"
    fi
}

# check the decrypted payload hash against recorded metadata
asset_metadata_check_payload_hash() { # $1 = decoded metadata text, $2 = payload file, $3 = asset name
    local stored_sha actual_sha
    stored_sha=$(asset_metadata_get "$1" payload_sha512)
    actual_sha=$(openssl_file_digest_calc sha512 "$2")
    if [[ "$actual_sha" != "$stored_sha" ]]; then
        aborting "payload sha512 does not match metadata for $3 - refusing to extract"
    fi
}

# check and warn (once) that ctime remains audit-only even when running as root
asset_metadata_check_root_ctime() { # $1 = decoded metadata text
    if ! is_root || $KK_CTIME_ROOT_WARNED; then
        return 0
    fi

    if [[ -n "$(asset_metadata_get "$1" orig_ctime)" ]]; then
        print_warning "orig_ctime is recorded for audit, but Linux ctime cannot be restored precisely even as root"
        KK_CTIME_ROOT_WARNED=true
    fi
}

# decrypt and return the locked metadata block for an asset
asset_metadata_decrypt() { # $1 = decoded public header text, $2 = asset file -> decoded metadata text
    local meta
    asset_metadata_decrypt_into "$1" "$2" meta
    printf '%s' "$meta"
}

# decrypt the locked metadata block for an asset into a caller variable
asset_metadata_decrypt_into() { # $1 = decoded public header text, $2 = asset file, $3 = output variable name
    local hdr="$1" asset_file="$2" outvar="$3"
    local -a meta_lines=()
    assembly_namespace_ensure
    asset_prompt_passphrase
    asset_get_metadata_ciphertext "$asset_file" "$hdr" "$KK_DIR_STAGE/meta.enc"
    asset_metadata_check_auth "$hdr" "$KK_DIR_STAGE/meta.enc"
    printf '%s\n' "$KK_PP" | openssl enc -d -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -pass stdin \
        -in "$KK_DIR_STAGE/meta.enc" -out "$KK_DIR_STAGE/meta.txt" 2> /dev/null ||
        aborting "failed to decrypt asset metadata"
    mapfile -t meta_lines < "$KK_DIR_STAGE/meta.txt"
    if ((${#meta_lines[@]} == 0)); then
        printf -v "$outvar" ''
    else
        printf -v "$outvar" '%s\n' "${meta_lines[@]}"
    fi
}

# try to decrypt the locked metadata block for an asset into a caller variable
asset_metadata_decrypt_try_into() { # $1 = decoded public header text, $2 = asset file, $3 = output variable name
    local actual auth_input auth_meta auth_salt auth_scheme expected hdr keyhex
    local asset_file="$2" outvar="$3"
    local -a meta_lines=()
    hdr="$1"

    assembly_namespace_ensure
    asset_get_metadata_ciphertext "$asset_file" "$hdr" "$KK_DIR_STAGE/meta.enc"
    auth_scheme=$(asset_metadata_get "$hdr" auth_scheme)
    [[ "$auth_scheme" == "$KK_AUTH_SCHEME" ]] || return 1
    auth_salt=$(asset_metadata_get "$hdr" metadata_auth_salt)
    expected=$(asset_metadata_get "$hdr" metadata_hmac)
    [[ -n "$auth_salt" && -n "$expected" ]] || return 1
    keyhex=$(asset_hmac_key_calc "$auth_salt")
    auth_meta=$(assembly_metadata_build_public_canonical "$hdr")
    auth_input="$KK_DIR_STAGE/auth-input.bin"
    asset_hmac_input_build "$auth_meta" "$auth_input" "$KK_DIR_STAGE/meta.enc"
    actual=$(asset_hmac_calc "$keyhex" "$auth_input")
    rm -f -- "$auth_input" || aborting "failed to remove temporary auth input file '$auth_input'"
    if [[ "$actual" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]]; then
        return 1
    fi
    if ! printf '%s\n' "$KK_PP" | openssl enc -d -"$KK_CIPHER" -"$KK_KDF_ALGO" -md "$KK_KDF_DIGEST" \
        -iter "$KK_PBKDF2_ITERATIONS" -pass stdin \
        -in "$KK_DIR_STAGE/meta.enc" -out "$KK_DIR_STAGE/meta.txt" 2> /dev/null; then
        return 1
    fi
    mapfile -t meta_lines < "$KK_DIR_STAGE/meta.txt"
    if ((${#meta_lines[@]} == 0)); then
        printf -v "$outvar" ''
    else
        printf -v "$outvar" '%s\n' "${meta_lines[@]}"
    fi
}

# read a key value from decoded metadata text
asset_metadata_get() { # $1 = decoded metadata text, $2 = key
    printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n 1
}

# resolve the restore path from current or legacy metadata fields
asset_metadata_get_path_original() { # $1 = decoded metadata text
    asset_metadata_get "$1" path_original
}

# check the authenticated payload tag before payload decryption
asset_payload_check_auth() { # $1 = decoded public header text, $2 = metadata ciphertext file, $3 = payload ciphertext file
    local hdr="$1" metadata_ciphertext="$2" payload_ciphertext="$3"
    local auth_meta auth_salt auth_input actual expected keyhex
    assembly_namespace_ensure
    auth_salt=$(asset_metadata_get "$hdr" payload_auth_salt)
    expected=$(asset_metadata_get "$hdr" payload_hmac)
    [[ -n "$auth_salt" && -n "$expected" ]] || aborting "asset payload authentication metadata incomplete - refusing to decrypt"
    keyhex=$(asset_hmac_key_calc "$auth_salt")
    auth_meta=$(assembly_metadata_build_public_canonical "$hdr")
    auth_input="$KK_DIR_STAGE/auth-input.bin"
    asset_hmac_input_build "$auth_meta" "$auth_input" "$metadata_ciphertext" "$payload_ciphertext"
    actual=$(asset_hmac_calc "$keyhex" "$auth_input")
    rm -f -- "$auth_input" || aborting "failed to remove temporary auth input file '$auth_input'"
    if [[ "$actual" != "$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')" ]]; then
        aborting "decryption failed (wrong passphrase or corrupted asset)"
    fi
}

# reject tar members whose paths, symlink targets, or entry types are unsafe
asset_payload_check_members_safe() { # $1 = payload tar.gz
    local archive="$1" line name target typeflag
    while IFS=$'\t' read -r typeflag name target; do
        [[ -n "$name" ]] || continue
        case "$name" in
            /* | ../* | */../* | ..)
                aborting "unsafe archive member path '$name': it would escape the restore location. The asset may be corrupted or crafted. Re-create it from the original data and try again."
                ;;
        esac
        if [[ "$typeflag" == "l" ]]; then
            case "$target" in
                /* | .. | ../* | */../*)
                    aborting "unsafe archive symlink '$name' -> '$target': its target points outside the restore location. If this symlink is intentional, re-encrypt from a copy that points to a path inside the tree; otherwise the asset may be corrupted and should be re-created."
                    ;;
            esac
            continue
        fi
        case "$typeflag" in
            - | d) ;;
            *)
                aborting "unsafe archive member '$name' (type $typeflag): kk only restores regular files and directories here. The asset may be corrupted or crafted; re-create it from trusted data."
                ;;
        esac
    done < <(tar -tzvf "$archive" 2> /dev/null | awk '{type=substr($1,1,1); name=""; for (i=6; i<=NF; i++) {name=(name ? name OFS : "") $i} if (index($0, " -> ") > 0) {split($0, a, " -> "); target=a[2]; sub(/ .*/, "", target)} else {target=""} sub(/ -> .*/, "", name); print type "\t" name "\t" target}')
}

# read a validated --ppfile passphrase file
asset_ppfile_read() { # $1 = file -> reads first line into KK_PP
    local file="$1"
    if [[ -L "$file" || ! -f "$file" ]]; then
        aborting "cannot read --ppfile '$file': passphrase file must be a regular file, not a symlink or special file"
    fi
    [[ -O "$file" ]] || aborting "cannot read --ppfile '$file': passphrase file must be owned by the current user"
    if [[ "$(stat -c %a -- "$file" 2> /dev/null || true)" != "600" ]]; then
        aborting "cannot read --ppfile '$file': passphrase file must have mode 0600 (chmod 600 '$file')"
    fi
    KK_PP=$(head -n 1 -- "$file")
}

# print full metadata for a selected asset
asset_print_info() { # $1 = relpath or empty
    local asset f hdr meta info
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    asset=$(asset_get_selection "${1:-}")
    f="$KK_DIR_NAME/$asset"
    hdr=$(asset_get_header "$f")
    if ! assets_inventory_session_metadata_load_into "$asset" meta; then
        asset_metadata_decrypt_into "$hdr" "$f" meta
    fi
    info=$(printf '%s\n%s\n' "$hdr" "$meta")
    if $KK_JSON_OUT; then
        local line k v out="" first=1
        while IFS= read -r line; do
            if [[ -n "$line" ]]; then
                k="${line%%=*}"
                v="${line#*=}"
                if ((first == 0)); then
                    out+=", "
                fi
                first=0
                out+="\"$(print_json_escape "$k")\": \"$(print_json_escape "$v")\""
            fi
        done <<< "$info"
        printf '{%s}\n' "$out"
    else
        printf '%s\n' "$info" | sort -u
        printf '\n'
        print_info "asset file: $f"
    fi
}

# build the hidden pending asset path inside KK_DIR_NAME
asset_print_path() { # $1 = final asset filename -> pending file path in KK_DIR_NAME
    assembly_run_id_ensure
    printf '%s/%s%s--%s\n' "$KK_DIR_NAME" "$KK_PENDING_PREFIX" "$KK_RUN_ID" "$1"
}

# ask for confirmation unless force or yes mode is active
asset_prompt_confirm() { # $1 = message; honors --yes and --force
    if $KK_YES_MODE || $KK_FORCE; then
        return 0
    fi
    local ans
    printf '%s [y/N] ' "$1"
    read -r ans || aborting "no input for confirmation"
    case "$ans" in
        [Yy] | [Yy][Ee][Ss]) return 0 ;;
        *) return 1 ;;
    esac
}

# read or load the encryption passphrase for the current run
asset_prompt_passphrase() { # $1 = "confirm" to require a matching second entry (used by encrypt only)
    local confirm="${1:-}"
    if [[ -n "${KK_PP:-}" ]]; then
        return 0
    fi
    if [[ -n "${KK_PPFILE:-}" ]]; then
        asset_ppfile_read "$KK_PPFILE"
        return 0
    fi
    [[ -t 0 ]] || aborting "passphrase prompt needs a tty; use --ppfile when non-interactive"
    local char pp="" sp
    stty -echo
    # first entry
    printf "%s" "Who's there .. ? "
    while IFS= read -r -N 1 char; do
        if [[ -z "$char" || "$char" == $'\n' ]]; then
            break
        fi
        pp+="$char"
        printf '*'
    done
    printf '\n'
    if [[ -z "$pp" ]]; then
        stty "$KK_STTY"
        aborting "who's not there - aborting"
    fi
    for sp in "${KK_SECRET_PHRASES[@]}"; do
        if [[ "$pp" == "$sp" ]]; then
            stty "$KK_STTY"
            if [ "${sp,,}" == "q" ] || [ "${sp,,}" == "quit" ]; then
                print_info "quit - exiting"
                exit 0
            fi
        fi
    done
    if [[ "$confirm" == "confirm" ]]; then
        # second entry; confirmation
        local pp2="" char2
        printf "%s" "Passphrase who ? "
        while IFS= read -r -N 1 char2; do
            if [[ -z "$char2" || "$char2" == $'\n' ]]; then
                break
            fi
            pp2+="$char2"
            printf '*'
        done
        stty "$KK_STTY"
        printf '\n'
        if [[ -z "$pp2" ]]; then
            aborting "empty passphrase confirmation - aborting"
        fi
        if [[ "$pp" != "$pp2" ]]; then
            aborting "passphrases do not match; aborting. Please try again."
        fi
    fi
    KK_PP="$pp"
}

# remove a selected asset after confirmation
asset_rm() { # $1 = relpath or empty
    local asset f hdr meta info
    assembly_namespace_ensure
    assets_inventory_ensure
    assets_inventory_require_complete
    asset=$(asset_get_selection "${1:-}")
    f="$KK_DIR_NAME/$asset"

    # Show detailed asset information before deletion
    hdr=$(asset_get_header "$f")
    if ! assets_inventory_session_metadata_load_into "$asset" meta; then
        asset_metadata_decrypt_into "$hdr" "$f" meta
    fi
    info=$(printf '%s\n%s\n' "$hdr" "$meta")

    print_info "asset file: $f"
    printf '\n'
    printf '%s\n' "$info" | sort -u
    printf '\n'

    if asset_prompt_confirm "remove $f ?"; then
        printf '\n'
        rm -f -- "$f" || aborting "failed to remove asset '$f'"
        rm -f -- "$f.sha256" 2> /dev/null || true # remove the companion too
        print_info "removed $f"
    else
        aborting "aborted - nothing removed"
    fi
}

# hash which covers the plaintext
asset_sha256_write() { # $1 = asset file -> writes $1.sha256
    local asset_file="$1" digest
    digest=$(openssl_file_digest_calc sha256 "$asset_file") ||
        aborting "failed to compute sha256 for '$asset_file'"
    printf '%s  %s\n' "$digest" "$(basename -- "$asset_file")" > "${asset_file}.sha256" ||
        aborting "failed to write sha256 companion '${asset_file}.sha256'"
    chmod "$KK_ASSET_PERMISSIONS" -- "${asset_file}.sha256" ||
        aborting "failed to secure sha256 companion '${asset_file}.sha256'"
    return 0
}

# reject asset files larger than the configured cap
asset_size_validate() { # $1 = asset file
    local size
    size=$(stat -c %s -- "$1" 2> /dev/null || printf '0')
    if [[ ! "$size" =~ ^[0-9]+$ || "$size" -gt "$KK_ASSET_MAX_BYTES" ]]; then
        aborting "asset '$1' exceeds the maximum supported size ($KK_ASSET_MAX_BYTES bytes)"
    fi
}

# build an unlocked vault inventory for the current KK_DIR
assets_inventory_build() {
    local asset end_milliseconds=0 hdr line meta start_milliseconds=0 valid_file
    local -a files=() unlock_failures=() valid_files=()

    assembly_namespace_ensure
    KK_ASSETS_INVENTORY_FILE="$KK_DIR_STAGE/assets.inventory.tsv"
    : > "$KK_ASSETS_INVENTORY_FILE" || aborting "failed to initialize asset inventory '$KK_ASSETS_INVENTORY_FILE'"
    KK_ASSETS_INVENTORY_MILLISECONDS=0
    KK_ASSETS_INVENTORY_READY=false
    KK_ASSETS_INVENTORY_UNLOCK_ERRORS=0

    shopt -s nullglob
    for valid_file in "$KK_DIR_NAME"/*"$KK_FILENAME_EXT"; do
        files+=("$valid_file")
    done
    shopt -u nullglob
    if ((${#files[@]} > 0)); then
        mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -r)
    fi

    for valid_file in "${files[@]}"; do
        hdr=$(head -n 1 -- "$valid_file" 2> /dev/null || true)
        [[ -n "$hdr" ]] || continue
        hdr=$(printf '%s' "$hdr" | base64 -d 2> /dev/null || true)
        [[ -n "$hdr" ]] || continue
        if [[ "$(asset_metadata_get "$hdr" magic)" == "$KK_MAGIC" ]]; then
            valid_files+=("$valid_file")
        fi
    done

    if ((${#valid_files[@]} == 0)); then
        KK_ASSETS_INVENTORY_READY=true
        return 0
    fi

    if ((${#valid_files[@]} > KK_ASSET_COUNT_MAX)); then
        aborting "'$KK_DIR_NAME' contains ${#valid_files[@]} assets, exceeding the maximum supported count ($KK_ASSET_COUNT_MAX)"
    fi

    if [[ -n "$KK_ASSETS_SESSION_DIR" ]]; then
        assembly_dir_ensure "$KK_ASSETS_SESSION_DIR/$KK_SESSION_METADATA_DIR_NAME"
    fi

    asset_prompt_passphrase
    start_milliseconds=$(date +%s%3N 2> /dev/null || printf '0')
    for valid_file in "${valid_files[@]}"; do
        asset=${valid_file##*/}
        hdr=$(asset_get_header "$valid_file")
        if asset_metadata_decrypt_try_into "$hdr" "$valid_file" meta; then
            printf -v line '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
                "$(($(wc -l < "$KK_ASSETS_INVENTORY_FILE") + 1))" "$asset" \
                "$(asset_metadata_get_path_original "$meta")" \
                "$(asset_metadata_get "$meta" kind)" \
                "$(asset_metadata_get "$meta" size)" \
                "$(asset_metadata_get "$meta" created)" \
                "$(asset_metadata_get "$meta" content_sha256)"
            printf '%s\n' "$line" >> "$KK_ASSETS_INVENTORY_FILE" || aborting "failed to write asset inventory '$KK_ASSETS_INVENTORY_FILE'"
            if [[ -n "$KK_ASSETS_SESSION_DIR" ]]; then
                printf '%s' "$meta" > "$(assets_inventory_session_metadata_file "$asset")" || aborting "failed to write session metadata for '$asset'"
                chmod 600 -- "$(assets_inventory_session_metadata_file "$asset")" || aborting "failed to secure session metadata for '$asset'"
            fi
        else
            unlock_failures+=("$asset")
        fi
    done
    end_milliseconds=$(date +%s%3N 2> /dev/null || printf '0')
    if [[ "$start_milliseconds" =~ ^[0-9]+$ && "$end_milliseconds" =~ ^[0-9]+$ && "$end_milliseconds" -ge "$start_milliseconds" ]]; then
        KK_ASSETS_INVENTORY_MILLISECONDS=$((end_milliseconds - start_milliseconds))
    fi
    KK_ASSETS_INVENTORY_READY=true
    KK_ASSETS_INVENTORY_UNLOCK_ERRORS=${#unlock_failures[@]}

    if [[ ! -s "$KK_ASSETS_INVENTORY_FILE" ]] && ((${#unlock_failures[@]} > 0)); then
        aborting "no assets in '$KK_DIR_NAME' unlocked with the current passphrase"
    fi

    if [[ -s "$KK_ASSETS_INVENTORY_FILE" ]] && ((${#unlock_failures[@]} > 0)); then
        assets_inventory_warn_unlock_mismatch "${unlock_failures[@]}"
    fi
}

# ensure the current run has a ready unlocked vault inventory file
assets_inventory_ensure() {
    $KK_ASSETS_INVENTORY_READY && return 0
    assets_inventory_session_load && return 0
    assets_inventory_build
}

# render unlocked inventory rows as JSON output
assets_inventory_print_json() {
    local rows
    if [[ ! -s "$KK_ASSETS_INVENTORY_FILE" ]]; then
        printf '[]\n'
        return 0
    fi
    mapfile -t rows < "$KK_ASSETS_INVENTORY_FILE"
    assets_print_json "${rows[@]}"
}

# render unlocked inventory rows as a human-readable table
assets_inventory_print_table() {
    local rows
    if [[ ! -s "$KK_ASSETS_INVENTORY_FILE" ]]; then
        print_info "no $KK_DIR_NAME assets found"
        return 0
    fi
    mapfile -t rows < "$KK_ASSETS_INVENTORY_FILE"
    printf '%-3s %-36s %-5s %-30s %-12s %s\n' "#" "asset" "kind" "path" "size" "created"
    local r i asset epath kind size created csha
    for r in "${rows[@]}"; do
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$r"
        printf '%-3s %-36s %-5s %-30s %-12s %s\n' \
            "$i" "$asset" "$kind" "${epath:0:30}" "$size" "$(print_timestamp_canonical "$created")"
    done
    printf '\n'
    print_info "unlocking ${#rows[@]} asset(s) in ${KK_DIR_NAME} took ${KK_ASSETS_INVENTORY_MILLISECONDS} ms"
}

# print unlocked inventory rows as TSV output
assets_inventory_print_tsv() {
    [[ -f "$KK_ASSETS_INVENTORY_FILE" ]] || return 0
    cat -- "$KK_ASSETS_INVENTORY_FILE"
}

# require a complete unlocked inventory for exact-match or mutating actions
assets_inventory_require_complete() {
    if ((KK_ASSETS_INVENTORY_UNLOCK_ERRORS > 0)); then
        aborting "some assets in '$KK_DIR_NAME' did not unlock with the current passphrase; refusing to continue on a partial vault view"
    fi
}

# search unlocked inventory rows by original path and print matches
assets_inventory_search() { # $1 = case-insensitive search pattern
    local pattern="$1"
    local end_milliseconds=0 start_milliseconds=0
    local -a hits=() rows=()

    assets_inventory_ensure
    if [[ ! -s "$KK_ASSETS_INVENTORY_FILE" ]]; then
        if $KK_JSON_OUT; then
            printf '[]\n'
            return 0
        fi
        print_info "no $KK_DIR_NAME assets found"
        return 0
    fi

    mapfile -t rows < "$KK_ASSETS_INVENTORY_FILE"
    start_milliseconds=$(date +%s%3N 2> /dev/null || printf '0')
    for line in "${rows[@]}"; do
        local i asset epath kind size created csha
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$line"
        if [[ "${epath,,}" == *"${pattern,,}"* ]]; then
            hits+=("$line")
        fi
    done
    end_milliseconds=$(date +%s%3N 2> /dev/null || printf '0')
    if $KK_JSON_OUT; then
        assets_print_json "${hits[@]}"
        return 0
    fi
    if [[ "$start_milliseconds" =~ ^[0-9]+$ && "$end_milliseconds" =~ ^[0-9]+$ && "$end_milliseconds" -ge "$start_milliseconds" ]]; then
        print_info "search matched ${#hits[@]} asset(s) in ${KK_DIR_NAME} took $((end_milliseconds - start_milliseconds)) ms"
    fi
    if ((${#hits[@]} == 0)); then
        print_info "no $KK_DIR_NAME assets matched '$pattern'"
        return 0
    fi
    printf '%-3s %-36s %-5s %-30s %-12s %s\n' "#" "asset" "kind" "path" "size" "created"
    for line in "${hits[@]}"; do
        local i asset epath kind size created csha
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$line"
        printf '%-3s %-36s %-5s %-30s %-12s %s\n' \
            "$i" "$asset" "$kind" "${epath:0:30}" "$size" "$(print_timestamp_canonical "$created")"
    done
}

# print the runtime path of a session cache directory for a token
assets_inventory_session_dir() { # $1 = session token -> secure session cache dir
    local token="$1"
    [[ "$token" =~ ^[0-9a-f]{32}$ ]] || return 1
    assembly_dir_runtime_ensure > /dev/null
    printf '%s/%s/%s\n' "$XDG_RUNTIME_DIR" "$KK_SESSION_PARENT_DIR_NAME" "$token"
}

# load an inventory session cache for the current KK_DIR when KK_SESSION is set
assets_inventory_session_load() {
    local dir expires kk_dir_real meta now unlock_errors
    local token="${KK_SESSION:-}"
    [[ -n "$token" ]] || return 1
    dir=$(assets_inventory_session_dir "$token") || return 1
    meta="$dir/$KK_SESSION_METADATA_FILE"
    [[ -d "$dir" && -O "$dir" && "$(stat -c %a -- "$dir" 2> /dev/null || true)" == "700" ]] || return 1
    [[ -r "$meta" && -O "$meta" && "$(stat -c %a -- "$meta" 2> /dev/null || true)" == "600" ]] || return 1
    [[ -r "$dir/$KK_SESSION_INVENTORY_FILE" && -O "$dir/$KK_SESSION_INVENTORY_FILE" && "$(stat -c %a -- "$dir/$KK_SESSION_INVENTORY_FILE" 2> /dev/null || true)" == "600" ]] || return 1
    kk_dir_real=$(sed -n 's/^kk_dir_real=//p' "$meta" | head -n 1)
    expires=$(sed -n 's/^expires=//p' "$meta" | head -n 1)
    unlock_errors=$(sed -n 's/^unlock_errors=//p' "$meta" | head -n 1)
    now=$(date +%s)
    if [[ -z "$kk_dir_real" || "$kk_dir_real" != "$(print_path_real "$KK_DIR_NAME")" ]]; then
        return 1
    fi
    if [[ ! "$expires" =~ ^[0-9]+$ || "$expires" -lt "$now" ]]; then
        rm -rf -- "$dir" 2> /dev/null || true
        return 1
    fi
    KK_ASSETS_INVENTORY_FILE="$dir/$KK_SESSION_INVENTORY_FILE"
    KK_ASSETS_INVENTORY_MILLISECONDS=0
    KK_ASSETS_INVENTORY_READY=true
    KK_ASSETS_INVENTORY_UNLOCK_ERRORS=${unlock_errors:-0}
    KK_ASSETS_SESSION_DIR="$dir"
    return 0
}

# print the runtime path of a cached metadata file for one asset
assets_inventory_session_metadata_file() { # $1 = asset filename -> cached metadata file path
    printf '%s/%s/%s\n' "$KK_ASSETS_SESSION_DIR" "$KK_SESSION_METADATA_DIR_NAME" "$1"
}

# load cached metadata for an asset from the active inventory session
assets_inventory_session_metadata_load_into() { # $1 = asset filename, $2 = output variable name
    local asset="$1" file="$2"
    local metadata_file
    local -a meta_lines=()
    [[ -n "$KK_ASSETS_SESSION_DIR" ]] || return 1
    metadata_file=$(assets_inventory_session_metadata_file "$asset")
    [[ -r "$metadata_file" ]] || return 1
    mapfile -t meta_lines < "$metadata_file"
    if ((${#meta_lines[@]} == 0)); then
        printf -v "$file" ''
    else
        printf -v "$file" '%s\n' "${meta_lines[@]}"
    fi
    return 0
}

# remove the current inventory session cache and print shell cleanup
assets_inventory_session_remove() {
    local dir
    if [[ -n "${KK_SESSION:-}" ]]; then
        dir=$(assets_inventory_session_dir "$KK_SESSION" 2> /dev/null || true)
        if [[ -n "$dir" ]]; then
            rm -rf -- "$dir" 2> /dev/null || true
        fi
    fi
    printf 'unset KK_SESSION\n'
}

# save the current unlocked inventory as a short-lived session cache
assets_inventory_session_save() {
    local dir expires now token
    assembly_dir_runtime_ensure > /dev/null
    assembly_dir_ensure "$XDG_RUNTIME_DIR/$KK_SESSION_PARENT_DIR_NAME"
    token=$(openssl rand -hex 16 | tr '[:upper:]' '[:lower:]') || aborting "failed to create session token"
    dir=$(assets_inventory_session_dir "$token") || aborting "failed to create session path"
    assembly_dir_ensure "$dir"
    assembly_dir_ensure "$dir/$KK_SESSION_METADATA_DIR_NAME"
    KK_ASSETS_SESSION_DIR="$dir"
    assets_inventory_build
    cp -- "$KK_ASSETS_INVENTORY_FILE" "$dir/$KK_SESSION_INVENTORY_FILE" || aborting "failed to save session inventory"
    chmod 600 -- "$dir/$KK_SESSION_INVENTORY_FILE" || aborting "failed to secure session inventory"
    KK_ASSETS_INVENTORY_FILE="$dir/$KK_SESSION_INVENTORY_FILE"
    now=$(date +%s)
    expires=$((now + KK_SESSION_TTL_SECONDS))
    {
        printf 'kk_dir_real=%s\n' "$(print_path_real "$KK_DIR_NAME")"
        printf 'created=%s\n' "$now"
        printf 'expires=%s\n' "$expires"
        printf 'unlock_errors=%s\n' "$KK_ASSETS_INVENTORY_UNLOCK_ERRORS"
    } > "$dir/$KK_SESSION_METADATA_FILE" || aborting "failed to save session metadata"
    chmod 600 -- "$dir/$KK_SESSION_METADATA_FILE" || aborting "failed to secure session metadata"
    printf 'kk: unlocked inventory session expires in %s seconds\n' "$KK_SESSION_TTL_SECONDS" >&2
    printf 'export KK_SESSION=%s\n' "$token"
}

# warn when some assets in the current KK_DIR did not unlock with the supplied passphrase
assets_inventory_warn_unlock_mismatch() {
    local -a assets=("$@")
    print_warning "found ${#assets[@]} asset(s) in '$KK_DIR_NAME' that did not unlock with the current passphrase; listing unlocked assets only:"
    printf '%s\n' "${assets[@]}" >&2
}

# print matching asset rows in table or JSON form
assets_print() { # $1 = relpath filter or empty; honors KK_JSON_OUT
    local row_file rows
    assembly_namespace_ensure
    row_file="$KK_DIR_STAGE/assets.rows.tsv"
    assets_print_tsv "${1:-}" "$row_file"
    mapfile -t rows < "$row_file"
    if ((${#rows[@]} == 0)); then
        if $KK_JSON_OUT; then
            printf '[]\n'
            return 0
        fi
        if [[ -n "${1:-}" ]]; then
            print_info "no $KK_DIR_NAME assets found for '$1'"
        else
            print_info "no $KK_DIR_NAME assets found"
        fi
        return 0
    fi
    if $KK_JSON_OUT; then
        assets_print_json "${rows[@]}"
        return 0
    fi
    printf '%-3s %-36s %-5s %-30s %-12s %s\n' "#" "asset" "kind" "path" "size" "created"
    local r i asset epath kind size created csha
    for r in "${rows[@]}"; do
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$r"
        printf '%-3s %-36s %-5s %-30s %-12s %s\n' \
            "$i" "$asset" "$kind" "${epath:0:30}" "$size" "$(print_timestamp_canonical "$created")"
    done
}

# render asset rows as JSON output
assets_print_json() { # $@ = TSV rows from assets_print_tsv
    local first=1 r
    printf '[\n'
    for r in "$@"; do
        local i asset epath kind size created csha
        IFS=$'\t' read -r i asset epath kind size created csha <<< "$r"
        if ((first == 0)); then
            printf ',\n'
        fi
        first=0
        printf '  {"index": %s, "asset": "%s", "path": "%s", "kind": "%s", "size": %s, "created": "%s", "content_sha256": "%s"}' \
            "$i" "$(print_json_escape "$asset")" "$(print_json_escape "$epath")" \
            "$(print_json_escape "$kind")" "$size" \
            "$(print_json_escape "$created")" "$(print_json_escape "$csha")"
    done
    printf '\n]\n'
}

# list asset filenames whose original paths are missing
assets_print_orphans() { # prints orphan asset names, one per line
    local row_file rows line
    assembly_namespace_ensure
    row_file="$KK_DIR_STAGE/assets.rows.tsv"
    assets_print_tsv "" "$row_file"
    mapfile -t rows < "$row_file"
    local -a orphans=()
    for line in "${rows[@]}"; do
        local asset epath
        IFS=$'\t' read -r _ asset epath _ <<< "$line"
        if [[ ! -e "$epath" ]]; then
            orphans+=("$asset")
        fi
    done
    if ((${#orphans[@]} > 0)); then
        printf '%s\n' "${orphans[@]}"
    fi
}

# print all assets using only public header and filename metadata
assets_print_public() { # honors KK_JSON_OUT
    local rows
    mapfile -t rows < <(assets_print_public_tsv)
    if ((${#rows[@]} == 0)); then
        if $KK_JSON_OUT; then
            printf '[]\n'
            return 0
        fi
        print_info "no $KK_DIR_NAME assets found"
        return 0
    fi
    if $KK_JSON_OUT; then
        assets_print_public_json "${rows[@]}"
        return 0
    fi
    printf '%-3s %-36s %-18s %s\n' "#" "asset" "state" "created"
    local r i asset state created
    for r in "${rows[@]}"; do
        IFS=$'\t' read -r i asset state created <<< "$r"
        printf '%-3s %-36s %-18s %s\n' \
            "$i" "$asset" "$state" "$(print_timestamp_canonical "$created")"
    done
}

# render public asset rows as JSON output
assets_print_public_json() { # $@ = TSV rows from assets_print_public_tsv
    local first=1 r
    printf '[\n'
    for r in "$@"; do
        local i asset state created
        IFS=$'\t' read -r i asset state created <<< "$r"
        if ((first == 0)); then
            printf ',\n'
        fi
        first=0
        printf '  {"index": %s, "asset": "%s", "state": "%s", "created": "%s"}' \
            "$i" "$(print_json_escape "$asset")" "$(print_json_escape "$state")" \
            "$(print_json_escape "$created")"
    done
    printf '\n]\n'
}

# collect public asset rows as tab-separated fields
assets_print_public_tsv() {
    local f base hdr meta created n=0
    local -a files=()
    shopt -s nullglob
    for f in "$KK_DIR_NAME"/*"$KK_FILENAME_EXT"; do
        files+=("$f")
    done
    shopt -u nullglob
    if ((${#files[@]} > 0)); then
        mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -r)
    fi

    for f in "${files[@]}"; do
        base=${f##*/}
        hdr=$(head -n 1 -- "$f" 2> /dev/null) || continue
        meta=$(printf '%s' "$hdr" | base64 -d 2> /dev/null) || continue
        if [[ "$(asset_metadata_get "$meta" magic)" != "$KK_MAGIC" ]]; then
            continue
        fi
        created=${base%%-*}
        n=$((n + 1))
        printf '%s\t%s\t%s\t%s\n' "$n" "$base" "locked" "$created"
    done
}

# collect matching asset metadata rows as tab-separated fields
assets_print_tsv() { # $1 = relpath to filter by, empty = all; $2 = optional output file
    local want="${1:-}" output_file="${2:-}"
    local f base hdr meta epath kind size created csha line
    local n=0
    local -a files=()
    if [[ -n "$output_file" ]]; then
        : > "$output_file" || aborting "failed to initialize asset row file '$output_file'"
    fi
    if $KK_ASSETS_INVENTORY_READY; then
        if [[ ! -f "$KK_ASSETS_INVENTORY_FILE" ]]; then
            return 0
        fi
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS=$'\t' read -r _ base epath kind size created csha <<< "$line"
            if [[ -n "$want" && "$epath" != "$want" ]]; then
                continue
            fi
            n=$((n + 1))
            printf -v line '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
                "$n" "$base" "$epath" "$kind" "$size" "$created" "$csha"
            if [[ -n "$output_file" ]]; then
                printf '%s\n' "$line" >> "$output_file" || aborting "failed to write asset rows to '$output_file'"
            else
                printf '%s\n' "$line"
            fi
        done < "$KK_ASSETS_INVENTORY_FILE"
        return 0
    fi
    shopt -s nullglob
    for f in "$KK_DIR_NAME"/*"$KK_FILENAME_EXT"; do
        files+=("$f")
    done
    shopt -u nullglob
    if ((${#files[@]} > 0)); then
        mapfile -t files < <(printf '%s\n' "${files[@]}" | sort -r)
    fi

    for f in "${files[@]}"; do
        base=${f##*/}
        hdr=$(head -n 1 -- "$f" 2> /dev/null) || continue
        meta=$(printf '%s' "$hdr" | base64 -d 2> /dev/null) || continue
        if [[ "$(asset_metadata_get "$meta" magic)" != "$KK_MAGIC" ]]; then
            continue
        fi
        asset_metadata_decrypt_into "$meta" "$f" meta
        epath=$(asset_metadata_get_path_original "$meta")
        if [[ -n "$want" && "$epath" != "$want" ]]; then
            continue
        fi
        n=$((n + 1))

        # print tsv rows, newest first: index<TAB>asset<TAB>path_original<TAB>kind<TAB>size<TAB>created<TAB>content_sha256
        printf -v line '%s\t%s\t%s\t%s\t%s\t%s\t%s' \
            "$n" "$base" "$epath" \
            "$(asset_metadata_get "$meta" kind)" \
            "$(asset_metadata_get "$meta" size)" \
            "$(asset_metadata_get "$meta" created)" \
            "$(asset_metadata_get "$meta" content_sha256)"
        if [[ -n "$output_file" ]]; then
            printf '%s\n' "$line" >> "$output_file" || aborting "failed to write asset rows to '$output_file'"
        else
            printf '%s\n' "$line"
        fi
    done
}

# describe what the selected action would do without changing anything
kk_action_dry_run() { # $1 = action, $2 = target (already the stored path)
    local action="$1" target="$2" rel cnt
    case "$action" in
        -d | --decrypt)
            local row_file rows asset f hdr meta epath ow
            assembly_namespace_ensure
            row_file="$KK_DIR_STAGE/assets.rows.tsv"
            assets_print_tsv "${target:-}" "$row_file"
            mapfile -t rows < "$row_file"
            if ((${#rows[@]} == 0)); then
                print_info "dry run: no assets found - nothing to do"
                return 0
            fi
            IFS=$'\t' read -r _ asset _ <<< "${rows[0]}"
            f="$KK_DIR_NAME/$asset"
            hdr=$(asset_get_header "$f")
            asset_metadata_decrypt_into "$hdr" "$f" meta
            epath=$(asset_metadata_get_path_original "$meta")
            ow="no"
            if [[ -e "$epath" ]]; then
                ow="yes (confirmation required unless --force)"
            fi
            print_info "dry run: would decrypt $f -> '$epath' [overwrite: $ow]"
            ;;
        -e | --encrypt)
            if is_network_socket "$target"; then
                aborting "socket mode not implemented yet (stubbed): $target"
            fi
            rel="$target"
            assembly_namespace_ensure
            assets_print_tsv "$rel" "$KK_DIR_STAGE/assets.rows.tsv"
            cnt=$(wc -l < "$KK_DIR_STAGE/assets.rows.tsv")
            print_info "dry run: would encrypt '$rel' -> new $KK_DIR_NAME asset ($cnt existing asset(s) for this path)"
            if ((cnt > 0)) && ! $KK_FORCE; then
                print_info "dry run: NOTE - without --force this would abort (asset already exists)"
            fi
            ;;
        -c | --cat | -i | --info)
            print_info "dry run: '$action' is read-only (would still need the passphrase to decrypt)"
            ;;
        --ls | --check | --selftest)
            print_info "dry run: '$action' performs no destructive changes"
            ;;
        --gc-assembly)
            local -a assembly_orph=()
            local record path
            mapfile -t assembly_orph < <(assembly_print_orphans_gc)
            if ((${#assembly_orph[@]} == 0)); then
                print_info "dry run: nothing to garbage-collect"
                return 0
            fi
            print_info "dry run: would remove ${#assembly_orph[@]} orphan assembly residue(s):"
            for record in "${assembly_orph[@]}"; do
                IFS=$'\t' read -r _ path <<< "$record"
                printf '%s\n' "$path"
            done
            ;;
        --rm)
            local row_file rows2
            assembly_namespace_ensure
            row_file="$KK_DIR_STAGE/assets.rows.tsv"
            assets_print_tsv "${target:-}" "$row_file"
            mapfile -t rows2 < "$row_file"
            if ((${#rows2[@]} == 0)); then
                print_info "dry run: nothing to remove"
                return 0
            fi
            print_info "dry run: would remove the selected $KK_DIR_NAME asset(s):"
            assets_print "${target:-}"
            ;;
        *)
            aborting "internal error: unknown action '$action'"
            ;;
    esac
}

# return success when the current action changes on-disk state
kk_action_is_filesystem_dependent() {
    if $KK_DRY_RUN; then
        return 1
    fi
    case "$KK_ACTION" in
        -d | --decrypt | -e | --encrypt | --gc-assembly | --rm | --selftest) return 0 ;;
        *) return 1 ;;
    esac
}

# infer the default action when the caller omitted one
kk_action_set_default() {
    if [[ -n "$KK_ACTION" ]]; then
        return 0
    fi
    if [[ -z "$KK_TARGET" ]]; then
        usage >&2
        exit 1
    fi
    if is_network_socket "$KK_TARGET"; then
        aborting "socket mode not implemented yet (stubbed): $KK_TARGET"
    fi
    local cnt
    assembly_namespace_ensure
    assets_print_tsv "$KK_TARGET" "$KK_DIR_STAGE/assets.rows.tsv"
    cnt=$(wc -l < "$KK_DIR_STAGE/assets.rows.tsv")
    if ((cnt == 0)); then
        KK_ACTION="--encrypt"
    elif $KK_FORCE; then
        KK_ACTION="--encrypt"
    else
        aborting "asset already exists for '$KK_TARGET' ($cnt found). Use -d, --decrypt, or --force --encrypt to create another."
    fi
}

# decide whether ls should automatically use unlocked inventory
kk_ls_should_auto_unlock() {
    if [[ "$KK_ACTION" != "--ls" ]]; then
        return 1
    fi
    if [[ -n "${KK_PP:-}" || -n "${KK_PPFILE:-}" ]]; then
        return 0
    fi
    if [[ -n "${KK_SESSION:-}" ]] && assets_inventory_session_load; then
        return 0
    fi
    return 1
}

# dispatch the parsed action to its handler
kk_arguments_dispatch() { # $1 = action, $2 = target
    local action="$1" target="$2" rel
    case "$action" in
        -c | --cat)
            rel=${target:-}
            asset_cat "$rel"
            ;;
        -d | --decrypt)
            rel=${target:-}
            asset_decrypt "$rel" "${KK_RESTORE_TARGET:-}"
            ;;
        -e | --encrypt)
            if is_network_socket "$target"; then
                aborting "socket mode not implemented yet (stubbed): $target"
            fi
            rel="$target"
            asset_encrypt "$rel"
            ;;
        -i | --info)
            rel=${target:-}
            asset_print_info "$rel"
            ;;
        --ls)
            kk_list_invalids
            if kk_ls_should_auto_unlock; then
                assets_inventory_ensure
                if $KK_JSON_OUT; then
                    assets_inventory_print_json
                else
                    assets_inventory_print_table
                fi
            else
                assets_print_public
            fi
            ;;
        --lock-session)
            assets_inventory_session_remove
            ;;
        --search)
            assets_inventory_search "$KK_SEARCH_PATTERN"
            ;;
        --unlock-session)
            assets_inventory_session_save
            ;;
        --rm)
            rel=${target:-}
            asset_rm "$rel"
            ;;
        --gc-assembly) assembly_gc_orphans ;;
        --check)
            rel=${target:-}
            asset_check "$rel"
            ;;
        --selftest) selftest ;;
        *) aborting "internal error: unknown action '$action'" ;;
    esac
}

# parse CLI arguments into action, target, and modifier state
kk_arguments_parse() {
    local -a a=("$@")
    local n=${#a[@]} i=0
    local -a actions=()
    local decrypt_seen=false
    local action_seen=""
    local f
    while ((i < n)); do
        f="${a[i]}"
        case "$f" in
            -c | --cat | -d | --decrypt | -e | --encrypt | -i | --info | --rm | --gc-assembly | --check | --selftest)
                if [[ -n "$action_seen" ]]; then
                    aborting "'$action_seen' cannot be combined with action flags: $f"
                fi
                actions+=("$f")
                if [[ "$f" == "-d" || "$f" == "--decrypt" ]]; then
                    decrypt_seen=true
                fi
                i=$((i + 1))
                ;;
            --dry-run)
                KK_DRY_RUN=true
                i=$((i + 1))
                ;;
            --force)
                KK_FORCE=true
                i=$((i + 1))
                ;;
            --json)
                KK_JSON_OUT=true
                i=$((i + 1))
                ;;
            --yes)
                KK_YES_MODE=true
                i=$((i + 1))
                ;;
            --help)
                usage
                exit 0
                ;;
            --checksum)
                kk_checksum_digest_calc
                exit 0
                ;;
            --checksum-update)
                kk_update_checksum_hash
                exit 0
                ;;
            --ppfile)
                if ((i >= n - 1)); then
                    aborting "--ppfile requires a file argument"
                fi
                KK_PPFILE="${a[i + 1]}"
                i=$((i + 2))
                ;;
            --version)
                printf 'kk %s\n' "$KK_VERSION"
                exit 0
                ;;
            --dir)
                printf '%s\n' "$KK_DIR_NAME"
                exit 0
                ;;
            --*) aborting "unknown flag: $f (see --help)" ;;
            *)
                # action keywords are matched here so KK_TARGET only ever
                # holds a path
                case "$f" in
                    ls | lock | search | unlock)
                        if ((${#actions[@]} > 0)); then
                            aborting "'$f' cannot be combined with action flags: ${actions[*]}"
                        fi
                        KK_ACTION="$f"
                        action_seen="$f"
                        ;;
                    *)
                        if [[ "$KK_ACTION" == "search" ]]; then
                            if [[ -z "$KK_SEARCH_PATTERN" ]]; then
                                KK_SEARCH_PATTERN="$f"
                            else
                                aborting "unexpected extra argument: $f"
                            fi
                        elif [[ -z "$KK_TARGET" ]]; then
                            KK_TARGET="$f"
                        elif [[ "$decrypt_seen" == true && -z "$KK_RESTORE_TARGET" ]]; then
                            KK_RESTORE_TARGET="$f"
                        else
                            aborting "unexpected extra argument: $f"
                        fi
                        ;;
                esac
                i=$((i + 1))
                ;;
        esac
    done

    case "$KK_ACTION" in
        ls) KK_ACTION="--ls" ;;
        lock) KK_ACTION="--lock-session" ;;
        search)
            if [[ -z "$KK_SEARCH_PATTERN" ]]; then
                aborting "'search' requires a pattern argument"
            fi
            KK_ACTION="--search"
            ;;
        unlock) KK_ACTION="--unlock-session" ;;
    esac
    if [[ -z "$KK_ACTION" ]]; then
        if ((${#actions[@]} > 1)); then
            aborting "conflicting action flags: ${actions[*]} - only one action per invocation"
        fi
        KK_ACTION="${actions[0]:-}"
    fi
}

# invoke an internal function without re-entering main
kk_call() { "$@"; } # allow the selftest subshell to call actions without re-entering main

# compute the script self-checksum digest after the marker line
kk_checksum_digest_calc() {
    local zero_path="${BASH_SOURCE[0]}"
    tail -n +"$(($(awk '/^# -----BEGIN CHECKSUM HASH-----$/ {print NR; exit}' "$zero_path") + 1))" "$zero_path" | openssl dgst -sha512 -r | cut -d' ' -f1
}

# create KK_DIR_NAME with the expected permissions
kk_dir_ensure() {
    mkdir -p -- "$KK_DIR_NAME"
    chmod "$KK_DIR_PERMISSIONS" -- "$KK_DIR_NAME"
}

# print warnings for invalid .kk files found in the active KK_DIR
kk_list_invalids() {
    local record path reason
    local -a invalids=()
    mapfile -t invalids < <(kk_print_invalids)
    for record in "${invalids[@]}"; do
        IFS=$'\t' read -r path reason <<< "$record"
        print_warning "ignoring invalid kk asset candidate in '$KK_DIR_NAME': $path ($reason)"
    done
}

# list invalid .kk files found in the active KK_DIR
kk_print_invalids() {
    local file hdr meta reason
    [[ -d "$KK_DIR_NAME" ]] || return 0
    shopt -s nullglob
    for file in "$KK_DIR_NAME"/*"$KK_FILENAME_EXT"; do
        [[ -e "$file" ]] || continue
        hdr=$(head -n 1 -- "$file" 2> /dev/null || true)
        if [[ -z "$hdr" ]]; then
            printf '%s\t%s\n' "$file" "header unreadable"
            continue
        fi
        meta=$(printf '%s' "$hdr" | base64 -d 2> /dev/null || true)
        if [[ -z "$meta" ]]; then
            printf '%s\t%s\n' "$file" "metadata decode failed"
            continue
        fi
        if [[ "$(asset_metadata_get "$meta" magic)" != "$KK_MAGIC" ]]; then
            printf '%s\t%s\n' "$file" "magic mismatch"
        fi
    done
    shopt -u nullglob
}

# list orphan pending asset files inside the active KK_DIR
kk_print_orphans() {
    local file run_id state
    [[ -d "$KK_DIR_NAME" ]] || return 0
    shopt -s nullglob
    for file in "$KK_DIR_NAME"/${KK_PENDING_PREFIX}*--*"$KK_FILENAME_EXT"; do
        [[ -e "$file" ]] || continue
        run_id=$(assembly_run_id "$file" || true)
        if [[ -z "$run_id" ]]; then
            print_warning "found unrecognized pending file in '$KK_DIR_NAME': $file"
            continue
        fi
        state=$(assembly_run_id_print_state "$run_id")
        if [[ "$state" == "orphan" ]]; then
            printf '%s\n' "$file"
        elif [[ "$state" == "unknown" ]]; then
            print_warning "found pending file with unreadable run id in '$KK_DIR_NAME': $file"
        fi
    done
    shopt -u nullglob
}

# rewrite the embedded script checksum hash
kk_update_checksum_hash() {
    local checksum_hash="$(kk_checksum_digest_calc)"
    local zero_path="${BASH_SOURCE[0]}"

    awk -i inplace -v new_hash="$checksum_hash" '
    /^readonly _KK_CHECKSUM_HASH=/ {
        sub(/".*"/, "\"" new_hash "\"");
    }
    { print }
    ' "$(realpath "$zero_path")"

    if [ $? -ne 0 ]; then
        aborting "failed to update checksum hash in $zero_path"
        exit 1
    fi

    if [[ "$(kk_checksum_digest_calc)" != "$checksum_hash" ]]; then
        aborting "failed to verify checksum hash update in $zero_path"
    fi

    print_info "updated checksum hash in $zero_path"
}

# run a round-trip self-test with wrong-passphrase and tamper checks
selftest() {
    print_info "selftest starting..."
    local tmp rc=0
    assembly_namespace_ensure
    tmp="$KK_DIR_STAGE/selftest"
    rm -rf -- "$tmp"
    mkdir -p -- "$tmp" || aborting "failed to create selftest workspace '$tmp'"
    (
        cd "$tmp" || exit 1
        printf 'knock knock\n' > selftest.txt
        cp selftest.txt selftest.orig
        m1=$(stat -c %Y selftest.txt)
        if ! (KK_PP="kk-selftest" kk_call asset_encrypt "selftest.txt"); then exit 1; fi
        rm -f selftest.txt || aborting "failed to remove selftest.txt"
        if ! (KK_PP="kk-selftest" kk_call asset_decrypt "selftest.txt"); then exit 1; fi
        cmp -s selftest.txt selftest.orig || exit 1
        if [[ "$(stat -c %Y selftest.txt)" != "$m1" ]]; then exit 1; fi
        if (KK_PP="wrong-passphrase" kk_call asset_decrypt "selftest.txt") 2> /dev/null; then exit 1; fi
        local e hlen
        e=$(ls -1 .kk/*.kk | head -n 1)
        hlen=$(head -n 1 "$e" | wc -c)
        printf 'X' | dd of="$e" bs=1 seek="$((hlen + 30))" conv=notrunc 2> /dev/null
        if (KK_PP="kk-selftest" kk_call asset_decrypt "selftest.txt") 2> /dev/null; then exit 1; fi
        print_info "selftest: round-trip OK, wrong-passphrase rejected, tamper rejected"
    ) || rc=$?

    rm -rf -- "$tmp" || aborting "failed to clean up selftest workspace '$tmp'"

    if ((rc != 0)); then
        aborting "selftest FAILED (exit $rc)"
    fi
    print_info "selftest PASSED"
}

# install cleanup-aware signal and exit handlers
signal_set_traps() {
    trap 'kk_status=$?; trap - EXIT; exit_cleanup "$kk_status"; exit "$kk_status"' EXIT
    trap 'KK_SIGNAL=HUP; exit 129' HUP
    trap 'KK_SIGNAL=INT; exit 130' INT
    trap 'KK_SIGNAL=QUIT; exit 131' QUIT
    trap 'KK_SIGNAL=TERM; exit 143' TERM
}

# print the command usage summary
usage() {
    cat << 'EOF'
kk - knock knock, who's there?

usage: kk <directory|file|socket> [flags]

actions:
  kk <path>             auto: encrypt if no .kk asset exists for this path, otherwise abort with a hint
  kk ls                 list assets; auto-unlocks when KK_PP, KK_PPFILE, or KK_SESSION is set
  kk search <pattern>   unlock the current KK_DIR once and search asset metadata by original path
  kk unlock             create a short-lived session cache for metadata discovery in the current KK_DIR
  kk lock               remove the current KK_SESSION cache and print shell cleanup

flags:
  -c | --cat            stream decrypted content to stdout (never touches disk)
  -d | --decrypt [path] restore the original from a .kk asset; add a path to restore elsewhere
  -e | --encrypt        encrypt and create a new .kk asset
  -i | --info           show full metadata for an asset

  --rm                  remove a .kk asset (numbered selection, never deletes silently)
  --check               compare stored hashes against the originals on disk

  --force               allow extra .kk assets on encrypt; on decrypt, auto-pick newest, skip overwrite prompts, and bypass restore safety validators
  --json                output json
  --ppfile <file>       read the passphrase from the first line of <file>
  --yes                 answer yes to all confirmations

  --dry-run             print what would happen; change nothing
  --help                show usage
  --checksum            print the script checksum
  --checksum-update     rewrite the embedded script checksum
  --gc-assembly         remove orphaned runtime directories, locks, and pending files
  --selftest            run an encrypt/decrypt round-trip self-test
  --version             show version number
  --dir                 show evaluated KK_DIR_NAME

socket mode: kk <host:port> - stubbed, wip
EOF
}

#
# main
#

# parse arguments, preflight state, and execute the selected action
main() {
    signal_set_traps
    kk_arguments_parse "$@"

    if [[ -n "$KK_TARGET" ]]; then
        KK_TARGET_RAW="$KK_TARGET"
        KK_TARGET=$(print_path "$KK_TARGET_RAW")
    fi

    if [[ -n "$KK_RESTORE_TARGET" ]]; then
        KK_RESTORE_TARGET=$(print_path "$KK_RESTORE_TARGET")
    fi

    readonly KK_TARGET KK_RESTORE_TARGET

    kk_action_set_default
    if $KK_DRY_RUN; then
        kk_action_dry_run "$KK_ACTION" "$KK_TARGET"
        exit 0
    fi
    kk_arguments_dispatch "$KK_ACTION" "$KK_TARGET"
}

main "$@"
