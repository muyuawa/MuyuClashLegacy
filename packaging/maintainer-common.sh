#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
LC_ALL=C
export PATH LC_ALL
unset LAUNCHD_SOCKET LaunchKeepContext

label=com.muyu.clashlegacy.supervisor
job_plist=/Library/LaunchDaemons/$label.plist
launchctl=/bin/launchctl
[ -x "$launchctl" ] || launchctl=/sbin/launchctl
cli=/usr/libexec/muyuclash/muyu-cli
recover=/usr/libexec/muyuclash/muyu-network-recover
state_parent=/private/var/lib
state_dir=$state_parent/muyuclash
geo_parent=/private/var/db
geo_dir=$geo_parent/muyuclash-geodata
run_dir=/var/run/muyuclash
control_socket=$run_dir/control.sock

fail() {
    echo "MuyuClash Legacy: $*" >&2
    exit 1
}

safe_directory() {
    [ ! -L "$1" ] && [ -d "$1" ] && [ -O "$1" ]
}

owned_socket() {
    safe_directory "$run_dir" && [ ! -L "$control_socket" ] &&
        [ -S "$control_socket" ] && [ -O "$control_socket" ]
}

prepare_state() {
    safe_directory "$state_parent" || fail "Unsafe state parent $state_parent"
    if [ ! -e "$state_dir" ] && [ ! -L "$state_dir" ]; then
        mkdir -m 0700 "$state_dir"
    fi
    safe_directory "$state_dir" || fail "Unsafe state directory $state_dir"
    chmod 0700 "$state_dir"
}

read_job() {
    # A failed launchctl query is different from a successful empty listing.
    jobs=$("$launchctl" list) || fail "Could not query launchd"
    job_seen=no
    job_pid=
    {
        read -r pid status name
        [ "$pid $status $name" = 'PID Status Label' ] || fail "Unexpected launchd list format"
        while read -r pid status name; do
            [ "$name" = "$label" ] || continue
            job_seen=yes
            case "$pid" in
                -) ;;
                [1-9]*)
                    case "$pid" in *[!0-9]*) fail "Invalid launchd process ID" ;; esac
                    job_pid=$pid
                    ;;
                *) fail "Invalid launchd process ID" ;;
            esac
            break
        done
    } <<EOF
$jobs
EOF
}

start_job() {
    prepare_state
    read_job
    if [ "$job_seen" = no ]; then
        "$launchctl" load "$job_plist" || fail "Could not load the supervisor"
    fi
    remaining=15
    while [ "$remaining" -gt 0 ]; do
        read_job
        if [ -n "$job_pid" ] && owned_socket && "$cli" "$control_socket" service.status >/dev/null 2>&1; then
            return
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    fail "The supervisor did not become ready"
}

clean_runtime() {
    if [ -e "$run_dir" ] || [ -L "$run_dir" ]; then
        safe_directory "$run_dir" || fail "Unsafe runtime directory $run_dir"
        if [ -e "$control_socket" ] || [ -L "$control_socket" ]; then
            owned_socket || fail "Unsafe control socket $control_socket"
            rm -- "$control_socket"
        fi
        rmdir "$run_dir" || fail "Unexpected files in $run_dir"
    fi
}

stop_job() {
    read_job
    stopped_pid=$job_pid
    if [ "$job_seen" = yes ]; then
        if [ -n "$stopped_pid" ] && owned_socket; then
            "$cli" "$control_socket" network.restore >/dev/null || fail "App network recovery failed"
        fi
        "$launchctl" unload "$job_plist" || fail "Could not unload the supervisor"
    fi
    remaining=25
    while [ "$remaining" -gt 0 ]; do
        read_job
        if [ "$job_seen" = no ] && { [ -z "$stopped_pid" ] || ! kill -0 "$stopped_pid" 2>/dev/null; }; then
            [ -x "$recover" ] || fail "Missing emergency network recovery tool"
            "$recover" --emergency >/dev/null || fail "Owned network recovery remains incomplete"
            clean_runtime
            return
        fi
        sleep 1
        remaining=$((remaining - 1))
    done
    fail "The supervisor is still present after unloading"
}

refresh_icons() {
    if [ -x /usr/bin/uicache ]; then
        su -c /usr/bin/uicache mobile || echo "MuyuClash Legacy: could not refresh the icon cache" >&2
    fi
}
