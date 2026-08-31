#!/usr/bin/env bash
#
# lazymap — a progressive nmap sweep that spends its time where hosts live.
#
# Throwing a full-port scan at a whole range up front is slow and mostly wasted:
# the vast majority of addresses are dark. lazymap works outside-in instead. It
# first flushes out the hosts that are likely alive (the edges of each /24, the
# ping responders), grabs quick top-port results from them, and only then pours
# the expensive full-range and version scans onto the hosts and ports that
# actually turned something up.
#
# TCP only — no UDP. SYN scan by default, so it wants root; pass -u for a
# rootless connect scan.
#
# The stages, in order:
#   0  build the target and exclude lists
#   1  ping-sweep the "probable" hosts, top-port scan the responders
#   2  top-port scan the probable hosts that ignored the ping
#   3  ping-sweep the rest of the range, top-port scan those responders
#   4  top-port scan whatever is still untouched
#   5  full port scan of every host found alive
#   6  version scan, on live hosts, of every port seen open so far
#   7  full port scan of the hosts nothing has touched yet
#   8  version scan of the ports stage 7 uncovered

set -uo pipefail

readonly PROG=lazymap

# Tunables (overridable via the options below).
TOP_PORTS=300
TIMING=4
MIN_RATE=
SCAN_TYPE=-sS
EXCLUDE=
OUTDIR=$(date +%Y%m%d_%H%M%S)

TARGETS=()
EXTRA_ARGS=()      # everything after `--`, passed straight to nmap
TIMING_ARGS=()     # -T / --min-rate, assembled once and reused
NMAP=(nmap)        # replaced from $NMAP_CMD, split so "sudo nmap" works


usage() {
    cat <<EOF
$PROG — progressive nmap sweep

Usage:
    $PROG [options] <target>... [-- <nmap args>...]

Targets are anything nmap understands (CIDRs, ranges, IPs, hostnames), the name
of a file to read them from, or '-' to read them from stdin.

Options:
    -o, --out <dir>         output directory (default: timestamped)
    -e, --exclude <spec>    hosts to skip, or a file listing them
    -t, --top-ports <n>     top TCP ports to hit in the fast passes (default: 300)
    -T, --timing <0-5>      nmap timing template (default: 4)
    -r, --min-rate <pps>    floor on nmap's packet rate
    -u, --unprivileged      connect scan (-sT) instead of SYN — no root needed
    -h, --help              show this and exit

Anything after '--' is handed to nmap verbatim. Set NMAP_CMD to choose the nmap
binary (e.g. NMAP_CMD='sudo nmap').
EOF
}


# --- small helpers -----------------------------------------------------------

log()  { printf '[%s] %s\n' "$(date '+%m-%d %H:%M')" "$*" | tee -a log.txt ; }
die()  { printf '%s: %s\n' "$PROG" "$*" >&2 ; exit 1 ; }

# Append a file (or stdin) into $1, keeping it sorted and free of duplicates.
merge() { cat "${2:-/dev/stdin}" >> "$1" ; sort -Vuo "$1" "$1" ; }

# Line count of a file or stdin.
count() { wc -l < "${1:-/dev/stdin}" ; }

# Hosts nmap marked "Up" in a .gnmap file.
up_hosts() { grep 'Status: Up' "$1" | cut -d' ' -f2 ; }

# Sorted, unique open TCP ports across one or more .gnmap files (missing ones
# are ignored). Call with at least one path so grep never blocks on stdin.
open_ports() { grep -ho '[0-9]*/open' "$@" 2>/dev/null | cut -d/ -f1 | sort -nu ; }

# True when $1 still lists a target that isn't removed by the exclude file $2.
# Lets a stage bow out cleanly rather than handing nmap an empty target set.
has_targets() {
    local list=$1 skip=${2:-}
    [[ -s $list ]] || return 1
    [[ -n $skip && -s $skip ]] || return 0
    comm -23 <(sort "$list") <(sort "$skip") | grep -q .
}

# nmap, with the shared timing/rate and pass-through args always appended.
scan() { "${NMAP[@]}" "$@" "${TIMING_ARGS[@]}" "${EXTRA_ARGS[@]}" ; }


# --- stages ------------------------------------------------------------------

stage0_targets() {
    log "Stage 0: building target list"

    local input=tmp/input.txt
    if [[ ${TARGETS[*]} == - ]]; then
        cat >> "$input"
    else
        local t
        for t in "${TARGETS[@]}"; do
            if [[ -f $t ]]; then cat "$t" >> "$input"; else echo "$t" >> "$input"; fi
        done
    fi

    local exclude=()
    if [[ -f $EXCLUDE ]]; then
        exclude=(--excludefile "$EXCLUDE")
    elif [[ -n $EXCLUDE ]]; then
        exclude=(--exclude "$EXCLUDE")
    fi

    "${NMAP[@]}" -n -sL "${exclude[@]}" -iL "$input" \
        | awk '/Nmap scan report/ {print $NF}' | merge scan_targets.txt

    # The first and last 16 addresses of each /24. Gateways, servers and other
    # infrastructure cluster at the low and high ends far more than the middle,
    # so these are the hosts worth looking at first.
    awk -F. '$NF <= 15 || $NF >= 240' scan_targets.txt | merge probable_hosts.txt

    log "Stage 0: $(count scan_targets.txt) hosts, $(count probable_hosts.txt) probable"
}

stage1_probable_ping() {
    log "Stage 1: probable hosts that answer pings"
    has_targets probable_hosts.txt || { log "Stage 1: nothing to sweep"; return; }

    scan -sn -n -iL probable_hosts.txt -oA tmp/stage1_ping
    up_hosts tmp/stage1_ping.gnmap | merge pingable_hosts.txt
    cp pingable_hosts.txt alive_hosts.txt

    if has_targets pingable_hosts.txt; then
        scan "$SCAN_TYPE" -n --open --top-ports "$TOP_PORTS" \
             -iL pingable_hosts.txt -oA tmp/stage1_ports
    fi

    log "Stage 1: $(count pingable_hosts.txt) pingable"
}

stage2_probable_dark() {
    log "Stage 2: probable hosts that ignored the ping"
    has_targets probable_hosts.txt pingable_hosts.txt \
        || { log "Stage 2: nothing left among the probable hosts"; return; }

    scan -Pn "$SCAN_TYPE" -n --open --top-ports "$TOP_PORTS" \
         -iL probable_hosts.txt --excludefile pingable_hosts.txt \
         -oA tmp/stage2_ports
    up_hosts tmp/stage2_ports.gnmap | merge alive_hosts.txt

    log "Stage 2: $(count alive_hosts.txt) alive so far"
}

stage3_rest_ping() {
    log "Stage 3: the rest of the range, hosts that answer pings"
    has_targets scan_targets.txt probable_hosts.txt \
        || { log "Stage 3: nothing left to sweep"; return; }

    scan -sn -n -iL scan_targets.txt --excludefile probable_hosts.txt \
         -oA tmp/stage3_ping
    up_hosts tmp/stage3_ping.gnmap | merge tmp/stage3_hosts.txt
    merge alive_hosts.txt    tmp/stage3_hosts.txt
    merge pingable_hosts.txt tmp/stage3_hosts.txt

    if has_targets tmp/stage3_hosts.txt; then
        scan "$SCAN_TYPE" -n --open --top-ports "$TOP_PORTS" \
             -iL tmp/stage3_hosts.txt -oA tmp/stage3_ports
    fi

    log "Stage 3: $(count tmp/stage3_hosts.txt) newly pingable"
}

stage4_rest_dark() {
    log "Stage 4: everything still untouched"
    sort -Vu probable_hosts.txt pingable_hosts.txt 2>/dev/null > tmp/stage4_seen.txt
    has_targets scan_targets.txt tmp/stage4_seen.txt \
        || { log "Stage 4: nothing left"; return; }

    scan "$SCAN_TYPE" -n --open --top-ports "$TOP_PORTS" \
         -iL scan_targets.txt --excludefile tmp/stage4_seen.txt \
         -oA tmp/stage4_ports
    up_hosts tmp/stage4_ports.gnmap | merge alive_hosts.txt

    log "Stage 4: $(count alive_hosts.txt) alive so far"
}

stage5_full() {
    log "Stage 5: full port scan of live hosts"
    has_targets alive_hosts.txt || { log "Stage 5: no live hosts"; return; }

    scan "$SCAN_TYPE" -n --open -p- -iL alive_hosts.txt -oA tmp/stage5_full

    log "Stage 5: $(open_ports tmp/stage5_full.gnmap | count) distinct ports open"
}

stage6_version() {
    log "Stage 6: version scan of live hosts"

    # Union of every open port we've seen on a live host — the quick top-port
    # passes as well as the full scan — so nothing found earlier is dropped, and
    # a full scan cut short still contributes whatever it managed to reach.
    local ports
    ports=$(open_ports tmp/stage1_ports.gnmap tmp/stage2_ports.gnmap \
                       tmp/stage3_ports.gnmap tmp/stage4_ports.gnmap \
                       tmp/stage5_full.gnmap)
    [[ -n $ports ]] && has_targets alive_hosts.txt \
        || { log "Stage 6: nothing to version-scan"; return; }

    scan "$SCAN_TYPE" -sV --version-intensity 9 --open \
         -p "$(paste -sd, <<<"$ports")" \
         -iL alive_hosts.txt -oA tmp/stage6_ver

    log "Stage 6: $(count <<<"$ports") ports scanned"
}

stage7_full_dark() {
    log "Stage 7: full port scan of the untouched hosts"
    has_targets scan_targets.txt alive_hosts.txt \
        || { log "Stage 7: no untouched hosts"; return; }

    scan "$SCAN_TYPE" -n --open -p- \
         -iL scan_targets.txt --excludefile alive_hosts.txt \
         -oA tmp/stage7_full

    log "Stage 7: $(open_ports tmp/stage7_full.gnmap | count) distinct ports open"
}

stage8_version_dark() {
    log "Stage 8: version scan of the untouched hosts"

    local ports
    ports=$(open_ports tmp/stage7_full.gnmap)
    [[ -n $ports ]] && has_targets scan_targets.txt alive_hosts.txt \
        || { log "Stage 8: nothing to version-scan"; return; }

    scan "$SCAN_TYPE" -sV --version-intensity 9 --open \
         -p "$(paste -sd, <<<"$ports")" \
         -iL scan_targets.txt --excludefile alive_hosts.txt \
         -oA tmp/stage8_ver

    log "Stage 8: $(count <<<"$ports") ports scanned"
}


# --- entry point -------------------------------------------------------------

main() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -o|--out)          OUTDIR=$2;         shift 2 ;;
            -e|--exclude)      EXCLUDE=$2;        shift 2 ;;
            -t|--top-ports)    TOP_PORTS=$2;      shift 2 ;;
            -T|--timing)       TIMING=$2;         shift 2 ;;
            -T[0-5])           TIMING=${1#-T};    shift   ;;  # nmap-style -T4
            -r|--min-rate)     MIN_RATE=$2;       shift 2 ;;
            -u|--unprivileged) SCAN_TYPE=-sT;     shift   ;;
            -h|--help)         usage; exit 0 ;;
            --)                shift; EXTRA_ARGS=("$@"); break ;;
            -)                 TARGETS+=("-");    shift   ;;  # read from stdin
            -*)                die "unknown option: $1 (try --help)" ;;
            *)                 TARGETS+=("$1");   shift   ;;
        esac
    done

    [[ ${#TARGETS[@]} -gt 0 ]] || { usage >&2; die "no targets given"; }

    IFS=' ' read -r -a NMAP <<<"${NMAP_CMD:-nmap}"

    # A SYN scan needs raw sockets. Say so plainly rather than let nmap fall
    # back to a connect scan (or bail) somewhere deep in the run.
    if [[ $SCAN_TYPE == -sS && $(id -u) -ne 0 && ${NMAP[0]} != sudo ]]; then
        die "SYN scan needs root — use sudo, set NMAP_CMD='sudo nmap', or pass -u"
    fi

    # Resolve file arguments while the paths still make sense; we cd shortly.
    local i
    for i in "${!TARGETS[@]}"; do
        [[ -f ${TARGETS[i]} ]] && TARGETS[i]=$(realpath "${TARGETS[i]}")
    done
    [[ -n $EXCLUDE && -f $EXCLUDE ]] && EXCLUDE=$(realpath "$EXCLUDE")

    TIMING_ARGS=("-T$TIMING")
    [[ -n $MIN_RATE ]] && TIMING_ARGS+=(--min-rate "$MIN_RATE")

    mkdir -p "$OUTDIR/tmp"
    cd "$OUTDIR" || die "cannot enter output directory: $OUTDIR"

    log "$PROG starting"
    log "  output:  $OUTDIR"
    log "  scan:    $SCAN_TYPE -T$TIMING${MIN_RATE:+ --min-rate $MIN_RATE}"
    log "  ports:   top $TOP_PORTS"
    [[ -n $EXCLUDE ]]              && log "  exclude: $EXCLUDE"
    [[ ${#EXTRA_ARGS[@]} -gt 0 ]] && log "  nmap:    ${EXTRA_ARGS[*]}"
    log "  targets: ${TARGETS[*]}"

    stage0_targets
    stage1_probable_ping
    stage2_probable_dark
    stage3_rest_ping
    stage4_rest_dark
    stage5_full
    stage6_version
    stage7_full_dark
    stage8_version_dark

    log "done — results under $OUTDIR/"
}

main "$@"
