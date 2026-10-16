#!/usr/bin/env bash
#
# lazymap — scans a range with nmap, likely-alive hosts first.
#
# A full-port scan of a whole range spends most of its time on dead addresses.
# lazymap works outside-in instead. It finds the hosts likely to be alive (the
# edges of each /24, the ones that answer pings), top-port scans them, and runs
# the slow full-port and version scans on them first. Addresses that never
# responded get their full scan last (stages 7–8), or not at all with -l.
#
# TCP only. SYN scan by default, so it needs root; -u switches to a connect
# scan. Everything is written to the output directory: the host lists, log.txt,
# per-stage nmap output under tmp/, and the merged lazymap.xml.
#
# Stages:
#   0  expand the targets, minus exclusions; pick out the probable hosts
#   1  ping-sweep the probable hosts; top-port scan the ones that answer
#   2  top-port scan (-Pn) the probable hosts that didn't answer
#   3  ping-sweep the rest of the range; top-port scan the ones that answer
#   4  top-port scan whatever is left (no -Pn: nmap pings them again first)
#   5  full port scan (-Pn) of every host found alive
#   6  version scan of every live host, on every port seen open so far
#   7  full port scan (-Pn) of every host not found alive    (skipped by -l)
#   8  version scan of stage 7's hosts, on the ports it found (skipped by -l)
#   9  merge every stage's XML into lazymap.xml (needs xmlstarlet)

set -uo pipefail

readonly PROG=lazymap

# Defaults, overridden by the options parsed in main().
TOP_PORTS=300
TIMING=4
MIN_RATE=
SCAN_TYPE=-sS
EXCLUDE=
OUTDIR=$(date +%Y%m%d_%H%M%S)
LIVE_ONLY=

TARGETS=()
EXTRA_ARGS=()      # everything after `--`; scan() appends it to every call
TIMING_ARGS=()     # -T and --min-rate; scan() appends it to every call
NMAP=(nmap)        # $NMAP_CMD split on spaces, so "sudo nmap" works
RDNS=()            # becomes (-n) if PTR lookups fail; used by stages 6 and 8
RDNS_CHECKED=      # set once check_rdns has run


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
    -T, --timing <0-5>      nmap timing template (default: 4; -T4 and -T 4 both work)
    -r, --min-rate <pps>    floor on nmap's packet rate
    -u, --unprivileged      connect scan (-sT) instead of SYN — no root needed
    -l, --live-only         skip stages 7-8, the full scan of every address that
                            never responded (the slow part on a sparse range)
    -h, --help              show this and exit

Anything after '--' is handed to nmap verbatim. Set NMAP_CMD to choose the nmap
binary (e.g. NMAP_CMD='sudo nmap').

Examples:
    # a /24, as root
    sudo $PROG 10.0.0.0/24

    # two ranges, no root, slower and quieter
    $PROG -u -T2 192.168.1.0/24 192.168.2.0/24

    # targets from a file, into a named directory, excluding a host
    sudo $PROG -o acme -e 10.0.0.1 targets.txt

    # from stdin, forcing a packet-rate floor and passing --reason to nmap
    subfinder -d example.com -silent | $PROG -u -r 1000 - -- --reason

Output (written to the output directory):
    scan_targets.txt    every host in scope
    probable_hosts.txt  the edge-of-subnet hosts scanned first
    pingable_hosts.txt  hosts that answered a ping
    alive_hosts.txt     everything found alive
    lazymap.xml         every stage merged into one nmap XML file
    log.txt             timestamped run log (also echoed to the terminal)
    tmp/                per-stage nmap output in all formats (.nmap, .gnmap, .xml)

The .gnmap files are grep-friendly. For an HTML report, run nmap's own stylesheet
over the merged XML:  xsltproc -o lazymap.html lazymap.xml
EOF
}


# --- small helpers -----------------------------------------------------------

# log writes to the terminal and log.txt; die writes to stderr and exits.
log()  { printf '[%s] %s\n' "$(date '+%m-%d %H:%M')" "$*" | tee -a log.txt ; }
die()  { printf '%s: %s\n' "$PROG" "$*" >&2 ; exit 1 ; }

# Add the lines of a file (or stdin) to $1, sorted and without duplicates.
merge() { cat "${2:-/dev/stdin}" >> "$1" ; sort -Vuo "$1" "$1" ; }

# Line count of a file or stdin.
count() { wc -l < "${1:-/dev/stdin}" ; }

# Hosts nmap marked "Up" in a .gnmap file.
up_hosts() { grep 'Status: Up' "$1" | cut -d' ' -f2 ; }

# Open TCP ports across the given .gnmap files, sorted and unique. Missing files
# are ignored. Always pass at least one path, or grep waits on stdin.
open_ports() { grep -ho '[0-9]*/open' "$@" 2>/dev/null | cut -d/ -f1 | sort -nu ; }

# True if list $1 has a host that the exclude file $2 doesn't remove. Stages
# 1–8 check this first and skip themselves rather than run nmap on nothing.
has_targets() {
    local list=$1 skip=${2:-}
    [[ -s $list ]] || return 1
    [[ -n $skip && -s $skip ]] || return 0
    comm -23 <(sort "$list") <(sort "$skip") | grep -q .
}

# Run nmap with the timing args and the `--` args appended. Used by stages 1–8.
scan() { "${NMAP[@]}" "$@" "${TIMING_ARGS[@]}" "${EXTRA_ARGS[@]}" ; }

# True if nmap's resolver gets through these targets within 30s. A list scan
# (-sL) only does lookups and sends nothing to the targets. The resolver aborts
# when no nameserver is reachable and hangs for good when one refuses queries,
# so it gets this trial run first. Runs in the foreground so a sudo in NMAP_CMD
# can still ask for a password.
dns_works() { timeout --foreground -k 5 30 "${NMAP[@]}" -sL "$@" >/dev/null 2>&1 ; }

# Before the first PTR lookups (stage 6, or 8 if 6 had nothing to scan), try
# the resolver on three hosts from list $1. If it fails, RDNS becomes (-n) and
# the rest of the run skips the lookups. Runs once.
check_rdns() {
    [[ -n $RDNS_CHECKED ]] && return
    RDNS_CHECKED=1
    local probe
    mapfile -t probe < <(head -n 3 "$1")
    dns_works "${probe[@]}" && return
    RDNS=(-n)
    log "  nmap's resolver crashed or hung on a PTR lookup; skipping them (-n)"
}


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

    # Hostname targets need the resolver. Try the first one and stop here if
    # it fails, rather than hang in the list scan below.
    local name
    name=$(tr -s '[:space:]' '\n' < "$input" | grep -m1 -E '^[^#:]*[A-Za-z][^:]*$')
    [[ -z $name ]] || dns_works -n "$name" \
        || die "nmap's resolver crashed or hung looking up '$name' (is DNS" \
               "reachable?); pass IP addresses instead"

    # A hostname target is reported as "name (ip)"; keep just the address.
    "${NMAP[@]}" -n -sL "${exclude[@]}" -iL "$input" \
        | awk '/Nmap scan report/ {gsub(/[()]/, "", $NF); print $NF}' \
        | merge scan_targets.txt

    # Probable hosts: the first and last 16 addresses of each /24 (.0–.15 and
    # .240–.255), where gateways, switches and servers usually sit.
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

    # No -Pn here: nmap pings these hosts again, and only the ones that answer
    # get a port scan. Stage 7 scans the rest with -Pn, unless -l skips it.
    scan "$SCAN_TYPE" -n --open --top-ports "$TOP_PORTS" \
         -iL scan_targets.txt --excludefile tmp/stage4_seen.txt \
         -oA tmp/stage4_ports
    up_hosts tmp/stage4_ports.gnmap | merge alive_hosts.txt

    log "Stage 4: $(count alive_hosts.txt) alive so far"
}

stage5_full() {
    log "Stage 5: full port scan of live hosts"
    has_targets alive_hosts.txt || { log "Stage 5: no live hosts"; return; }

    # -Pn from here on. These hosts are known to be alive, and host discovery
    # would drop the ones only stage 2's -Pn scan found.
    scan -Pn "$SCAN_TYPE" -n --open -p- -iL alive_hosts.txt -oA tmp/stage5_full

    log "Stage 5: $(open_ports tmp/stage5_full.gnmap | count) distinct ports open"
}

stage6_version() {
    log "Stage 6: version scan of live hosts"

    # Every port seen open in stages 1–5, on any live host, and every live host
    # is probed on all of them. Counting the top-port passes too means a full
    # scan cut short loses nothing they found.
    local ports
    ports=$(open_ports tmp/stage1_ports.gnmap tmp/stage2_ports.gnmap \
                       tmp/stage3_ports.gnmap tmp/stage4_ports.gnmap \
                       tmp/stage5_full.gnmap)
    [[ -n $ports ]] && has_targets alive_hosts.txt \
        || { log "Stage 6: nothing to version-scan"; return; }

    check_rdns alive_hosts.txt
    scan -Pn "$SCAN_TYPE" "${RDNS[@]}" -sV --version-intensity 9 --open \
         -p "$(paste -sd, <<<"$ports")" \
         -iL alive_hosts.txt -oA tmp/stage6_ver

    log "Stage 6: $(count <<<"$ports") ports scanned"
}

stage7_full_dark() {
    log "Stage 7: full port scan of the untouched hosts"
    has_targets scan_targets.txt alive_hosts.txt \
        || { log "Stage 7: no untouched hosts"; return; }

    # Everything not yet found alive. None of it answered a ping, so without
    # -Pn nmap would skip it again.
    scan -Pn "$SCAN_TYPE" -n --open -p- \
         -iL scan_targets.txt --excludefile alive_hosts.txt \
         -oA tmp/stage7_full
    up_hosts tmp/stage7_full.gnmap | merge tmp/stage7_hosts.txt
    merge alive_hosts.txt tmp/stage7_hosts.txt

    log "Stage 7: $(count tmp/stage7_hosts.txt) hosts with" \
        "$(open_ports tmp/stage7_full.gnmap | count) distinct ports open"
}

stage8_version_dark() {
    log "Stage 8: version scan of the untouched hosts"

    # Only the hosts stage 7 found open ports on, probed on every port it
    # found. Under -Pn, the whole dark set would mean re-probing every empty
    # address.
    local ports
    ports=$(open_ports tmp/stage7_full.gnmap)
    [[ -n $ports ]] && has_targets tmp/stage7_hosts.txt \
        || { log "Stage 8: nothing to version-scan"; return; }

    check_rdns tmp/stage7_hosts.txt
    scan -Pn "$SCAN_TYPE" "${RDNS[@]}" -sV --version-intensity 9 --open \
         -p "$(paste -sd, <<<"$ports")" \
         -iL tmp/stage7_hosts.txt -oA tmp/stage8_ver

    log "Stage 8: $(count <<<"$ports") ports scanned"
}

stage9_merge() {
    log "Stage 9: merging every stage into lazymap.xml"

    local xmls=(tmp/stage*.xml)    # glob order is stage order
    [[ -e ${xmls[0]} ]] || { log "Stage 9: no scan output to merge"; return; }
    command -v xmlstarlet >/dev/null \
        || { log "Stage 9: xmlstarlet not found, skipping the merge"; return; }

    # Every stage's <nmaprun>, in stage order. A file cut short (nmap killed
    # mid-run) is kept up to where it breaks off.
    local f broken=()
    for f in "${xmls[@]}"; do
        if xmlstarlet val -q -w "$f"; then
            xmlstarlet sel -t -c /nmaprun "$f"
        else
            broken+=("$f")
            xmlstarlet fo -R "$f" 2>/dev/null | xmlstarlet sel -t -c /nmaprun
        fi
    done > tmp/stage9_runs.xml

    # Then every up host's record again, sorted by address: IPv4 numerically,
    # IPv6 (no numeric key) first, by text. The sort is stable, so each
    # address's records end up side by side, in stage order. The merge then
    # only looks a few siblings ahead instead of searching the whole document.
    local addr='address[@addrtype != "mac"]/@addr'
    local ipnum="substring-before($addr, '.') * 16777216
               + substring-before(substring-after($addr, '.'), '.') * 65536
               + substring-before(substring-after(substring-after($addr, '.'), '.'), '.') * 256
               + substring-after(substring-after(substring-after($addr, '.'), '.'), '.')"
    {
        echo '<lazymap>'
        cat tmp/stage9_runs.xml
        { echo '<runs>'; cat tmp/stage9_runs.xml; echo '</runs>'; } \
            | xmlstarlet sel -t -e hosts \
                  -m "/runs/nmaprun/host[status/@state = 'up' and $addr]" \
                      -s A:N:- "$ipnum" -s A:T:- "$addr" -c . -b -b
        echo '</lazymap>'
    } > tmp/stage9_all.xml
    rm -f tmp/stage9_runs.xml

    local end timestr exit=(-a exit -o success -b)
    end=$(date +%s)
    timestr=$(date -d "@$end" '+%a %b %d %H:%M:%S %Y')
    (( ${#broken[@]} )) && exit=(-a exit -o error -b
                                 -a errormsg -o "truncated: ${broken[*]}" -b)

    # An address has at most one record per stage file, so they all sit within
    # that many siblings. Each sibling gets its own literal [k] step: libxml2
    # only stops walking an axis early when the last predicate is a literal
    # [n]. position() < n, or host[n][test], walks every sibling.
    local k sibs=.
    for ((k = 1; k < ${#xmls[@]}; k++)); do
        sibs+=" | (following-sibling::host[$k])[$addr = \$ip]"
    done

    # One <host> per address, built from all its records ($all):
    #   status     a real reply beats -Pn's assumed "user-set" up
    #   hostnames  all of them
    #   ports      all of them; if stages disagree on a port the later one
    #              wins, unless that would replace a -sV result with a bare one
    #   the rest   (os, hostscript, trace, times...) from the last stage with it
    # <extraports> is dropped: per-scan counts don't add up once merged.
    # Every pass scans a subset of the ports of the widest pass of its scan
    # type, so only that pass's <scaninfo> is kept.
    {
        echo '<?xml version="1.0" encoding="UTF-8"?>'
        echo '<!DOCTYPE nmaprun>'
        # nmap's stylesheet link, so a browser or xsltproc can render it
        xmlstarlet sel -t -c '/processing-instruction("xml-stylesheet")' -n \
            "${xmls[0]}" 2>/dev/null
        xmlstarlet sel -t \
            --var runs=/lazymap/nmaprun \
            --var first='$runs[not(@start > $runs/@start)][1]' \
            --var heads="/lazymap/hosts/host[not($addr = preceding-sibling::host[1]/$addr)]" \
            --var up='count($heads)' \
            --var total="$(count scan_targets.txt)" \
            --var elapsed="format-number($end - \$first/@start, '0.00')" \
            -e nmaprun \
                -a scanner -o nmap -b \
                -a args -m '$runs' -v @args -i 'position() != last()' -o ' ; ' -b -b -b \
                -a start -v '$first/@start' -b \
                -a startstr -v '$first/@startstr' -b \
                -a version -v '$runs[1]/@version' -b \
                -a xmloutputversion -v '$runs[1]/@xmloutputversion' -b \
                -m '$runs/scaninfo' \
                    --var same='$runs/scaninfo[@type = current()/@type
                                              and @protocol = current()/@protocol]' \
                    -i 'count(. | $same[not(@numservices < $same/@numservices)][1]) = 1' \
                        -c . -b \
                -b \
                -c '($runs/verbose)[1]' \
                -c '($runs/debugging)[1]' \
                -c '$runs/prescript' \
                -m '$heads' \
                    --var ip="string($addr)" \
                    --var all="$sibs" \
                    --var ok='$all/status' \
                    -e host \
                        -i '$all/@starttime' \
                            -a starttime -v '($all/@starttime)[not(. > $all/@starttime)][1]' -b \
                        -b \
                        -i '$all/@endtime' \
                            -a endtime -v '($all/@endtime)[not(. < $all/@endtime)][1]' -b \
                        -b \
                        -c '($ok[@reason != "user-set"] | $ok[last()])[1]' \
                        -c '$all[1]/address[@addrtype != "mac"]' \
                        -c '($all/address[@addrtype = "mac"])[1]' \
                        -e hostnames \
                            -m '$all/hostnames/hostname' \
                                --var same='$all/hostnames/hostname[@name = current()/@name
                                                                    and @type = current()/@type]' \
                                -i 'count(. | $same[1]) = 1' -c . -b \
                            -b \
                        -b \
                        -i '$all/ports/port' \
                            -e ports \
                                -m '$all/ports/port' -s A:T:- @protocol -s A:N:- @portid \
                                    --var same='$all/ports/port[@protocol = current()/@protocol
                                                                and @portid = current()/@portid]' \
                                    --var win='($same[service/@method = "probed"][last()]
                                                | $same[last()])[1]' \
                                    -i 'count(. | $win) = 1' -c . -b \
                                -b \
                            -b \
                        -b \
                        -m '$all/*[not(self::status or self::address or self::hostnames
                                       or self::ports or self::times)]' \
                            -i 'count(. | ($all/*[name() = name(current())])[last()]) = 1' \
                                -c . -b \
                        -b \
                        -c '($all/times)[last()]' \
                    -b \
                -b \
                -c '$runs/postscript' \
                -e runstats \
                    -e finished \
                        -a time -o "$end" -b \
                        -a timestr -o "$timestr" -b \
                        -a summary \
                            -o "Nmap done at $timestr; " -v '$total' -o ' IP addresses (' \
                            -v '$up' -o ' hosts up) scanned in ' -v '$elapsed' -o ' seconds' \
                        -b \
                        -a elapsed -v '$elapsed' -b \
                        "${exit[@]}" \
                    -b \
                    -e hosts \
                        -a up -v '$up' -b \
                        -a down -v '$total - $up' -b \
                        -a total -v '$total' -b \
                    -b \
                -b \
            -b \
            tmp/stage9_all.xml | xmlstarlet fo -o
    } > tmp/stage9_merged.xml && mv tmp/stage9_merged.xml lazymap.xml \
        || { log "Stage 9: merge failed"; return; }

    log "Stage 9: $(xmlstarlet sel -t -v 'count(/nmaprun/host)' -o ' hosts, ' \
                        -v 'count(/nmaprun/host/ports/port)' -o ' open ports' \
                        lazymap.xml)${broken[*]:+, recovered from truncated ${broken[*]}}"
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
            -l|--live-only)    LIVE_ONLY=1;       shift   ;;
            -h|--help)         usage; exit 0 ;;
            --)                shift; EXTRA_ARGS=("$@"); break ;;
            -)                 TARGETS+=("-");    shift   ;;  # read from stdin
            -*)                die "unknown option: $1 (try --help)" ;;
            *)                 TARGETS+=("$1");   shift   ;;
        esac
    done

    [[ ${#TARGETS[@]} -gt 0 ]] || { usage >&2; die "no targets given"; }

    IFS=' ' read -r -a NMAP <<<"${NMAP_CMD:-nmap}"

    # A SYN scan needs root. Fail now rather than have nmap fall back to a
    # connect scan, or bail, partway through the run.
    if [[ $SCAN_TYPE == -sS && $(id -u) -ne 0 && ${NMAP[0]} != sudo ]]; then
        die "SYN scan needs root — use sudo, set NMAP_CMD='sudo nmap', or pass -u"
    fi

    # Make file paths absolute before cd-ing into the output directory.
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
    if [[ -n $LIVE_ONLY ]]; then
        log "Stages 7-8: skipped (--live-only)"
    else
        stage7_full_dark
        stage8_version_dark
    fi
    stage9_merge

    log "done — results under $OUTDIR/"
}

main "$@"
